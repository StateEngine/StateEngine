//! Real HTTP MCP: redundant caller assertions agree with capability custody.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
use se_host::*;
use se_store::*;
use serde_json::json;
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

#[test]
fn all_tools_check_each_identity_alias_against_the_authenticated_principal() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let session = session::session()?;
    let issued = credential(
        &session,
        "http",
        "bound-principal",
        now()? + 300_000_000,
        now()? + 60_000_000,
    )?;
    let EventBody::CredentialIssued { credential: id, .. } = &issued else {
        return Err("credential setup".into());
    };
    let id = *id;
    let (mut writer, lease) = direct(&f)?;
    writer.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("matching-principal")?),
            vec![
                session::prepared(&f, &session, &f.a),
                issued,
                session::activated(&session)?,
                EventBody::CredentialActivated {
                    credential: id,
                    session: session.clone(),
                    expected: revision(1)?,
                    first_request: session::record()?,
                },
                EventBody::WorkingStateSet {
                    agent: f.a.clone(),
                    text: InputText::Inline("own-private-state".into()),
                    expected: Expected::Absent,
                },
            ],
        )?,
        &*lease,
    )?;
    writer.close()?;
    drop(lease);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host = HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let port = host.http_port().ok_or("HTTP port absent")?;
        let stop = host.local_stop();
        let consumer = async {
            let result: Check = async {
                let listed = rpc(port, "bound-principal", "tools/list", json!({})).await?;
                for tool in listed["result"]["tools"].as_array().ok_or("tool list absent")? {
                    for field in ["agent_id", "agentId", "project_id", "projectId", "project"] {
                        require(tool["inputSchema"]["properties"][field] == json!({
                            "type": "string", "description": "Caller assertion; optional; must match the bound identity"
                        }), format!("missing caller metadata {} {field}: {tool}", tool["name"]))?;
                        require(!tool["inputSchema"]["required"].as_array().is_some_and(|fields| fields.contains(&json!(field))), "caller assertion became required")?;
                    }
                    let description = match tool["name"].as_str() {
                        Some("stateengine_agent_launch") => Some("The seat to launch."),
                        Some("stateengine_agent_stop") => Some("The seat to stop."),
                        _ => None,
                    };
                    if let Some(description) = description {
                        require(tool["inputSchema"]["properties"]["target_agent_id"]["description"] == description, "target selection is not described")?;
                    }
                }
                let assertions = json!({"agent_id":f.a,"agentId":f.a,"project_id":f.project,"projectId":f.project,"project":f.project});
                for name in ["stateengine_working_state_get", "stateengine_resume"] {
                    let mut args = assertions.clone();
                    if name == "stateengine_resume" { args["byte_budget"] = json!(16384); }
                    let result = rpc(port, "bound-principal", "tools/call", json!({"name":name,"arguments":args})).await?;
                    require(result["result"]["isError"] == false, format!("matching {name}: {result}"))?;
                    if name == "stateengine_working_state_get" { require(result.to_string().contains("own-private-state"), "matching call lost its own principal")?; }
                }
                for tool in se_core::ops::mcp_tools()? {
                    for field in ["agent_id", "agentId", "project_id", "projectId", "project"] {
                        let mut args = assertions.clone(); args[field] = json!("another-principal");
                        let refused = rpc(port, "bound-principal", "tools/call", json!({"name":tool.name,"arguments":args})).await?;
                        require(refused["result"]["isError"] == true, format!("mismatch accepted {} {field}: {refused}", tool.name))?;
                        let text = refused.to_string();
                        require(text.contains("another-principal") && text.contains(if field.starts_with("agent") { f.a.as_str() } else { f.project.as_str() }), format!("mismatch omitted both values: {refused}"))?;
                        require(!text.contains("own-private-state"), "mismatching call read private state")?;
                    }
                }
                Ok(())
            }.await;
            stop.request(); result
        };
        let (exit, result) = join(host.serve(listener), consumer).await;
        let closed = exit.finish(&bound()?).await;
        require(closed.transport_closed && closed.endpoint_retired, "host cleanup incomplete")?;
        result
    })
}
