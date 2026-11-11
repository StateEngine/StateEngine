//! A bound session's own stateengine_whoami returns only verified identity
//! facts: no credential material, no owner fallback, honest session source.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
use se_host::*;
use se_store::*;
use serde_json::json;
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn whoami_reports_the_admitted_principal_without_credentials() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let session = session::session()?;
    let issued = credential(
        &session,
        "http",
        "whoami-principal",
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
            Some(fixture::request("whoami-principal")?),
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
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?)
                .await?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let port = host.http_port().ok_or("HTTP port absent")?;
        let stop = host.local_stop();
        let consumer = async {
            let result: Check = async {
                // Discovery advertises an object input schema carrying the
                // optional caller assertions; a validating client can register it.
                let list = rpc(port, "whoami-principal", "tools/list", json!({})).await?;
                let tools = list["result"]["tools"]
                    .as_array()
                    .ok_or("tools/list returned no tools")?;
                let whoami_tool = tools
                    .iter()
                    .find(|tool| tool["name"] == "stateengine_whoami")
                    .ok_or("stateengine_whoami absent from tools/list")?;
                require(
                    whoami_tool["inputSchema"]["type"] == json!("object"),
                    format!("whoami input schema is not an object: {whoami_tool}"),
                )?;
                let properties = &whoami_tool["inputSchema"]["properties"];
                require(
                    properties.get("agent_id").is_some()
                        && properties.get("project_id").is_some(),
                    format!("whoami caller properties missing: {whoami_tool}"),
                )?;

                let plain = rpc(
                    port,
                    "whoami-principal",
                    "tools/call",
                    json!({"name":"stateengine_whoami","arguments":{}}),
                )
                .await?;
                require(
                    plain["result"]["isError"] == false,
                    format!("bound whoami refused: {plain}"),
                )?;
                let out = &plain["result"]["structuredContent"];
                require(out["schema"] == "se.principal/v1", format!("family drift: {plain}"))?;
                require(
                    out["project"]["id"] == json!(f.project.as_str())
                        && out["project"]["name"] == json!("Project"),
                    format!("project identity: {out}"),
                )?;
                require(
                    out["agent"]["id"] == json!(f.a.as_str()) && out["agent"]["name"] == json!("Sable"),
                    format!("agent identity: {out}"),
                )?;
                require(
                    out["session"]["id"] == json!(session.as_str())
                        && out["session"]["generation"] == json!(1),
                    format!("session identity: {out}"),
                )?;
                // The fixture preparation records no surface: honest absence.
                require(
                    out["session"]["source"]["state"] == "absent",
                    format!("session source: {out}"),
                )?;
                require(out["grants"] == json!([]), format!("grants: {out}"))?;
                require(
                    out["binding"]
                        == json!({"state":"activated","scope":"project","auth":"session"}),
                    format!("binding: {out}"),
                )?;
                require(
                    !plain.to_string().contains("whoami-principal"),
                    "credential material leaked into the result",
                )?;

                // Matching caller assertions agree with custody and are stripped.
                let asserted = rpc(
                    port,
                    "whoami-principal",
                    "tools/call",
                    json!({"name":"stateengine_whoami","arguments":{"agent_id":f.a,"project_id":f.project}}),
                )
                .await?;
                require(
                    asserted["result"]["isError"] == false
                        && asserted["result"]["structuredContent"]["agent"]["id"]
                            == json!(f.a.as_str()),
                    format!("matching assertion lost its principal: {asserted}"),
                )?;

                // A mismatching caller assertion is refused with both values.
                let mismatch = rpc(
                    port,
                    "whoami-principal",
                    "tools/call",
                    json!({"name":"stateengine_whoami","arguments":{"agent_id":"another-agent"}}),
                )
                .await?;
                require(
                    mismatch["result"]["isError"] == true,
                    format!("mismatch accepted: {mismatch}"),
                )?;
                let text = mismatch.to_string();
                require(
                    text.contains("another-agent") && text.contains(f.a.as_str()),
                    format!("mismatch omitted a value: {mismatch}"),
                )?;
                Ok(())
            }
            .await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), consumer).await;
        let closed = exit.finish(&bound()?).await;
        require(closed.transport_closed && closed.endpoint_retired, "host cleanup incomplete")?;
        result
    })
}
