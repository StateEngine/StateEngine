//! Authenticated public MCP must not acquire the owner's destructive Remove API.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
use se_host::*;
use se_store::*;
use serde_json::json;
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

/// Protects: actual HTTP tool discovery/calls refuse Remove, with project state retained.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn authenticated_mcp_cannot_remove_a_project() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let session = session::session()?;
    let issued = credential(
        &session,
        "http",
        "synthetic-marker-remove-capability",
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
            Some(fixture::request("marker-remove-mcp-session")?),
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
                    text: InputText::Inline("retained-marker-remove-note".into()),
                    expected: Expected::Absent,
                },
            ],
        )?,
        &*lease,
    )?;
    let mut snapshot = writer.snapshot(f.scoped(Visibility::Owner))?;
    let original = present(snapshot.project(f.project.clone())?)?;
    snapshot.close()?;
    writer.close()?;
    drop(lease);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let port = host.http_port().ok_or("HTTP port absent")?;
        let stop = host.local_stop();
        let consumer = async {
            let result: Check = async {
                let bearer = "synthetic-marker-remove-capability";
                let listed = rpc(port, bearer, "tools/list", json!({})).await?;
                let tools = listed["result"]["tools"]
                    .as_array()
                    .ok_or("tool list absent")?;
                require(
                    !tools
                        .iter()
                        .any(|tool| tool["name"] == "stateengine_remove"),
                    "MCP advertised owner-only Remove",
                )?;
                // WorkingStateGet has an empty DTO: its agent is selected by
                // the authenticated session, not invented read arguments.
                let before = rpc(
                    port,
                    bearer,
                    "tools/call",
                    json!({"name":"stateengine_working_state_get", "arguments":{}}),
                )
                .await?;
                require(
                    before["result"]["isError"] == false,
                    format!("initial public working-state read failed: {before}"),
                )?;
                let note = &before["result"]["structuredContent"];
                require(
                    note["agent"]["id"] == json!(f.a)
                        && note["value"]["state"] == "present"
                        && note["value"]["value"]["text"] == "retained-marker-remove-note"
                        && note["value"]["value"]["revision"] == 1,
                    format!("initial public read did not return the exact saved note: {before}"),
                )?;
                // Actual ProjectRemove input shape, not a fabricated keep-data flag.
                for all in [false, true] {
                    let refused = rpc(
                        port,
                        bearer,
                        "tools/call",
                        json!({
                            "name":"stateengine_remove",
                            "arguments":{
                                "all":all,
                                "keep_integrations":false,
                                "idempotency_key":format!("mcp-remove-{all}")
                            }
                        }),
                    )
                    .await?;
                    require(
                        refused["result"]["isError"] == true,
                        format!("MCP Remove succeeded: {refused}"),
                    )?;
                }
                // Status needs native process custody absent from this fixture.
                // Instead prove the original saved note remains publicly readable.
                let after = rpc(
                    port,
                    bearer,
                    "tools/call",
                    json!({"name":"stateengine_working_state_get", "arguments":{}}),
                )
                .await?;
                require(
                    after["result"]["isError"] == false
                        && after["result"]["structuredContent"] == *note,
                    format!(
                        "saved note changed or became unreadable after refused Remove: {after}"
                    ),
                )?;
                Ok(())
            }
            .await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), consumer).await;
        let closed = exit.finish(&bound()?).await;
        require(
            closed.transport_closed && closed.endpoint_retired,
            "host cleanup incomplete",
        )?;
        result
    })?;
    // Retained notes alone do not prove a project was not tombstoned: removal
    // deliberately preserves history. Read the durable registration separately.
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
    let retained = present(snapshot.project(f.project.clone())?)?;
    snapshot.close()?;
    require(
        matches!(&retained.current.body, EventBody::ProjectRegistered { project, .. } if project == &f.project),
        "refused MCP Remove tombstoned or replaced the project registration",
    )?;
    require(
        retained.revision == original.revision
            && retained.current.header.event == original.current.header.event,
        "refused MCP Remove advanced the persisted project projection",
    )
}
