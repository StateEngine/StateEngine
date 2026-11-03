//! Public TCP MCP consumers of real protected decision data. Typed session
//! facts establish read authority; they do not claim a native provider launch.
#![cfg(any(target_os = "linux", windows))]
use se_host::*;
use se_store::*;
use serde_json::{Value, json};
use std::{io::Write, sync::Arc};
#[path = "../../se-host/tests/support/wave2_host_fixture.rs"]
mod support;
use support::session as capture;
use support::*;
#[path = "../../se-store/tests/support/wave2_continuity_fixture.rs"]
#[allow(
    dead_code,
    reason = "Shared store fixtures also serve metadata-only judges."
)]
mod governing;

fn fixture(damage: u8) -> Result<Fixture, Box<dyn std::error::Error>> {
    let (f, session) = governing::Governing::new()?.host_parts()?;
    let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
    let mut stage = files.create_staging(&f.options.state_directory)?;
    stage.file.write_all(&[23; 32])?;
    stage.file.sync_all()?;
    drop(stage.file);
    files.publish_no_replace(&stage.path, &f.options.state_directory.join("credential"))?;
    let (mut d, lease) = direct(&f)?;
    let now = now()?;
    let issued = credential(
        &session,
        "http",
        "decision-reader",
        now + 300_000_000,
        now + 60_000_000,
    )?;
    let EventBody::CredentialIssued { credential: id, .. } = &issued else {
        return Err("credential fixture".into());
    };
    let id = *id;
    d.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                EventBody::PrincipalRegistered {
                    principal: Actor::Human(f.owner.clone()),
                    kind: PrincipalKind::Human,
                    owner: f.owner.clone(),
                    created_by: None,
                    name: "Owner".into(),
                    role: "owner".into(),
                    expected: Expected::Absent,
                },
                issued,
                EventBody::CredentialActivated {
                    credential: id,
                    session,
                    expected: revision(1)?,
                    first_request: capture::record()?,
                },
            ],
        )?,
        &*lease,
    )?;
    let n = serial();
    let decision = se_types::DecisionId::from_parts(1_700_000_000_000 + n, [n as u8; 10])?;
    d.append(
        f.batch(
            f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.b.clone())),
            None,
            vec![EventBody::DecisionProposed {
                decision,
                key: "own.pending".into(),
                statement: InputText::Inline("💙".repeat(450)),
                rationale: None,
                prior: None,
                kind: DecisionKind::Decision,
            }],
        )?,
        &*lease,
    )?;
    d.close()?;
    drop(lease);
    if damage == 1 {
        // Deliberately damage one retained payload in this disposable store.
        // Every assertion below still traverses the production reader.
        let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
        db.execute_batch("DROP TRIGGER payloads_no_update")?;
        assert_eq!(db.execute("UPDATE payloads SET content=CAST('damaged' AS BLOB) WHERE field='statement' AND content=CAST('visible first' AS BLOB)", [])?, 1);
    }
    if damage == 2 {
        // Duplicate only a hidden superseded projection. Current law's one
        // predecessor is now ambiguous; the unaffected heads remain readable.
        let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
        assert_eq!(db.execute("INSERT INTO decisions(project_id,decision_id,proposed_seq,revision,last_seq,state) SELECT project_id,zeroblob(16),proposed_seq,revision,last_seq,state FROM decisions WHERE state='superseded'", [])?, 1);
    }
    Ok(f)
}

async fn list(port: u16, args: Value) -> Result<Value, Box<dyn std::error::Error>> {
    let response = rpc(
        port,
        "decision-reader",
        "tools/call",
        json!({"name":"stateengine_decision_list","arguments":args}),
    )
    .await?;
    require(
        response["result"]["isError"] == false,
        format!("positive session-bound decision.list refused: {response}"),
    )?;
    Ok(response["result"]["structuredContent"].clone())
}

fn run(damage: u8) -> Check {
    let initialized = initialize_host_process()?;
    let f = fixture(damage)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host = HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let port = host.http_port().ok_or("public HTTP port absent")?;
        let stop = host.local_stop();
        let client = async {
            let result: Check = async {
                let page = list(port, json!({"limit":100})).await?;
                require(page["schema"] == "se.decision-page/v1", format!("wrong page family: {page}"))?;
                require(page["items"].as_array().is_some_and(|items| items.len() == 4), format!("visible head membership changed: {page}"))?;
                require(!page.to_string().contains("SECRET"), "another agent's requests/history/mail/state leaked")?;
                require(page["window"]["omitted"]["count"] == if damage > 0 { 1 } else { 0 }
                    && (damage == 0 || page["window"]["omitted"]["reason"] == "unreadable"), format!("unreadable row not counted exactly once: {page}"))?;
                let items = page["items"].as_array().ok_or("items absent")?;
                let pending = items.iter().find(|item| item["key"] == "own.pending").ok_or("own pending request disappeared")?;
                require(pending["statement"]["text"].as_str().is_some_and(|text| text.chars().count() == 400)
                    && pending["statement"]["bytes"] == 1800 && pending["statement"]["complete"] == false
                    && pending["statement"]["command"].as_str().is_some_and(|text| text.starts_with("se decision show ")), "Unicode preview lost its exact bytes, boundary or full-read hint")?;
                if damage > 0 {
                    let broken: Vec<_> = items.iter().filter(|item| !item["unreadable"].is_null()).collect();
                    require(broken.len() == 1 && broken[0]["statement"].is_null(), "corrupt law was omitted or fabricated")?;
                    require(page["window"]["complete"] == false, "unreadable law became a complete page")?;
                } else {
                    let replacement = items.iter().find(|item| item["statement"]["text"] == "visible replacement").ok_or("governing replacement absent")?;
                    require(replacement["supersedes"].is_string(), "committed predecessor ID absent")?;
                    let first = list(port, json!({"limit":1})).await?;
                    require(first["window"]["omitted"]["count"] == 3, format!("remaining count wrong: {first}"))?;
                    let cursor = first["next"].as_str().ok_or("bounded page has no cursor")?;
                    let second = list(port, json!({"limit":1,"cursor":cursor})).await?;
                    require(second["items"][0]["id"] != first["items"][0]["id"], "cursor repeated the same decision")?;
                    let changed = rpc(port, "decision-reader", "tools/call", json!({"name":"stateengine_decision_list","arguments":{"limit":1,"cursor":cursor,"history":true}})).await?;
                    require(changed["result"]["isError"] == true, "decision cursor crossed changed history selector")?;
                }
                Ok(())
            }.await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        require(report.transport_closed && report.endpoint_retired, "native listener cleanup incomplete")?;
        result
    })
}

#[test]
fn active_session_mcp_lists_law_and_own_requests_with_exact_links_and_paging() -> Check {
    run(0)
}
#[test]
fn active_session_mcp_counts_a_damaged_law_row_without_fabricating_or_omitting_it() -> Check {
    run(1)
}

#[test]
fn active_session_mcp_keeps_paging_when_a_predecessor_projection_is_ambiguous() -> Check {
    run(2)
}
