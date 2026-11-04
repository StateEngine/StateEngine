//! Trusted native pins retain tool metadata through the real host writer/reader.
//! Typed session setup does not claim a provider launch or current-content authorship.
#![cfg(all(feature = "listener", target_os = "linux"))]
use se_core::ops::transcript::{
    Record,
    tool::{NativeIdentity, Outcome, Target},
};
use se_host::*;
use se_store::*;
use se_types::{NativePath, ProviderSessionId, Sha256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256 as Hasher};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

#[test]
fn trusted_tool_facts_survive_capture_readback_and_retry_for_both_providers() -> Check {
    for provider in [Provider::Claude, Provider::Codex] {
        capture_case(provider)?;
    }
    Ok(())
}
fn capture_case(provider: Provider) -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let session = session::session()?;
    let conversation = ProviderSessionId::new(format!("provider-{}", f.a.as_str()))?;
    let rows = match provider {
        Provider::Claude => vec![
            json!({"type":"assistant","uuid":"native-called","sessionId":conversation.as_str(),"cwd":"/native/work",
                "message":{"role":"assistant","content":[
                    {"type":"tool_use","id":"call-a","name":"Edit","input":{"file_path":"a.rs","new_string":"INTENDED_CONTENT"}},
                    {"type":"tool_use","id":"call-b","name":"Read","input":{"file_path":"b.rs"}}]}}),
            json!({"type":"user","uuid":"native-result-b","sessionId":conversation.as_str(),
                "message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-b","is_error":true,"content":"PRIVATE_OUTPUT"}]}}),
            json!({"type":"user","uuid":"native-result-a","sessionId":conversation.as_str(),
                "message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-a","is_error":false,"content":"PRIVATE_OUTPUT"}]}}),
        ],
        Provider::Codex => {
            let row = |item: Value| {
                json!({"type":"event_msg","payload":{"type":"item_completed",
                "thread_id":conversation.as_str(),"turn_id":"native-turn","item":item}})
            };
            vec![
                json!({"type":"session_meta","payload":{"id":conversation.as_str()}}),
                row(
                    json!({"type":"FileChange","id":"actual-file-item","status":"Completed",
                "changes":[{"path":"a.rs","diff":"INTENDED_CONTENT"}]}),
                ),
                row(
                    json!({"type":"McpToolCall","id":"actual-mcp-item","call_id":"actual-call",
                    "tool":"read","status":"Failed","arguments":{"path":"b.rs"},"error":{"message":"PRIVATE_OUTPUT"}}),
                ),
            ]
        }
        _ => return Err("unexpected provider".into()),
    };
    let mut bytes = Vec::new();
    for row in rows {
        bytes.extend(serde_json::to_vec(&row)?);
        bytes.push(b'\n');
    }
    let path = f.home.join("native-tools.jsonl");
    std::fs::write(&path, &bytes)?;
    let native_path = NativePath::from_local(path)?;
    let pin =
        se_proc::NativeSourcePin::open(&native_path.to_local()?)?.ok_or("native source absent")?;
    let source = session::record()?;
    let (mut direct, lease) = direct(&f)?;
    let mut prepared = session::prepared(&f, &session, &f.a);
    if let EventBody::SessionPrepared {
        provider: actual,
        native_ref,
        ..
    } = &mut prepared
    {
        *actual = provider;
        *native_ref = conversation.as_str().into();
    }
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("native-tools-setup")?),
            vec![
                prepared,
                session::activated(&session)?,
                session::source(source, &session, &pin.identity(), Expected::Absent),
            ],
        )?,
        &*lease,
    )?;
    direct.close()?;
    drop(lease);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host = HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        configure_private_listener(&mut host)?;
        let capture = host.capture_handle();
        capture.bind(TranscriptPin {
            identity: SessionIdentity { project:f.project.clone(),agent:f.a.clone(),session:session.clone() },
            conversation:conversation.clone(),path:native_path.clone(),file_identity:Sha256::from_bytes(pin.identity())
        }, source, pin, &bound()?).await?;
        let execution = host.execution_context();
        let mut admitted = f.self_scope(&f.a).admission; admitted.session = Some(session.clone());
        let stop = host.local_stop();
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let consumer = async {
            let result: Check = async {
                let first = capture.catch_up(admitted.clone(), conversation.clone(), native_path.clone(), &bound()?).await?;
                require(first.capture_commits.len() == if provider == Provider::Claude {3} else {2}, "tool-only source was not fully committed")?;
                let retry = capture.catch_up(admitted, conversation, native_path, &bound()?).await?;
                require(retry.capture_commits.len()==1 && first.capture_commits.iter().any(|old|
                    old.event_id==retry.capture_commits[0].event_id), "tool retry did not reuse the retained event")?;
                let mut snapshot = execution.reader.snapshot(f.self_scope(&f.a))?;
                let page = snapshot.turns(f.a.clone(), budget(10,100_000,None)?)?;
                require(page.items().len() == if provider == Provider::Claude {4} else {2}, "native facts lost or duplicated")?;
                let mut completed = 0;
                for event in page.items() {
                    let EventBody::SessionTurn {session:actual_session, agent, provider:actual_provider, role:Role::System,
                        text:StoredText::Present(text), evidence,..} = &event.body else { return Err("tool fact fabricated chat".into()); };
                    require(!text.contains("PRIVATE_OUTPUT") && !text.contains("INTENDED_CONTENT"), "tool payload leaked into metadata")?;
                    let tool = Record::decode(text)?.captured_tool.ok_or("tool missing on public readback")?;
                    tool.validate_binding(actual_session,agent,*actual_provider,source,evidence)?;
                    require(tool.session == session && tool.agent == f.a && tool.source == source, "native source binding differs")?;
                    let from = evidence.offset as usize; let to = from + evidence.length as usize;
                    require(evidence.sha256 == Some(Hasher::digest(&bytes[from..to]).into()), "tool evidence differs from native bytes")?;
                    require(matches!(tool.target, Target::Paths(ref paths) if paths.len()==1 && paths[0].content_revision.is_none()), "native target was inferred or given intended content as revision")?;
                    match tool.outcome {
                        Outcome::Succeeded | Outcome::Failed => completed += 1,
                        Outcome::Unknown(_) => {},
                        Outcome::Cancelled => return Err("fabricated cancellation".into()),
                    }
                    require(match tool.native {
                        NativeIdentity::ClaudeCall {ref tool_use_id} => provider==Provider::Claude && ["call-a","call-b"].contains(&tool_use_id.as_str()),
                        NativeIdentity::CodexItem {ref item_id,ref call_id,..} => provider==Provider::Codex &&
                            (item_id.as_deref()==Some("actual-file-item") && call_id.is_none() ||
                             item_id.as_deref()==Some("actual-mcp-item") && call_id.as_deref()==Some("actual-call")),
                        NativeIdentity::Unknown(_) => false,
                    }, "actual native identities were relabeled")?;
                }
                require(completed == 2, "actual outcomes missing")?;
                let progress = present(snapshot.capture_source(source)?)?;
                require(matches!(progress.current.body, EventBody::CaptureProgress {new_offset,..} if new_offset==bytes.len() as u64), "source cursor stopped before retained facts")?;
                snapshot.close()?; Ok(())
            }.await;
            stop.request(); result
        };
        let (exit,result) = join(host.serve(listener),consumer).await;
        drop(capture); drop(execution);
        let report = exit.finish(&bound()?).await;
        require(report.transport_closed && report.endpoint_retired,"tool capture host did not close")?;
        result
    })
}
