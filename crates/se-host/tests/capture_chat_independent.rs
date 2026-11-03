//! Production capture through a retained native file and the public coordinator handle.
//! Session facts are typed setup; this does not claim a real provider launch.
#![cfg(all(feature = "listener", target_os = "linux"))]
use se_host::*;
use se_store::*;
use se_types::{NativePath, ProviderSessionId, Sha256};
use serde_json::json;
use sha2::{Digest, Sha256 as Hasher};
use std::{fs::OpenOptions, io::Write};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

#[test]
fn pinned_capture_keeps_real_chat_and_refuses_schema_drift_without_advancing() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let s = session::session()?;
    let conversation = ProviderSessionId::new(format!("provider-{}", f.a.as_str()))?;
    let path = f.home.join("transcript.jsonl");
    let native_path = NativePath::from_local(path.clone())?;
    let records = [
        json!({"type":"session-owner","sessionId":conversation.as_str()}),
        json!({"type":"tools-used","sessionId":conversation.as_str()}),
        json!({"type":"api-request-shape","sessionId":conversation.as_str()}),
        json!({"type":"api-request","sessionId":conversation.as_str()}),
        json!({"type":"api-request-blob","hash":"ab".repeat(32),"message":{"role":"system","content":"CACHE_SECRET"}}),
        json!({"type":"user","sessionId":conversation.as_str(),"uuid":"user-real","message":{"role":"user","content":"real user λ"}}),
        json!({"type":"user","sessionId":conversation.as_str(),"uuid":"tool-only","message":{"role":"user","content":[{"type":"tool_result","content":"TOOL_SECRET"}]}}),
        json!({"type":"user","sessionId":conversation.as_str(),"uuid":"user-mixed","message":{"role":"user","content":[{"type":"tool_result","content":[{"type":"text","text":"TOOL_SECRET"}]},{"type":"text","text":"second real user"}]}}),
        json!({"type":"assistant","sessionId":conversation.as_str(),"uuid":"assistant-real","message":{"role":"assistant","content":[{"type":"text","text":"real assistant"}]}}),
    ];
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend(serde_json::to_vec(&record)?);
        bytes.push(b'\n');
    }
    std::fs::write(&path, &bytes)?;
    let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("native source absent")?;
    let source = session::record()?;
    let (mut direct, lease) = direct(&f)?;
    direct.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                session::prepared(&f, &s, &f.a),
                session::activated(&s)?,
                session::source(source, &s, &pin.identity(), Expected::Absent),
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
        let capture = host.capture_handle();
        capture.bind(TranscriptPin { identity: SessionIdentity {project:f.project.clone(),agent:f.a.clone(),session:s.clone()}, conversation:conversation.clone(), path:native_path.clone(),file_identity:Sha256::from_bytes(pin.identity()) }, source, pin, &bound()?).await?;
        let execution = host.execution_context();
        let mut admitted = f.self_scope(&f.a).admission;
        admitted.session = Some(s.clone());
        let stop = host.local_stop();
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let consumer = async {
            let result: Check = async {
                let result = capture.catch_up(admitted.clone(), conversation.clone(), native_path.clone(), &bound()?).await?;
                require(result.capture_commits.len() == 3, "metadata or tool results became chat; real chat missing")?;
                let mut snapshot = execution.reader.snapshot(f.self_scope(&f.a))?;
                let page = snapshot.turns(f.a.clone(), budget(10, 100_000, None)?)?;
                let mut texts = Vec::new();
                for event in page.items() {
                    let EventBody::SessionTurn { role, text:StoredText::Present(text), evidence, .. } = &event.body else { return Err("unexpected captured event".into()); };
                    require(matches!(role, Role::User | Role::Assistant), "non-chat role was published")?;
                    texts.push(text.clone());
                    let start = usize::try_from(evidence.offset)?;
                    let end = start + usize::try_from(evidence.length)?;
                    let hash: [u8;32] = Hasher::digest(&bytes[start..end]).into();
                    require(evidence.sha256 == Some(hash), "raw native evidence digest differs")?;
                }
                texts.sort();
                require(texts == vec!["real assistant", "real user λ", "second real user"], format!("wrong public chat: {texts:?}"))?;
                let before = present(snapshot.capture_source(source)?)?;
                snapshot.close()?;
                let mut file = OpenOptions::new().append(true).open(&path)?;
                writeln!(file, "{}", json!({"type":"api-request","sessionId":conversation.as_str(),"message":{"role":"user","content":"MUST_NOT_DISAPPEAR"}}))?;
                file.sync_all()?;
                require(capture.catch_up(admitted, conversation, native_path, &bound()?).await.is_err(), "message-bearing metadata silently discarded")?;
                let mut after = execution.reader.snapshot(f.self_scope(&f.a))?;
                let current = present(after.capture_source(source)?)?;
                require(current.revision == before.revision && current.current.header.event == before.current.header.event, "schema drift advanced the durable cursor")?;
                require(after.turns(f.a.clone(), budget(10,100_000,None)?)?.items().len() == 3, "schema drift fabricated a chat turn")?;
                after.close()?;
                Ok(())
            }.await;
            stop.request(); result
        };
        let (exit, result) = join(host.serve(listener), consumer).await;
        drop(capture); drop(execution);
        let report = exit.finish(&bound()?).await;
        require(report.transport_closed && report.endpoint_retired, "capture host transport cleanup incomplete")?;
        result
    })
}
