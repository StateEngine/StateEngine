//! Protects: capture separates metadata from chat and refuses malformed known chat atomically.
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
fn pinned_capture_keeps_chat_separate_and_refuses_broken_known_records() -> Check {
    for bad_bookkeeping in [false, true] {
        capture_case(bad_bookkeeping)?;
    }
    Ok(())
}

fn capture_case(bad_bookkeeping: bool) -> Check {
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
            Some(fixture::request(&format!(
                "fixture-capture_chat_independent-44-{}",
                serial()
            ))?),
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
        let mut configuration = se_core::config_policy::ConfigFile::default();
        configuration.runtime.listen_port = Some(private_port()?);
        host.configure(configuration)?;
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
                require(result.capture_commits.len() == 4, "metadata, tool facts or real chat missing")?;
                let mut snapshot = execution.reader.snapshot(f.self_scope(&f.a))?;
                let page = snapshot.turns(f.a.clone(), budget(20, 100_000, None)?)?;
                let mut texts = Vec::new();
                let mut metadata = 0;
                let mut tools = 0;
                for event in page.items() {
                    let EventBody::SessionTurn { role, text:StoredText::Present(text), evidence, .. } = &event.body else { return Err("unexpected captured event".into()); };
                    match role {
                        Role::User | Role::Assistant => texts.push(text.clone()),
                        Role::System => {
                            let body: serde_json::Value = serde_json::from_str(text)?;
                            require(body["schema"] == "se.transcript-event/v1", "metadata schema missing")?;
                            require(!text.contains("CACHE_SECRET") && !text.contains("TOOL_SECRET"), "provider payload leaked into metadata")?;
                            if body["kind"] == "captured-tool" {
                                let record = se_core::ops::transcript::Record::decode(text)?;
                                let tool = record.captured_tool.ok_or("native tool fact missing")?;
                                require(matches!(tool.native, se_core::ops::transcript::tool::NativeIdentity::Unknown(_)), "missing native identity was fabricated")?;
                                tools += 1;
                            }
                            metadata += 1;
                        }
                        Role::Tool => return Err("tool role was published".into()),
                    }
                    let start = usize::try_from(evidence.offset)?;
                    let end = start + usize::try_from(evidence.length)?;
                    let hash: [u8;32] = Hasher::digest(&bytes[start..end]).into();
                    require(evidence.sha256 == Some(hash), "raw native evidence digest differs")?;
                }
                require(metadata == 7 && tools == 2, "metadata lost its durable representation")?;
                texts.sort();
                require(texts == vec!["real assistant", "real user λ", "second real user"], format!("wrong public chat: {texts:?}"))?;

                snapshot.close()?;
                let mut file = OpenOptions::new().append(true).open(&path)?;
                // The allow-list admits payloads only for api-request-blob and
                // queue-operation; api-request with payload must refuse below.
                writeln!(file, "{}", json!({"type":"api-request-blob","message":{"role":"user","content":"REQUEST_CACHE_SECRET"}}))?;
                file.sync_all()?;
                writeln!(file, "{}", json!({"type":"assistant","sessionId":conversation.as_str(),"uuid":"after-metadata","message":{"role":"assistant","content":"after metadata"}}))?;
                file.sync_all()?;
                let added = capture.catch_up(admitted.clone(), conversation.clone(), native_path.clone(), &bound()?).await?;
                require(added.capture_commits.len() == 1, "permitted cache metadata blocked the real assistant")?;
                let mut stable = execution.reader.snapshot(f.self_scope(&f.a))?;
                let before = present(stable.capture_source(source)?)?;
                let retained = stable.turns(f.a.clone(), budget(20,100_000,None)?)?;
                require(retained.items().len() == 12, "permitted cache and real assistant were not retained exactly")?;
                let mut found_assistant = false;
                for event in retained.items() {
                    let EventBody::SessionTurn { role, text:StoredText::Present(text), .. } = &event.body
                        else { return Err("unreadable captured tail".into()); };
                    require(!text.contains("REQUEST_CACHE_SECRET") && !text.contains("MUST_NOT_DISAPPEAR"),
                        "refused or allowed cache payload leaked into captured text")?;
                    found_assistant |= *role == Role::Assistant && text == "after metadata";
                }
                require(found_assistant, "assistant after permitted bookkeeping was lost")?;
                stable.close()?;
                let invalid = if bad_bookkeeping {
                    json!({"type":"api-request","sessionId":conversation.as_str(),"message":{"role":"user","content":"MUST_NOT_DISAPPEAR"}})
                } else {
                    json!({"type":"user","sessionId":conversation.as_str(),"uuid":"broken-known","message":{"role":"user"}})
                };
                writeln!(file, "{}", invalid)?;
                file.sync_all()?;
                let error = capture.catch_up(admitted, conversation, native_path, &bound()?).await
                    .err().ok_or("invalid known record was silently discarded")?;
                if bad_bookkeeping {
                    require(matches!(error.body.detail(), se_types::Detail::UsageInvalidValue(detail)
                        if detail.expected == "bookkeeping without message or content fields"), "wrong refusal for message-bearing bookkeeping")?;
                }
                let mut after = execution.reader.snapshot(f.self_scope(&f.a))?;
                let current = present(after.capture_source(source)?)?;
                require(current.revision == before.revision && current.current.header.event == before.current.header.event, "invalid known record advanced the durable cursor")?;
                require(after.turns(f.a.clone(), budget(20,100_000,None)?)?.items().len() == 12, "invalid known record fabricated a turn")?;
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
fn private_port() -> std::result::Result<u16, Box<dyn std::error::Error>> {
    for port in 20000..=29999 {
        if port != 20800
            && let Ok(probe) = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        {
            return Ok(probe.local_addr()?.port());
        }
    }
    Err("no available explicit test listener port".into())
}
