//! Metadata-only native queue bookkeeping must not block later chat capture.
#![cfg(all(feature = "listener", target_os = "linux"))]
use se_host::*;
use se_store::*;
use se_types::{NativePath, ProviderSessionId, Sha256};
use serde_json::{Value, json};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

fn transcript() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(path) = std::env::var_os("SE_CLAUDE_METADATA_CORPUS") {
        return Ok(std::fs::read(path)?);
    }
    let mut bytes = Vec::new();
    for value in [
        json!({"type":"queue-operation","operation":"enqueue","timestamp":"2026-11-04T18:03:00.682Z"}),
        json!({"type":"queue-operation","operation":"dequeue","timestamp":"2026-11-04T18:03:00.684Z"}),
        json!({"type":"user","sessionId":"metadata-queue-session","uuid":"user","message":{"role":"user","content":"a real task"}}),
        json!({"type":"assistant","sessionId":"metadata-queue-session","uuid":"assistant-1","message":{"role":"assistant","content":"working"}}),
        json!({"type":"assistant","sessionId":"metadata-queue-session","uuid":"assistant-2","message":{"role":"assistant","content":"done"}}),
    ] {
        bytes.extend(serde_json::to_vec(&value)?);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

#[test]
fn metadata_queue_records_are_counted_and_later_native_turns_are_readable() -> Check {
    let initialized = initialize_host_process()?;
    let bytes = transcript()?;
    let records: Vec<Value> = bytes
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(serde_json::from_slice)
        .collect::<Result<_, _>>()?;
    let conversation = ProviderSessionId::new(
        records
            .iter()
            .find_map(|v| v.get("sessionId").and_then(Value::as_str))
            .ok_or("native conversation absent")?,
    )?;
    let f = Fixture::new()?;
    seed(&f)?;
    let session = session::session()?;
    let path = f.home.join("transcript.jsonl");
    std::fs::write(&path, &bytes)?;
    let native = NativePath::from_local(path.clone())?;
    let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("source absent")?;
    let source = session::record()?;
    let (mut direct, lease) = direct(&f)?;
    let mut prepared = session::prepared(&f, &session, &f.a);
    if let EventBody::SessionPrepared { native_ref, .. } = &mut prepared {
        *native_ref = conversation.as_str().into();
    }
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("fixture-metadata-queue-setup")?),
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
            identity: SessionIdentity { project:f.project.clone(), agent:f.a.clone(), session:session.clone() },
            conversation:conversation.clone(), path:native.clone(), file_identity:Sha256::from_bytes(pin.identity()),
        }, source, pin, &bound()?).await?;
        let execution = host.execution_context();
        let mut scope = f.self_scope(&f.a);
        scope.admission.session = Some(session);
        let stop = host.local_stop();
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let consumer = async {
            let result: Check = async {
                capture.catch_up(scope.admission.clone(), conversation.clone(), native.clone(), &bound()?).await?;
                let mut snapshot = execution.reader.snapshot(scope.clone())?;
                let page = snapshot.turns(f.a.clone(), budget(100, 1_000_000, None)?)?;
                let mut roles = [0, 0];
                let mut queue_count = 0;
                for event in page.items() {
                    let EventBody::SessionTurn { role, text:StoredText::Present(text), .. } = &event.body
                        else { return Err("unreadable captured body".into()); };
                    match role {
                        Role::User => roles[0] += 1,
                        Role::Assistant => roles[1] += 1,
                        Role::System => {
                            let body: Value = serde_json::from_str(text)?;
                            require(body.get("queued_input").is_none(), "bookkeeping invented queued input or an outcome")?;
                            if body["kind"] == "queue-operation" {
                                queue_count += body["count"].as_u64().ok_or("queue aggregate count absent")?;
                            }
                        }
                        Role::Tool => return Err("tool-only native message became chat".into()),
                    }
                }
                require(roles == [1, 2], "native text turns were lost behind queue bookkeeping")?;
                require(queue_count == 2, "metadata enqueue/dequeue were not counted exactly")?;
                let before = present(snapshot.capture_source(source)?)?;
                snapshot.close()?;
                capture.catch_up(scope.admission.clone(), conversation, native, &bound()?).await?;
                let mut replay = execution.reader.snapshot(scope)?;
                let after = present(replay.capture_source(source)?)?;
                require(before.revision == after.revision, "unchanged native tail advanced on replay")?;
                require(replay.turns(f.a.clone(), budget(100, 1_000_000, None)?)?.items().len() == page.items().len(),
                    "replay duplicated captured turns")?;
                replay.close()?;
                eprintln!("native_records={} bytes={} queue_bookkeeping={} user_turns={} assistant_turns={} replay_duplicates=0",
                    records.len(), bytes.len(), queue_count, roles[0], roles[1]);
                Ok(())
            }.await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), consumer).await;
        drop(capture);
        drop(execution);
        let report = exit.finish(&bound()?).await;
        require(report.transport_closed && report.endpoint_retired, "capture consumer cleanup incomplete")?;
        result
    })
}
