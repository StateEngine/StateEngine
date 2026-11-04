//! Real pinned-rollout reader and host writer; no provider process is launched.
#![cfg(all(feature = "listener", target_os = "linux"))]
use se_host::*;
use se_store::*;
use se_types::{NativePath, ProviderSessionId, SessionId, Sha256};
use serde_json::json;
use std::{fs::OpenOptions, io::Write};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

fn setup(
    f: &Fixture,
    id: &SessionId,
    source: RecordId,
    identity: &[u8],
    conversation: &ProviderSessionId,
) -> Result<Vec<EventBody<InputText>>, Box<dyn std::error::Error>> {
    let mut prepared = session::prepared(f, id, &f.a);
    if let EventBody::SessionPrepared {
        provider,
        native_ref,
        ..
    } = &mut prepared
    {
        *provider = Provider::Codex;
        *native_ref = format!("se-codex-pending:{id}");
    }
    let mut bound = session::source(source, id, identity, Expected::Absent);
    if let EventBody::CaptureSource { native_ref, .. } = &mut bound {
        *native_ref = conversation.as_str().into();
    }
    Ok(vec![prepared, session::activated(id)?, bound])
}
fn record(n: u64) -> serde_json::Value {
    json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"native-thread","turn_id":format!("turn-{n}"),"item":{"type":"AgentMessage","id":format!("item-{n}"),"content":[{"type":"Text","text":format!("same native text {n}")}]}}})
}
fn rollout(path: &std::path::Path, prefix: bool) -> Check {
    let mut file = std::fs::File::create(path)?;
    writeln!(
        file,
        "{}",
        json!({"type":"session_meta","payload":{"id":"native-thread"}})
    )?;
    if prefix {
        writeln!(
            file,
            "{}",
            json!({"type":"event_msg","payload":{"type":"task_started"}})
        )?;
    }
    for n in 0..6 {
        writeln!(file, "{}", record(n))?;
    }
    file.sync_all()?;
    Ok(())
}

#[test]
fn resumed_rollout_keeps_original_events_and_verifies_its_own_source_ranges() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let first = session::session()?;
    let resumed = session::session()?;
    let first_source =
        se_core::ops::process_commit::session_credential_id(&first, "capture-source")?;
    let resumed_source =
        se_core::ops::process_commit::session_credential_id(&resumed, "capture-source")?;
    let conversation = ProviderSessionId::new("native-thread")?;
    let original_path = f.home.join("first.jsonl");
    let resumed_path = f.home.join("resumed.jsonl");
    rollout(&original_path, false)?;
    rollout(&resumed_path, true)?;
    let first_pin = se_proc::NativeSourcePin::open(&original_path)?.ok_or("first pin absent")?;
    let second_pin = se_proc::NativeSourcePin::open(&resumed_path)?.ok_or("second pin absent")?;
    let (mut direct, lease) = direct(&f)?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("codex-first")?),
            setup(
                &f,
                &first,
                first_source,
                &first_pin.identity(),
                &conversation,
            )?,
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
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        let capture = host.capture_handle();
        let execution = host.execution_context();
        let stop = host.local_stop();
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let consumer = async {
            let result: Check = async {
                let native_first = NativePath::from_local(original_path.clone())?;
                capture
                    .bind(
                        TranscriptPin {
                            identity: SessionIdentity {
                                project: f.project.clone(),
                                agent: f.a.clone(),
                                session: first.clone(),
                            },
                            conversation: conversation.clone(),
                            path: native_first.clone(),
                            file_identity: Sha256::from_bytes(first_pin.identity()),
                        },
                        first_source,
                        first_pin,
                        &bound()?,
                    )
                    .await?;
                let mut admitted = f.self_scope(&f.a).admission;
                admitted.session = Some(first.clone());
                capture
                    .catch_up(admitted, conversation.clone(), native_first, &bound()?)
                    .await?;
                let mut snapshot = execution.reader.snapshot(f.self_scope(&f.a))?;
                let before = snapshot
                    .turns(f.a.clone(), budget(100, 100_000, None)?)?
                    .items()
                    .to_vec();
                require(before.len() == 6, "original capture differs")?;
                snapshot.close()?;
                let mut changes = vec![EventBody::SessionEnded {
                    session: first.clone(),
                    expected: revision(2)?,
                    reason: InputText::Inline("native stopped".into()),
                    final_turn: None,
                    final_cursor: None,
                }];
                changes.extend(setup(
                    &f,
                    &resumed,
                    resumed_source,
                    &second_pin.identity(),
                    &conversation,
                )?);
                execution
                    .writer
                    .submit(f.batch(
                        f.owner_project(),
                        Some(fixture::request("codex-resume")?),
                        changes,
                    )?)?
                    .await?;
                let native_second = NativePath::from_local(resumed_path.clone())?;
                capture
                    .bind(
                        TranscriptPin {
                            identity: SessionIdentity {
                                project: f.project.clone(),
                                agent: f.a.clone(),
                                session: resumed.clone(),
                            },
                            conversation: conversation.clone(),
                            path: native_second.clone(),
                            file_identity: Sha256::from_bytes(second_pin.identity()),
                        },
                        resumed_source,
                        second_pin,
                        &bound()?,
                    )
                    .await?;
                let mut admitted = f.self_scope(&f.a).admission;
                admitted.session = Some(resumed.clone());
                capture
                    .catch_up(
                        admitted.clone(),
                        conversation.clone(),
                        native_second.clone(),
                        &bound()?,
                    )
                    .await?;
                // Re-read the saved cursor while its last turn belongs to the old
                // session and its file/path/offsets belong to this new rollout.
                capture
                    .catch_up(
                        admitted.clone(),
                        conversation.clone(),
                        native_second.clone(),
                        &bound()?,
                    )
                    .await?;
                let mut snapshot = execution.reader.snapshot(f.self_scope(&f.a))?;
                let retained = snapshot.turns(f.a.clone(), budget(100, 100_000, None)?)?;
                require(
                    retained.items().len() == 6,
                    "B31-04: resumed rollout duplicated native history",
                )?;
                for (old, new) in before.iter().zip(retained.items()) {
                    require(
                        old.header.event == new.header.event
                            && old.header.occurred_at_us == new.header.occurred_at_us
                            && old.header.session == new.header.session,
                        "replay replaced original event provenance",
                    )?;
                }
                snapshot.close()?;
                let mut file = OpenOptions::new().append(true).open(&resumed_path)?;
                for n in 6..9 {
                    writeln!(file, "{}", record(n))?;
                }
                file.sync_all()?;
                capture
                    .catch_up(
                        admitted.clone(),
                        conversation.clone(),
                        native_second.clone(),
                        &bound()?,
                    )
                    .await?;
                capture
                    .catch_up(admitted, conversation, native_second, &bound()?)
                    .await?;
                let mut snapshot = execution.reader.snapshot(f.self_scope(&f.a))?;
                let turns = snapshot.turns(f.a.clone(), budget(100, 100_000, None)?)?;
                require(
                    turns.items().len() == 9,
                    "new native items were lost or replay grew history",
                )?;
                snapshot.close()?;
                Ok(())
            }
            .await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), consumer).await;
        drop(capture);
        drop(execution);
        let report = exit.finish(&bound()?).await;
        require(
            report.transport_closed && report.endpoint_retired,
            "capture host did not close",
        )?;
        result
    })
}
