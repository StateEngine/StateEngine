//! Real pinned-rollout reader and host writer; no provider process is launched.
#![cfg(all(feature = "listener", target_os = "linux"))]
use se_host::*;
use se_store::*;
use se_types::{NativePath, ProviderSessionId, SessionId, Sha256};
use serde_json::json;
use std::time::{Duration, Instant};
use std::{fs::OpenOptions, io::Write};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

fn observed_conversation(
    f: &Fixture,
    mut read: impl Snapshot,
) -> Result<se_core::ops::AgentRow, Box<dyn std::error::Error>> {
    let admission = f.owner_project();
    let mut row = present(
        se_core::ops::agent_status::show(
            se_core::ops::AgentShow {
                target_agent_id: Some(f.a.clone()),
            },
            &mut se_core::commit::Cx {
                read: &mut read,
                admission: &admission,
            },
        )?
        .agent,
    )?;
    let plan = prepare_agent_observation(&f.project, &row, &mut read)?;
    read.close()?;
    observe_agent(plan, Instant::now() + Duration::from_secs(2))?.apply(&mut row)?;
    Ok(row)
}

fn unavailable(row: &se_core::ops::AgentRow, reason: &str) {
    assert_eq!(row.conversation.state, "unverifiable");
    assert!(!row.resume.ready && row.resume.command.is_none() && row.resume.argv.is_none());
    assert!(
        row.resume
            .reason
            .as_deref()
            .is_some_and(|r| r.contains(reason)),
        "{:?}",
        row.resume.reason
    );
}

fn setup(
    f: &Fixture,
    id: &SessionId,
    source: RecordId,
    identity: &[u8],
    conversation: &ProviderSessionId,
    backend: Provider,
) -> Result<Vec<EventBody<InputText>>, Box<dyn std::error::Error>> {
    let mut prepared = session::prepared(f, id, &f.a);
    if let EventBody::SessionPrepared {
        provider,
        native_ref,
        ..
    } = &mut prepared
    {
        *provider = backend;
        *native_ref = conversation.as_str().into();
    }
    let mut bound = session::source(source, id, identity, Expected::Absent);
    if let EventBody::CaptureSource { native_ref, .. } = &mut bound {
        *native_ref = conversation.as_str().into();
    }
    Ok(vec![prepared, session::activated(id)?, bound])
}
fn record(n: u64, backend: Provider) -> serde_json::Value {
    if backend == Provider::Claude {
        json!({"type":"assistant","sessionId":"native-thread","uuid":format!("uuid-{n}"),"message":{"role":"assistant","content":format!("same native text {n}")}})
    } else {
        json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"native-thread","turn_id":format!("turn-{n}"),"item":{"type":"AgentMessage","id":format!("item-{n}"),"content":[{"type":"Text","text":format!("same native text {n}")}]}}})
    }
}
fn tool_record(n: u64) -> serde_json::Value {
    json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"native-thread","turn_id":format!("turn-{n}"),"item":{"type":"CommandExecution","id":format!("command-{n}"),"command":format!("printf command-{n}"),"status":"completed","exit_code":0}}})
}
fn rollout(path: &std::path::Path, prefix: bool, backend: Provider, tools: bool) -> Check {
    let mut file = std::fs::File::create(path)?;
    if backend == Provider::Codex {
        writeln!(
            file,
            "{}",
            json!({"type":"session_meta","payload":{"id":"native-thread"}})
        )?;
    }
    if prefix {
        if backend == Provider::Codex {
            writeln!(
                file,
                "{}",
                json!({"type":"event_msg","payload":{"type":"task_started"}})
            )?;
        } else {
            writeln!(
                file,
                "{}",
                json!({"type":"user","sessionId":"native-thread","isSidechain":true})
            )?;
        }
    }
    for n in 0..6 {
        if tools {
            writeln!(file, "{}", tool_record(n))?;
        }
        writeln!(file, "{}", record(n, backend))?;
    }
    file.sync_all()?;
    Ok(())
}

#[test]
fn resumed_rollout_keeps_original_events_and_verifies_its_own_source_ranges() -> Check {
    resume_capture(Provider::Codex, false)
}
#[test]
fn resumed_claude_uuids_keep_original_events_and_verify_new_source_ranges() -> Check {
    resume_capture(Provider::Claude, false)
}
#[test]
fn resumed_codex_tools_keep_one_execution_and_each_sources_verified_cursor() -> Check {
    resume_capture(Provider::Codex, true)
}
struct ResumeSeed {
    original_path: std::path::PathBuf,
    resumed_path: std::path::PathBuf,
    first_pin: se_proc::NativeSourcePin,
    second_pin: se_proc::NativeSourcePin,
}

fn seed_resume_sessions(
    f: &Fixture,
    first: &SessionId,
    first_source: RecordId,
    conversation: &ProviderSessionId,
    backend: Provider,
    tools: bool,
) -> Result<ResumeSeed, Box<dyn std::error::Error>> {
    let original_path = f.home.join("first.jsonl");
    let resumed_path = f.home.join("resumed.jsonl");
    rollout(&original_path, false, backend, tools)?;
    rollout(&resumed_path, true, backend, tools)?;
    let first_pin = se_proc::NativeSourcePin::open(&original_path)?.ok_or("first pin absent")?;
    let second_pin = se_proc::NativeSourcePin::open(&resumed_path)?.ok_or("second pin absent")?;
    let (mut direct, lease) = direct(f)?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("saved-profile")?),
            vec![EventBody::ProfileSaved {
                agent: f.a.clone(),
                profile: Profile {
                    provider_settings: Default::default(),
                    provider: backend,
                    model: None,
                    permission: PermissionProfile::WorkspaceWrite,
                    harness: None,
                    named_profile: "default".into(),
                    effort: None,
                    external: false,
                },
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("codex-first")?),
            setup(
                f,
                first,
                first_source,
                &first_pin.identity(),
                conversation,
                backend,
            )?,
        )?,
        &*lease,
    )?;
    direct.close()?;
    drop(lease);
    Ok(ResumeSeed {
        original_path,
        resumed_path,
        first_pin,
        second_pin,
    })
}

fn verify_resumed_file_integrity(
    f: &Fixture,
    execution: &ExecutionContext,
    resumed_path: &std::path::Path,
) -> Check {
    // Status must use this new source range to verify the retained
    // native event, even though the event belongs to the old session.
    let snapshot = execution.reader.snapshot(f.scoped(Visibility::Owner))?;
    let row = observed_conversation(f, snapshot)?;
    assert_eq!(row.conversation.state, "saved", "{:?}", row.resume.reason);

    // Keep the inode and length; only the committed bytes differ.
    let original = std::fs::read(resumed_path)?;
    let mut changed = original.clone();
    let last = changed
        .iter_mut()
        .rev()
        .find(|b| **b == b't')
        .ok_or("text byte")?;
    *last = b'x';
    std::fs::write(resumed_path, changed)?;
    let snapshot = execution.reader.snapshot(f.scoped(Visibility::Owner))?;
    let row = observed_conversation(f, snapshot)?;
    unavailable(&row, "unchanged bytes");
    std::fs::write(resumed_path, &original)?;

    // A missing or replaced file cannot borrow the retained event's
    // old evidence, even when the replacement bytes are identical.
    let saved = resumed_path.with_extension("saved");
    std::fs::rename(resumed_path, &saved)?;
    let snapshot = execution.reader.snapshot(f.scoped(Visibility::Owner))?;
    unavailable(&observed_conversation(f, snapshot)?, "file is absent");
    std::fs::write(resumed_path, &original)?;
    let snapshot = execution.reader.snapshot(f.scoped(Visibility::Owner))?;
    unavailable(
        &observed_conversation(f, snapshot)?,
        "original captured file incarnation",
    );
    std::fs::remove_file(resumed_path)?;
    std::fs::rename(saved, resumed_path)?;
    Ok(())
}

struct ResumeCx<'a> {
    f: &'a Fixture,
    capture: &'a CaptureHandle,
    execution: &'a ExecutionContext,
    first: &'a SessionId,
    resumed: &'a SessionId,
    resumed_source: RecordId,
    conversation: &'a ProviderSessionId,
    backend: Provider,
    tools: bool,
    per_turn: usize,
}

async fn bind_and_catch_up_resumed(
    cx: &ResumeCx<'_>,
    second_pin: se_proc::NativeSourcePin,
    resumed_path: &std::path::Path,
    before: &[StoredEvent],
) -> Check {
    let (f, capture, execution, first, resumed, resumed_source, conversation, backend, per_turn) = (
        cx.f,
        cx.capture,
        cx.execution,
        cx.first,
        cx.resumed,
        cx.resumed_source,
        cx.conversation,
        cx.backend,
        cx.per_turn,
    );
    let mut changes = vec![EventBody::SessionEnded {
        session: first.clone(),
        expected: revision(2)?,
        reason: InputText::Inline("native stopped".into()),
        final_turn: None,
        final_cursor: None,
    }];
    changes.extend(setup(
        f,
        resumed,
        resumed_source,
        &second_pin.identity(),
        conversation,
        backend,
    )?);
    execution
        .writer
        .submit(f.batch(
            f.owner_project(),
            Some(fixture::request("codex-resume")?),
            changes,
        )?)?
        .await?;
    let native_second = NativePath::from_local(resumed_path.to_path_buf())?;
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
        retained.items().len() == 6 * per_turn,
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
    verify_resumed_file_integrity(f, execution, resumed_path)?;
    verify_resumed_tail_append(cx, admitted, native_second, resumed_path).await
}

async fn verify_resumed_tail_append(
    cx: &ResumeCx<'_>,
    admitted: Admission,
    native_second: NativePath,
    resumed_path: &std::path::Path,
) -> Check {
    let mut file = OpenOptions::new().append(true).open(resumed_path)?;
    for n in 6..9 {
        if cx.tools {
            writeln!(file, "{}", tool_record(n))?;
        }
        writeln!(file, "{}", record(n, cx.backend))?;
    }
    file.sync_all()?;
    cx.capture
        .catch_up(
            admitted.clone(),
            cx.conversation.clone(),
            native_second.clone(),
            &bound()?,
        )
        .await?;
    cx.capture
        .catch_up(admitted, cx.conversation.clone(), native_second, &bound()?)
        .await?;
    let mut snapshot = cx.execution.reader.snapshot(cx.f.self_scope(&cx.f.a))?;
    let turns = snapshot.turns(cx.f.a.clone(), budget(100, 100_000, None)?)?;
    require(
        turns.items().len() == 9 * cx.per_turn,
        "new native items were lost or replay grew history",
    )?;
    snapshot.close()?;
    Ok(())
}

fn resume_capture(backend: Provider, tools: bool) -> Check {
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
    let seeded = seed_resume_sessions(&f, &first, first_source, &conversation, backend, tools)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        configure_private_listener(&mut host)?;
        let capture = host.capture_handle();
        let execution = host.execution_context();
        let stop = host.local_stop();
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let consumer = async {
            let result: Check = async {
                let native_first = NativePath::from_local(seeded.original_path.clone())?;
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
                            file_identity: Sha256::from_bytes(seeded.first_pin.identity()),
                        },
                        first_source,
                        seeded.first_pin,
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
                let per_turn = if tools { 2 } else { 1 };
                require(before.len() == 6 * per_turn, "original capture differs")?;
                snapshot.close()?;
                let cx = ResumeCx {
                    f: &f,
                    capture: &capture,
                    execution: &execution,
                    first: &first,
                    resumed: &resumed,
                    resumed_source,
                    conversation: &conversation,
                    backend,
                    tools,
                    per_turn,
                };
                bind_and_catch_up_resumed(&cx, seeded.second_pin, &seeded.resumed_path, &before)
                    .await
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
