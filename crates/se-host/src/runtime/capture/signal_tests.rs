//! Real pinned source, host writer and public read model under a held source lock.
use super::*;
use crate::client::ClientOptions;
use crate::runtime::test_support as support;
use crate::*;
use se_core::{
    admission::HumanTerminal,
    ops::{AnyOp, HookClaude, HookEvent},
};
use se_store::*;
use se_types::{NativePath, ProviderSessionId, Sha256};
use serde_json::json;
use std::{sync::mpsc, time::Instant};
use support::session;
use support::*;

// Each source-lock race remains concurrent inside its fixture scenario.
static LISTENER: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn busy_stop_retries_and_publishes_completed_text_without_shutdown() -> Check {
    scenario("released")
}
#[test]
fn exhausted_busy_stop_records_one_visible_failure_and_later_capture_recovers() -> Check {
    scenario("held")
}
#[test]
fn busy_session_start_remains_read_only() -> Check {
    scenario("session-start")
}

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn scenario(case: &'static str) -> Check {
    let _listener = LISTENER
        .lock()
        .map_err(|_| "hook fixture listener lock poisoned")?;
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let session = session::session()?;
    let conversation = ProviderSessionId::new(format!("provider-{}", f.a.as_str()))?;
    let path = f.home.join("transcript.jsonl");
    std::fs::write(
        &path,
        format!(
            "{}\n",
            json!({"type":"assistant", "sessionId":conversation.as_str(), "uuid":"finished-reply", "message":{"role":"assistant", "content":"completed while host stays live"}})
        ),
    )?;
    let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("native source absent")?;
    let source = se_core::ops::process_commit::session_credential_id(&session, "capture-source")?;
    let (mut direct, lease) = direct(&f)?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("hook-source")?),
            vec![
                session::prepared(&f, &session, &f.a),
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
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        configure_private_listener(&mut host)?;
        let capture = host.capture_handle();
        let native_path = NativePath::from_local(path)?;
        capture
            .bind(
                TranscriptPin {
                    identity: SessionIdentity {
                        project: f.project.clone(),
                        agent: f.a.clone(),
                        session: session.clone(),
                    },
                    conversation: conversation.clone(),
                    path: native_path.clone(),
                    file_identity: Sha256::from_bytes(pin.identity()),
                },
                source,
                pin,
                &bound()?,
            )
            .await?;
        let execution = host.execution_context();
        let stop = host.local_stop();
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let router = host.router()?;
        let source_pin = capture.sources.get(&session)?;
        let (locked, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let holder = std::thread::spawn(move || -> std::result::Result<(), String> {
            let _guard = source_pin.lock().map_err(|e| e.to_string())?;
            locked.send(()).map_err(|e| e.to_string())?;
            if case == "released" {
                std::thread::sleep(Duration::from_millis(150));
            } else {
                released
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        });
        observed.recv_timeout(Duration::from_secs(2))?;
        let consumer = async {
            let result: Check = async {
                let mut admission = f.self_scope(&f.a).admission;
                admission.session = Some(session.clone());
                let call = || RoutedCall {
                    admitted: HostedCall {
                        remote_credential:None,
                        input: HostedInput::Operation(AnyOp::HookClaude(HookClaude {
                            event: HookEvent::Stop,
                        })),
                        kernel: Kernel::read_only(),
                        admission: admission.clone(),
                        terminal: HumanTerminal::Refused {
                            reason: "hook is not a human terminal".into(),
                        },
                        selections: None,
                    },
                    hook: Some(ClaudeHookInput {
                        kind: if case == "session-start" {
                            ClaudeHookKind::SessionStart
                        } else {
                            ClaudeHookKind::Stop
                        },
                        conversation: conversation.clone(),
                        claimed_transcript: native_path.clone(),
                        payload: json!({}),
                    }),
                };
                let short = || {
                    Deadline::from_options(&ClientOptions {
                        timeout: if case == "released" {
                            Duration::from_secs(2)
                        } else {
                            Duration::from_millis(300)
                        },
                        ..options()
                    })
                };
                let started = Instant::now();
                let first = router.execute_call(call(), &short()?).await;
                assert!(
                    started.elapsed() < Duration::from_secs(3),
                    "hook renewed its finite budget"
                );
                if case == "held" {
                    let mut read = execution.reader.snapshot(f.self_scope(&f.a))?;
                    let history = read.history(HistoryQuery { agent:Some(f.a.clone()), session:Some(session.clone()), kinds:vec![EventKind::CaptureFailed], families:vec![], transcript:TranscriptFilter::All, since:None }, budget(20, 100_000, None)?)?;
                    assert_eq!(history.items().len(), 1, "terminal busy capture did not record capture.failed while the host remained live");
                    read.close()?;
                }
                if case == "session-start" {
                    assert_eq!(
                        first
                            .err()
                            .ok_or("busy SessionStart wrote a result")?
                            .code(),
                        se_types::Code::StoreBusy
                    );
                } else {
                    let first = first?;
                    if case == "held" {
                        assert_ne!(first.output.exit_code(), 0, "explicit JSON hook capture failure returned success");
                    } else {
                        assert_eq!(first.output.exit_code(), 0);
                    }
                    let se_core::ops::AnyOutput::HookClaude(value) = first.output else {
                        return Err("wrong hook output".into());
                    };
                    assert!(value.value.stdout.is_empty());
                    if case == "held" {
                        assert!(value.value.failure.is_some());
                        assert!(matches!(value.value.captured, Read::Unreadable { .. }));
                        let repeated = router.execute_call(call(), &short()?).await?;
                        let se_core::ops::AnyOutput::HookClaude(repeated) = repeated.output else {
                            return Err("wrong repeated output".into());
                        };
                        assert!(repeated.value.failure.is_some());
                    } else {
                        assert!(value.value.failure.is_none());
                        assert!(started.elapsed() >= Duration::from_millis(100));
                    }
                }
                let mut read = execution.reader.snapshot(f.self_scope(&f.a))?;
                let turns = read.turns(f.a.clone(), budget(20, 100_000, None)?)?;
                assert_eq!(turns.items().len(), usize::from(case == "released"));
                let history = read.history(
                    HistoryQuery {
                        agent: Some(f.a.clone()),
                        session: Some(session.clone()),
                        kinds: vec![EventKind::CaptureFailed],
                        families: vec![],
                        transcript: TranscriptFilter::All,
                        since: None,
                    },
                    budget(20, 100_000, None)?,
                )?;
                assert_eq!(
                    history.items().len(),
                    usize::from(case == "held"),
                    "failure receipt missing, duplicated, or SessionStart wrote"
                );
                read.close()?;
                if case != "released" {
                    release.send(())?;
                }
                if case == "held" {
                    let recovered = router.execute_call(call(), &bound()?).await?;
                    let se_core::ops::AnyOutput::HookClaude(value) = recovered.output else {
                        return Err("wrong recovery output".into());
                    };
                    assert!(value.value.failure.is_none());
                    let mut read = execution.reader.snapshot(f.self_scope(&f.a))?;
                    assert_eq!(
                        read.turns(f.a.clone(), budget(20, 100_000, None)?)?
                            .items()
                            .len(),
                        1
                    );
                    read.close()?;
                }
                Ok(())
            }
            .await;
            if case != "released" {
                let _ = release.send(());
            }
            stop.request();
            result
        };
        let (exit, result) = futures_util::future::join(host.serve(listener), consumer).await;
        holder
            .join()
            .map_err(|_| "source holder panicked")?
            .map_err(|e| format!("source holder: {e}"))?;
        drop(router);
        drop(capture);
        drop(execution);
        let report = exit.finish(&bound()?).await;
        assert!(
            report.transport_closed && report.endpoint_retired,
            "hook fixture did not close"
        );
        result
    })
}
