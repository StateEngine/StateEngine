//! The public host shutdown retains storage while native custody is incomplete.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
use se_host::client::lease::Deadline;
use se_host::*;
use se_store::*;
use se_types::Read;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;

struct UnsettledCustody {
    fail: bool,
    called: AtomicBool,
}
impl CustodyExecutor for UnsettledCustody {
    fn execute<'a>(
        &'a self,
        _: se_core::ports::CustodyPlan,
        _: Admission,
        _: &'a Deadline,
    ) -> HostFuture<'a, se_core::ops::AnyOutput> {
        Box::pin(async {
            Err(se_types::SeError::invalid(
                "judge coordinator",
                "no execution request in this shutdown-only consumer",
            ))
        })
    }
    fn shutdown<'a>(&'a self, _: &'a Deadline) -> HostFuture<'a, CustodyShutdown> {
        self.called.store(true, Ordering::SeqCst);
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                Err(se_types::SeError::invalid(
                    "native shutdown fixture",
                    "retained cleanup obligation",
                ))
            } else {
                Ok(CustodyShutdown {
                    complete: false,
                    pending: vec!["retained cleanup obligation".into()],
                })
            }
        })
    }
}
fn shutdown_case(fail: bool) -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host=HostedRuntime::prepare(initialized,start(&f)?,rt.handle().clone(),&bound()?).await?;
        let listener=host.listen(rt.handle().clone(),&bound()?).await?;
        let execution=host.execution_context();
        let custody=Arc::new(UnsettledCustody {fail,called:AtomicBool::new(false)});
        let (_activity,receiver)=tokio::sync::watch::channel(0);
        host.install_custody(custody.clone(),receiver)?;
        let stop=host.local_stop(); stop.request();
        let mut report=host.serve(listener).await.finish(&bound()?).await;
        let skipped=matches!(&report.storage,Read::Unreadable {reason,..} if reason.contains("retains its lease and writer"));
        let pending=report.pending.iter().any(|s|s.contains("retained cleanup obligation"));
        // The writer is a real retained FULL writer, not a count or a mock.
        let final_write=execution.writer.submit(f.working("cleanup still writes final capture",Expected::Absent,"final-custody-cleanup")?)?.await;
        let readback=if final_write.is_ok() {
            let mut read=execution.reader.snapshot(f.scoped(Visibility::Owner))?;
            let result=read.working_state(f.a.clone())?;
            read.close()?; matches!(result,Read::Present {..})
        } else {false};
        // This fixture has no native child. Finish its retained storage explicitly
        // after observing the failure; a red assertion must not strand the writer.
        let drained=report.runtime.drain_storage(&bound()?).await?;
        require(custody.called.load(Ordering::SeqCst),"native custody was not joined before storage")?;
        require(skipped && pending,"incomplete native custody did not retain a named storage obligation")?;
        require(final_write.is_ok() && readback,"shutdown drained the real writer before native custody completed")?;
        require(drained.writer_joined && drained.pending.is_empty(),"fixture storage cleanup incomplete")?;
        require(report.transport_closed && report.endpoint_retired,"transport cleanup was skipped after custody failure")
    })
}
#[test]
fn incomplete_custody_skips_storage_drain_and_retains_final_write_capacity() -> Check {
    shutdown_case(false)
}
#[test]
fn custody_shutdown_error_skips_storage_drain_and_keeps_its_failure() -> Check {
    shutdown_case(true)
}

/// Retained public coordinators cannot keep native custody or use drained storage.
#[test]
fn retained_router_and_capture_refuse_after_drain_without_retaining_the_lease() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let session = session::session()?;
    let source = session::record()?;
    let path = f.home.join("retained-transcript.jsonl");
    let conversation = se_types::ProviderSessionId::new(format!("provider-{}", f.a.as_str()))?;
    std::fs::write(
        &path,
        format!(
            "{}\n",
            serde_json::json!({"type":"session-owner","sessionId":conversation.as_str()})
        ),
    )?;
    let pin = se_proc::NativeSourcePin::open(&path)?.ok_or("native source absent")?;
    let binding = TranscriptPin {
        identity: SessionIdentity {
            project: f.project.clone(),
            agent: f.a.clone(),
            session: session.clone(),
        },
        conversation,
        path: se_types::NativePath::from_local(path.clone())?,
        file_identity: se_types::Sha256::from_bytes(pin.identity()),
    };
    let (mut direct, lease) = direct(&f)?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-wave2_host_shutdown_independent-126-{}",
                serial()
            ))?),
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
        let capture = host.capture_handle();
        capture
            .bind(binding.clone(), source, pin, &bound()?)
            .await?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let router = host.router()?;
        let call = || -> Result<RoutedCall, Box<dyn std::error::Error>> {
            let mut admission = f.self_scope(&f.a).admission;
            admission.session = Some(session.clone());
            Ok(RoutedCall {
                hook: None,
                admitted: HostedCall {
                    input: HostedInput::Operation(se_core::ops::AnyOp::WorkingStateGet(
                        Default::default(),
                    )),
                    kernel: se_core::dispatch::Kernel::new(se_core::dispatch::CallFacts {
                        event: fixture::event()?,
                        message: fixture::message()?,
                        agent: fixture::agent()?,
                        profile_event: fixture::event()?,
                        occurred_at_us: now()?,
                        door: Door::Cli,
                    })?,
                    admission,
                    terminal: se_core::admission::HumanTerminal::Refused {
                        reason: "agent read".into(),
                    },
                    selections: None,
                },
            })
        };
        router.execute_call(call()?, &bound()?).await?;
        host.local_stop().request();
        let report = host.serve(listener).await.finish(&bound()?).await;
        require(
            report.pending.is_empty() && report.transport_closed && report.endpoint_retired,
            "clean drain failed",
        )?;
        require(
            router.execute_call(call()?, &bound()?).await.is_err(),
            "retained router used drained storage",
        )?;
        drop(report);
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(f.options.state_directory.join("runtime.lock"))?;
        lock.try_lock()
            .map_err(|e| format!("retained router/capture held the OS lease: {e}"))?;
        let pin =
            se_proc::NativeSourcePin::open(&path)?.ok_or("retained transcript disappeared")?;
        let error = capture
            .bind(binding, source, pin, &bound()?)
            .await
            .err()
            .ok_or("expired capture handle admitted a new bind")?;
        require(
            matches!(error.body.detail(), se_types::Detail::RuntimeNotRunning(_)),
            format!("expired bind lost its structured reopen refusal: {error}"),
        )?;
        require(
            router.execute_call(call()?, &bound()?).await.is_err(),
            "router reopened after original lease release",
        )?;
        Ok(())
    })
}
