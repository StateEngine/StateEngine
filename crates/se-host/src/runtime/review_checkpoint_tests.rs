//! Reviewer-owned fault controls through the authenticated native stop consumer.
use super::test_support::{bound, fixture::*, seed, start};
use super::*;
use crate::client::{BlockingIpcClient, endpoint::RuntimeStopOutcome};
use se_store::{HostStore, LeaseIdentity, RuntimeLease, StateFiles, StoreResult, WriterOwner};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

struct PanicTask {
    inner: Arc<HostLease>,
    fired: Arc<AtomicBool>,
}
impl RuntimeLease for PanicTask {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        if std::thread::current().name() == Some("se-store-checkpoint") {
            self.fired.store(true, Ordering::Release);
            panic!("review checkpoint native task failure");
        }
        self.inner.identity()
    }
    fn files(&self) -> &dyn StateFiles {
        self.inner.files()
    }
}
#[derive(Clone, Copy)]
enum Case {
    Panic,
    MissingCause,
    Clean,
}

fn stop_consumer(case: Case) -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        if !matches!(case, Case::Clean) {
            // Replace only the checkpoint's lease adapter. SQLite, the host lease,
            // writer, drain and shutdown coordinator remain the actual consumers.
            let first = host
                .writer
                .take()
                .ok_or("fixture writer absent")?
                .drain(Duration::from_secs(4))
                .await?;
            let fired = Arc::new(AtomicBool::new(false));
            let writer = first.host.start_writer(
                start(&f)?.writer,
                Arc::new(PanicTask {
                    inner: host.lease.clone(),
                    fired: fired.clone(),
                }),
            )?;
            host.execution.writer = writer.client();
            host.writer = Some(writer);
            let until = Instant::now() + Duration::from_secs(10);
            while !fired.load(Ordering::Acquire) && Instant::now() < until {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            if !fired.load(Ordering::Acquire) {
                return Err("checkpoint fault did not fire".into());
            }
            if matches!(case, Case::MissingCause) {
                // A report boundary fault: keep the real drain/host proof, but
                // withdraw the cause to test failed-without-cause separately.
                let mut drained = host
                    .writer
                    .take()
                    .ok_or("replacement writer absent")?
                    .drain(Duration::from_secs(4))
                    .await?;
                assert!(
                    drained.report.maintenance_failed && drained.report.maintenance_error.is_some()
                );
                drained.report.maintenance_error = None;
                host.flush = Some(drained.report);
                host.drained = Some(drained.host);
            }
        }
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let endpoint = listener.endpoint().clone();
        let key = se_types::Secret::new(vec![23; 32])?;
        let client = std::thread::spawn(move || {
            let options = crate::client::ClientOptions {
                expected_generation: Some(endpoint.generation),
                timeout: Duration::from_secs(15),
                cancelled: Arc::new(AtomicBool::new(false)),
            };
            let until = se_types::UnixMicros::new(
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_micros()
                    + 15_000_000) as u64,
            )
            .map_err(|e| e.to_string())?;
            BlockingIpcClient::stop(
                &endpoint,
                &key,
                se_types::IdempotencyKey::new("review-checkpoint-stop")
                    .map_err(|e| e.to_string())?,
                until,
                &options,
            )
            .map_err(|e| e.to_string())
        });
        let exit = host.serve(listener).await;
        let report = exit.finish(&bound()?).await;
        let reply = client.join().map_err(|_| "native stop client panicked")??;
        assert!(report.endpoint_retired && report.transport_closed);
        let RuntimeStopOutcome::Facts { pending, .. } = reply.outcome else {
            return Err("native stop returned a refusal instead of shutdown facts".into());
        };
        println!("native_stop_pending={pending:?}");
        match case {
            Case::Panic => {
                let diagnostic = pending
                    .iter()
                    .find(|text| text.contains("review checkpoint native task failure"))
                    .ok_or("native shutdown omitted checkpoint panic")?;
                assert!(
                    diagnostic.contains("Background store maintenance failed"),
                    "{diagnostic}"
                );
                assert!(
                    diagnostic.contains("se down")
                        && diagnostic.contains("se up")
                        && diagnostic.contains("recreate"),
                    "failed shutdown supplied no working recreation step: {diagnostic}"
                );
            }
            Case::MissingCause => {
                let diagnostic = pending
                    .iter()
                    .find(|text| text.contains("recorded cause is unavailable"))
                    .ok_or("failed maintenance with absent cause was collapsed to clean")?;
                assert!(
                    diagnostic.contains("Preserve") && diagnostic.contains("restart"),
                    "{diagnostic}"
                );
            }
            Case::Clean => assert!(
                pending.is_empty(),
                "clean shutdown acquired invented debt: {pending:?}"
            ),
        }
        Ok(())
    })
}
#[test]
fn review_checkpoint_panic_reaches_native_stop_with_working_step() -> Check {
    stop_consumer(Case::Panic)
}
#[test]
fn review_checkpoint_missing_cause_is_still_failed() -> Check {
    stop_consumer(Case::MissingCause)
}
#[test]
fn review_checkpoint_clean_absence_remains_clean() -> Check {
    stop_consumer(Case::Clean)
}
