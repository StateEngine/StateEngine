//! A real authenticated stop must report pending cleanup before its original clock expires.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
use se_host::{
    client::{BlockingIpcClient, ClientOptions, endpoint::RuntimeStopOutcome, lease::Deadline},
    *,
};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::*;
struct SlowCustody;
impl CustodyExecutor for SlowCustody {
    fn execute<'a>(
        &'a self,
        _: se_core::ports::CustodyPlan,
        _: se_store::Admission,
        _: &'a Deadline,
    ) -> HostFuture<'a, se_core::ops::AnyOutput> {
        Box::pin(async { Err(se_types::SeError::invalid("fixture", "shutdown only")) })
    }
    fn shutdown<'a>(&'a self, deadline: &'a Deadline) -> HostFuture<'a, CustodyShutdown> {
        Box::pin(async move {
            // Stop at a safety cap too, so a broken thirty-second host clock
            // cannot leave this negative test holding the real fixture writer.
            tokio::time::sleep_until(tokio::time::Instant::from_std(
                deadline.at().min(Instant::now() + Duration::from_secs(2)),
            ))
            .await;
            Ok(CustodyShutdown {
                complete: false,
                pending: vec![
                    "agent fixture-agent lifecycle fixture-lifecycle remains unproved".into(),
                ],
            })
        })
    }
}
#[test]
fn exhausted_native_cleanup_delivers_named_pending_facts_within_the_original_wire_deadline() -> Check
{
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
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let endpoint = listener.endpoint().clone();
        let (_, activity) = tokio::sync::watch::channel(0);
        host.install_custody(Arc::new(SlowCustody), activity)?;
        let key = se_types::Secret::new(vec![23; 32])?;
        let client = std::thread::spawn(move || {
            let options = ClientOptions {
                expected_generation: Some(endpoint.generation),
                timeout: Duration::from_secs(1),
                cancelled: Arc::new(AtomicBool::new(false)),
            };
            let until = se_types::UnixMicros::new(
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_micros()
                    + 1_000_000) as u64,
            )
            .map_err(|e| e.to_string())?;
            BlockingIpcClient::stop(
                &endpoint,
                &key,
                se_types::IdempotencyKey::new("deadline-stop").map_err(|e| e.to_string())?,
                until,
                &options,
            )
            .map_err(|e| e.to_string())
        });
        let exit = host.serve(listener).await;
        let mut report = exit.finish(&bound()?).await;
        let reply = client.join().map_err(|_| "stop client panicked")?;
        // The fixture has no native root: release its real retained writer even
        // when testing an expired wire deadline, before asserting the outcome.
        let drained = report.runtime.drain_storage(&bound()?).await?;
        assert!(drained.writer_joined);
        assert!(report.endpoint_retired && report.transport_closed);
        let reply = reply.map_err(|e| {
            format!("typed pending result missed the original one-second stop clock: {e}")
        })?;
        let RuntimeStopOutcome::Facts {
            pending, achieved, ..
        } = reply.outcome
        else {
            return Err("pending facts absent".into());
        };
        assert!(
            pending
                .iter()
                .any(|v| v.contains("fixture-agent") && v.contains("fixture-lifecycle"))
        );
        assert!(!achieved.contains(&se_host::client::endpoint::RuntimeStopFact::AgentsStopped));
        Ok(())
    })
}
