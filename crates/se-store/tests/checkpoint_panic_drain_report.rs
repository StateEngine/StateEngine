//! A background checkpoint task that dies by panic must be named in the drain
//! report the owner receives, never read as clean maintenance.
#![cfg(any(target_os = "linux", windows))]

use se_store::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::{host, options, wait};

/// Delegates to the real lease, but panics when the checkpoint task asks for
/// the lease identity, so only that thread dies.
struct PanicOnTask {
    inner: Arc<Lease>,
    fired: Arc<AtomicBool>,
}
impl RuntimeLease for PanicOnTask {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        if std::thread::current().name() == Some("se-store-checkpoint") {
            self.fired.store(true, Ordering::Release);
            panic!("planted lease panic on the checkpoint task");
        }
        self.inner.identity()
    }
    fn files(&self) -> &dyn StateFiles {
        self.inner.files()
    }
}

/// Protects: a panicked checkpoint task reaches the drain report as Failed.
#[test]
fn drain_report_names_a_panicked_checkpoint_task() -> Check {
    let f = Fixture::new()?;
    let (h, lease) = host(&f)?;
    let fired = Arc::new(AtomicBool::new(false));
    let planted = Arc::new(PanicOnTask {
        inner: lease.clone(),
        fired: fired.clone(),
    });
    let writer = h.start_writer(options(256)?, planted)?;
    let start = Instant::now();
    while !fired.load(Ordering::Acquire) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the checkpoint task never reached the planted panic"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    let drained = wait(writer.drain(Duration::from_secs(4)))??;
    assert!(
        drained.report.maintenance_failed,
        "a dead checkpoint task must not drain as clean"
    );
    let error = drained
        .report
        .maintenance_error
        .as_ref()
        .ok_or("failed drain omitted its error")?;
    assert_eq!(error.code, StoreErrorCode::BackupFailed);
    assert!(
        error.cause.contains("planted lease panic"),
        "the panic must be named, got: {}",
        error.cause
    );
    Ok(())
}
