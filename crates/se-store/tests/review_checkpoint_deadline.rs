//! Independent drain deadline control with the real SQLite writer and lease.
#![cfg(any(target_os = "linux", windows))]
use se_store::*;
use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;

struct HeldTask {
    inner: Arc<Lease>,
    entered: Arc<AtomicBool>,
    gate: Arc<(Mutex<bool>, Condvar)>,
}
impl RuntimeLease for HeldTask {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        if std::thread::current().name() == Some("se-store-checkpoint") {
            self.entered.store(true, Ordering::Release);
            let (lock, changed) = &*self.gate;
            let mut release = lock.lock().expect("control gate");
            while !*release {
                release = changed.wait(release).expect("control gate wait");
            }
        }
        self.inner.identity()
    }
    fn files(&self) -> &dyn StateFiles {
        self.inner.files()
    }
}

#[test]
fn review_checkpoint_hung_worker_respects_original_drain_deadline() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = native_host::host(&f)?;
    let entered = Arc::new(AtomicBool::new(false));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let wrapper = Arc::new(HeldTask {
        inner: lease,
        entered: entered.clone(),
        gate: gate.clone(),
    });
    let retained = Arc::downgrade(&wrapper);
    let writer = host.start_writer(native_host::options(256)?, wrapper)?;
    let until = Instant::now() + Duration::from_secs(10);
    while !entered.load(Ordering::Acquire) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    // Always release and join before judging, including the deliberately red base.
    let did_enter = entered.load(Ordering::Acquire);
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let began = Instant::now();
        let result = native_host::wait(writer.drain(Duration::from_millis(100)))
            .map_err(|error| error.to_string());
        let _ = send.send((began.elapsed(), result));
    });
    let early = receive.recv_timeout(Duration::from_millis(750));
    let returned_while_held = early.is_ok();
    let retained_while_held = retained.upgrade().is_some();
    {
        let (lock, changed) = &*gate;
        *lock.lock().map_err(|_| "control gate poisoned")? = true;
        changed.notify_all();
    }
    let (elapsed, result) = match early {
        Ok(value) => value,
        Err(_) => receive.recv_timeout(Duration::from_secs(5))?,
    };
    worker.join().map_err(|_| "drain driver panicked")?;
    let result = result?;
    let error = match result {
        Ok(drained) => {
            drop(drained);
            None
        }
        Err(error) => Some(error),
    };
    let released_by = Instant::now() + Duration::from_secs(5);
    while retained.upgrade().is_some() && Instant::now() < released_by {
        std::thread::sleep(Duration::from_millis(5));
    }
    println!(
        "drain_ms={} returned_while_held={returned_while_held} retained_while_held={retained_while_held} worker_released={}",
        elapsed.as_millis(),
        retained.upgrade().is_none()
    );
    assert!(did_enter, "real checkpoint did not enter the control");
    assert!(
        retained.upgrade().is_none(),
        "checkpoint retained its lease after release"
    );
    assert!(
        returned_while_held,
        "drain waited for the held checkpoint beyond its original 100 ms budget"
    );
    assert!(elapsed < Duration::from_millis(750));
    assert!(
        retained_while_held,
        "timed-out worker lost custody before its native work finished"
    );
    let error = error.ok_or("held maintenance incorrectly returned a clean host")?;
    assert_eq!(error.code, StoreErrorCode::Busy);
    assert!(
        error.cause.contains("closure is unproved"),
        "{}",
        error.cause
    );
    assert!(
        error.remedy.text.contains("Preserve") && error.remedy.text.contains("restart"),
        "{}",
        error.remedy.text
    );
    Ok(())
}
