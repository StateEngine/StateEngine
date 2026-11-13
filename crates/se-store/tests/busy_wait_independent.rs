//! Busy refusals report the wait they actually spent: a BUSY failure means the
//! connection's configured busy timeout was fully consumed by SQLite's retry
//! loop, and the store says so instead of collapsing it to 0 ms.
#![cfg(any(target_os = "linux", windows))]
use rusqlite::{Connection, OpenFlags};
use se_store::*;
use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::{host, options, wait};

fn observer(path: &Path) -> Result<Connection, Box<dyn std::error::Error>> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}
fn payload(f: &Fixture, key: &str) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    f.batch(
        f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
        Some(request(key)?),
        (0..8)
            .map(|n| {
                Ok(EventBody::MessageSent {
                    quiet: false,
                    message: message()?,
                    recipient: Actor::Agent(f.b.clone()),
                    kind: "finding".into(),
                    body: InputText::Inline(format!("{key}-{n} busy-wait payload")),
                    refs: vec![],
                    reply_to: None,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?,
    )
}

/// A held WAL write lock longer than the old 250 ms host wait must not refuse
/// an ordinary write: the writer's busy handler rides out the hold (the
/// fixture's bound is 2 s, the hold 1.5 s).
#[test]
fn the_writer_absorbs_a_slow_write_lock_hold() -> Check {
    let f = Fixture::new()?;
    let (h, lease) = host(&f)?;
    let writer = h.start_writer(options(256)?, lease.clone())?;
    let client = writer.client();
    let path = f.options.state_directory.join("state.db");
    let holder = observer(&path)?;
    let release = thread::spawn(move || {
        match holder.execute_batch("BEGIN IMMEDIATE") {
            Ok(()) => {}
            Err(e) => panic!("holder takes the WAL write lock: {e}"),
        }
        thread::sleep(Duration::from_millis(1500));
        match holder.execute_batch("ROLLBACK") {
            Ok(()) => {}
            Err(e) => panic!("holder releases the WAL write lock: {e}"),
        }
    });
    thread::sleep(Duration::from_millis(150));
    let started = Instant::now();
    let receipt = wait(client.submit(payload(&f, "slow-hold")?)?)??;
    assert_eq!(receipt.state, CommitState::Committed);
    match release.join() {
        Ok(()) => {}
        Err(e) => panic!("holder thread: {e:?}"),
    }
    // The write started while the lock was held and waited out the remainder:
    // a refusal-class path (the old 250 ms wait) would have finished sooner
    // with a refusal, and an early start would finish almost immediately.
    assert!(
        started.elapsed() >= Duration::from_millis(1000),
        "write did not wait out the slow lock hold: {:?}",
        started.elapsed()
    );
    drop(wait(writer.drain(Duration::from_secs(4)))??);
    Ok(())
}

/// A refusal after the full configured bound reports that bound, not 0 ms.
#[test]
fn a_refused_write_reports_the_consumed_bound() -> Check {
    let f = Fixture::new()?;
    let (h, lease) = host(&f)?;
    let writer = h.start_writer(options(256)?, lease.clone())?;
    let client = writer.client();
    let path = f.options.state_directory.join("state.db");
    let holder = observer(&path)?;
    holder.execute_batch("BEGIN IMMEDIATE")?;
    let pending = client.submit(payload(&f, "busy-bound")?)?;
    // Hold past the fixture's 2 s bound so the writer's retry loop expires.
    thread::sleep(Duration::from_secs(3));
    let Err(error) = wait(pending)? else {
        panic!("the held lock must refuse the write");
    };
    holder.execute_batch("ROLLBACK")?;
    assert_eq!(error.code, StoreErrorCode::Busy);
    assert_eq!(
        error.detail,
        StoreDetail::BusyWait {
            waited_ms: 2000,
            extended_code: 5,
        }
    );
    drop(wait(writer.drain(Duration::from_secs(4)))??);
    Ok(())
}
