// Native runtime-owner observations in this fixture are implemented for Linux and Windows.
#![cfg(any(target_os = "linux", windows))]

use se_store::*;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::*;
use std::time::Duration;

/// Protects: S03/S08 — accepted host work commits after its waiter disappears, preserving the original receipt.
#[test]
fn dropped_waiter_is_resolved_by_the_same_key_and_drain_releases_the_lock() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let mut owner = host.start_writer(options(256)?, lease.clone())?;
    let client = owner.client();
    drop(client.submit(f.working("accepted", Expected::Absent, "drop-waiter")?)?);
    let flush = wait(owner.flush(Duration::from_secs(2))?)??;
    assert_eq!(flush.pending_requests, 0);
    assert!(flush.indeterminate.is_empty());
    let replay =
        wait(client.submit(f.working("accepted", Expected::Absent, "drop-waiter")?)?)??;
    assert_eq!(replay.state, CommitState::Replayed);
    assert_eq!(replay.writer.kind(), WriterKind::Host { generation: 1 });
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut s = reader.snapshot(f.self_scope(&f.a))?;
    let retained =
        present(s.operation_receipt(Actor::Agent(f.a.clone()), request("drop-waiter")?.key)?)?;
    same_receipt(&retained, &replay);
    assert_eq!(retained.state, CommitState::Committed);
    s.close()?;
    assert!(retained.write_timings.is_none());
    let timings = replay
        .write_timings
        .as_ref()
        .ok_or("host replay omitted its own timing")?;
    assert_eq!(timings.request_key, replay.request_key);
    assert!(timings.group_requests >= 1);
    let drained = wait(owner.drain(Duration::from_secs(2)))??;
    assert_eq!(drained.report.pending_requests, 0);
    assert_eq!(
        client
            .submit(f.working("closed", revision(1)?, "closed")?)
            .err()
            .ok_or("drained writer accepted")?
            .code,
        StoreErrorCode::WriterClosed
    );
    drop(drained);
    drop(client);
    drop(lease);
    // Another actual exclusive OS lock can be acquired after writer shutdown.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.options.state_directory.join("runtime.lock"))?;
    lock.try_lock()?;
    lock.unlock()?;
    Ok(())
}

/// Protects: S08 — a full queue refuses immediately while already accepted native work remains pending.
#[test]
fn queue_backpressure_and_failed_operation_do_not_cancel_other_work() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(1)?, lease.clone())?;
    let client = owner.client();
    let blocker = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    blocker.execute_batch("BEGIN IMMEDIATE")?;
    let accepted = client.submit(f.working("first", Expected::Absent, "pending")?)?;
    assert_eq!(
        client
            .submit(f.working("second", Expected::Absent, "overfull")?)
            .err()
            .ok_or("queue bound ignored")?
            .code,
        StoreErrorCode::Backpressure
    );
    blocker.execute_batch("ROLLBACK")?;
    let first = wait(accepted)??;
    assert_eq!(first.state, CommitState::Committed);
    let invalid = wait(client.submit(f.working("bad", Expected::Absent, "invalid-cas")?)?)?;
    assert_eq!(
        invalid.err().ok_or("stale CAS accepted")?.code,
        StoreErrorCode::RevisionConflict
    );
    let good = wait(client.submit(f.working("good", revision(1)?, "good")?)?)??;
    assert_eq!(good.state, CommitState::Committed);
    let drained = wait(owner.drain(Duration::from_secs(2)))??;
    drop(drained);
    Ok(())
}

/// Protects: S08 — the returned maintenance host retains its exclusive runtime lease until SQL closes.
#[test]
fn drained_host_keeps_exclusive_custody_until_its_connection_closes() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease)?;
    let drained = wait(owner.drain(Duration::from_secs(2)))??;
    let competitor = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.options.state_directory.join("runtime.lock"))?;
    let attempt = competitor.try_lock();
    assert!(
        matches!(attempt, Err(std::fs::TryLockError::WouldBlock)),
        "runtime lock escaped while the returned maintenance host still owns an open SQLite connection: {attempt:?}"
    );
    drop(drained);
    competitor.try_lock()?;
    competitor.unlock()?;
    Ok(())
}

/// Protects: S08 / section 20 — queue configuration cannot exceed the 1 MiB resident-byte ceiling.
#[test]
fn writer_configuration_refuses_more_than_one_mib_resident_bytes() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let mut config = options(256)?;
    config.resident_bytes = std::num::NonZeroU32::new(1024 * 1024 + 1).ok_or("resident bound")?;
    match host.start_writer(config, lease) {
        Err(error) => assert_eq!(error.code, StoreErrorCode::EventInvalid),
        Ok(owner) => {
            drop(wait(owner.drain(Duration::from_secs(2)))??);
            return Err(
                "writer admitted a resident-byte ceiling above section 20's 1 MiB bound".into(),
            );
        }
    }
    Ok(())
}
