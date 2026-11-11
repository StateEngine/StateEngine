//! Public writer durability across deferred maintenance, pressure and backup.
#![cfg(any(target_os = "linux", windows))]
use rusqlite::{Connection, OpenFlags};
use se_store::*;
use std::{io::Write, path::Path, time::Duration};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::{host, options, wait};
#[cfg(target_os = "linux")]
#[path = "support/deferred_checkpoint_crash.rs"]
mod crash;
const HARD: u64 = 64 * 1024 * 1024;

fn payload(f: &Fixture, key: &str) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let bodies = (0..40)
        .map(|n| {
            let pattern = format!("{key}-{n}-");
            let mut body = pattern.repeat(24500usize.div_ceil(pattern.len()));
            body.truncate(24500);
            Ok(EventBody::MessageSent {
                quiet: false,
                message: message()?,
                recipient: Actor::Agent(f.b.clone()),
                kind: "finding".into(),
                body: InputText::Inline(body),
                refs: vec![],
                reply_to: None,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    f.batch(
        f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
        Some(request(key)?),
        bodies,
    )
}
fn observer(path: &Path) -> Result<Connection, Box<dyn std::error::Error>> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}
fn wal(db: &Connection) -> Result<(i64, i64, u64), Box<dyn std::error::Error>> {
    let (log, done): (i64, i64) = db.query_row("PRAGMA wal_checkpoint(NOOP)", [], |r| {
        Ok((r.get(1)?, r.get(2)?))
    })?;
    assert!(
        log >= 0 && done >= 0 && log >= done,
        "invalid external WAL observation {log}/{done}"
    );
    let page: i64 = db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok((
        log,
        done,
        u64::try_from(log)? * (u64::try_from(page)? + 24) + 32,
    ))
}
fn pin(db: &Connection) -> Check {
    db.execute_batch("BEGIN")?;
    let _: i64 = db.query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
    Ok(())
}
fn healthy(db: &Connection) -> Check {
    assert_eq!(
        db.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))?,
        "ok"
    );
    assert!(!db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    Ok(())
}
fn member_ids(db: &Connection, key: &str) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(db.prepare("SELECT e.event_id FROM operations o JOIN operation_events m USING(operation_id) JOIN events e ON e.seq=m.event_seq WHERE o.request_key=? ORDER BY m.ordinal")?
        .query_map([key], |r| r.get(0))?.collect::<rusqlite::Result<Vec<_>>>()?)
}
fn matches_receipt(db: &Connection, key: &str, receipt: &CommitReceipt) -> Check {
    let expected: Vec<Vec<u8>> = receipt
        .events
        .iter()
        .map(|id| {
            Ok(
                uuid::Uuid::parse_str(id.as_str().strip_prefix("ev_").ok_or("event prefix")?)?
                    .as_bytes()
                    .to_vec(),
            )
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;
    assert_eq!(
        member_ids(db, key)?,
        expected,
        "returned operation membership changed"
    );
    Ok(())
}

/// Protects: direct/bootstrap receipts use the same soft deferral policy; a
/// caller sees known committed data while checkpoint debt remains explicit.
#[test]
fn direct_receipt_defers_soft_maintenance_without_hiding_commit() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let receipt = direct.append(payload(&f, "direct-pending")?, &*lease)?;
    assert_eq!(receipt.state, CommitState::Committed);
    assert!(
        receipt.maintenance_pending,
        "direct receipt hid deferred maintenance"
    );
    let outside = observer(&f.options.state_directory.join("state.db"))?;
    let (log, done, _) = wal(&outside)?;
    assert!(
        log >= 256 && log > done,
        "direct append performed its soft checkpoint inline"
    );
    matches_receipt(&outside, "direct-pending", &receipt)?;
    healthy(&outside)?;
    direct.close()?;
    Ok(())
}

/// Protects: sustained writes cannot postpone the hard cutoff; a blocked reader
/// permits at most one committed group overshoot, then retry is refused unchanged.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at the guardrail rebaseline onto current main; delete this expect when the lint is fixed"
)]
fn pressure_blocks_growth_and_retries_after_reader_releases() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let mut writer = host.start_writer(options(256)?, lease.clone())?;
    let client = writer.client();
    let path = f.options.state_directory.join("state.db");
    let pinned = observer(&path)?;
    pin(&pinned)?;
    let outside = observer(&path)?;
    let mut before = wal(&outside)?.2;
    let mut largest_group_growth = 0;
    let mut commits = Vec::new();
    let mut crossed = false;
    for n in 0..128 {
        let key = format!("pressure-{n}");
        let receipt = wait(client.submit(payload(&f, &key)?)?)??;
        assert_eq!(receipt.state, CommitState::Committed);
        let after = wal(&outside)?.2;
        largest_group_growth = largest_group_growth.max(after.saturating_sub(before));
        if after >= HARD {
            assert!(
                receipt
                    .write_timings
                    .as_ref()
                    .is_some_and(|t| t.checkpoint.is_some()),
                "hard pressure did not run a foreground checkpoint"
            );
            assert!(
                receipt.maintenance_pending,
                "blocked pressure lost maintenance debt"
            );
            crossed = true;
        }
        commits.push((key, receipt));
        before = after;
        if crossed {
            break;
        }
    }
    assert!(crossed, "sustained fixture never reached the hard boundary");
    assert!(
        before < HARD + largest_group_growth,
        "more than one committed group grew past the cutoff"
    );
    let head: i64 = outside.query_row("SELECT max(seq) FROM events", [], |r| r.get(0))?;
    for _ in 0..2 {
        let refused = wait(client.submit(payload(&f, "pressure-retry")?)?)?
            .err()
            .ok_or("pressure admitted another group")?;
        assert_eq!(refused.code, StoreErrorCode::Busy);
        assert!(refused.cause.contains("64 MiB"));
        assert_eq!(wal(&outside)?.2, before, "refused append grew live WAL");
        assert_eq!(
            outside.query_row("SELECT max(seq) FROM events", [], |r| r.get::<_, i64>(0))?,
            head
        );
        assert!(member_ids(&outside, "pressure-retry")?.is_empty());
    }
    let mutation = se_store::atlas_resume::AtlasResumeMutation::Epoch {
        project: f.project.clone(),
        root: se_types::AtlasRootId::from_parts(1_700_000_001_000, [7; 10])?,
        expected: None,
        next: Some(se_types::IndexEpochId::from_parts(
            1_700_000_001_000,
            [8; 10],
        )?),
    };
    let refused = wait(client.atlas_resume(mutation.clone())?)?
        .err()
        .ok_or("auxiliary cursor writer bypassed pressure")?;
    assert_eq!(refused.code, StoreErrorCode::Busy);
    assert_eq!(wal(&outside)?.2, before);
    assert_eq!(
        outside.query_row("SELECT count(*) FROM atlas_resume_roots", [], |r| r
            .get::<_, i64>(0))?,
        0
    );
    pinned.execute_batch("ROLLBACK")?;
    let retry = wait(client.submit(payload(&f, "pressure-retry")?)?)??;
    assert_eq!(retry.state, CommitState::Committed);
    assert!(
        retry
            .write_timings
            .as_ref()
            .is_some_and(|t| t.checkpoint.is_some()),
        "pressure retry did not block on truncation before appending"
    );
    assert!(
        wal(&outside)?.2 < HARD,
        "released pressure did not truncate live WAL"
    );
    for (key, receipt) in &commits {
        matches_receipt(&outside, key, receipt)?;
    }
    matches_receipt(&outside, "pressure-retry", &retry)?;
    assert!(matches!(
        wait(client.atlas_resume(mutation)?)??,
        se_store::atlas_resume::AtlasResumeWrite::EpochSet
    ));
    healthy(&outside)?;
    eprintln!(
        "pressure controls: {} committed groups, cutoff={}, largest_group_growth={largest_group_growth}, high_water={before}, two unchanged refusals, retry committed",
        commits.len(),
        HARD
    );
    wait(writer.flush(Duration::from_secs(4))?)??;
    drop(wait(writer.drain(Duration::from_secs(4)))??);
    Ok(())
}

/// Protects: a real online backup while checkpoint work is pending contains the
/// complete returned receipt and can be copied into a fresh home and reopened.
#[test]
fn backup_during_pending_maintenance_reopens_consistently() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    drop(host);
    drop(lease);
    let lease = Lease::acquire_with_backup_ports(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
        true,
    )?;
    let host = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    let writer = host.start_writer(options(256)?, lease.clone())?;
    let context = writer.backup_context();
    let path = f.options.state_directory.join("state.db");
    let pinned = observer(&path)?;
    pin(&pinned)?;
    let receipt = wait(writer.client().submit(payload(&f, "backup-pending")?)?)??;
    assert!(receipt.maintenance_pending);
    assert!(!receipt.maintenance_failed);
    assert!(
        receipt
            .write_timings
            .as_ref()
            .is_some_and(|t| t.checkpoint.is_none())
    );
    let outside = observer(&path)?;
    let (log, done, _) = wal(&outside)?;
    assert!(
        log >= 256 && log > done,
        "backup did not start with unfinished WAL maintenance"
    );
    let report =
        SqliteFactory::backup(&f.options, lease.clone(), context, Duration::from_secs(10))?;
    assert_eq!(report.published.through, receipt.last);
    let restored = Fixture::new()?;
    let files = se_proc::NativeStateFiles::open(&restored.options.state_directory)?;
    let mut stage = files.create_staging(&restored.options.state_directory)?;
    let bytes = std::fs::read(&report.published.path)?;
    use sha2::{Digest, Sha256};
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&bytes)),
        report.published.sha256
    );
    assert_eq!(bytes.len() as u64, report.published.bytes);
    stage.file.write_all(&bytes)?;
    stage.file.sync_all()?;
    drop(stage.file);
    files.publish_no_replace(
        &stage.path,
        &restored.options.state_directory.join("state.db"),
    )?;
    let reader = present(SqliteFactory::open_reader(&restored.options)?)?;
    assert_eq!(reader.info()?.id, f.store);
    assert_eq!(reader.info()?.head, Some(receipt.last.clone()));
    let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
    let retained = present(
        snapshot.operation_receipt(Actor::Agent(f.a.clone()), request("backup-pending")?.key)?,
    )?;
    same_receipt(&receipt, &retained);
    assert_eq!(retained.state, CommitState::Committed);
    assert!(retained.write_timings.is_none());
    snapshot.close()?;
    let copied = observer(&restored.options.state_directory.join("state.db"))?;
    matches_receipt(&copied, "backup-pending", &receipt)?;
    healthy(&copied)?;
    assert_eq!(
        member_ids(&outside, "backup-pending")?,
        member_ids(&copied, "backup-pending")?
    );
    // This proves backup-file restoration, not the currently unimplemented
    // owner restore_backup operation and its separate incarnation protocol.
    pinned.execute_batch("ROLLBACK")?;
    drop(wait(writer.drain(Duration::from_secs(4)))??);
    Ok(())
}
