//! Background WAL maintenance: the checkpoint task owns idle maintenance on its
//! own connection, so the writer never runs it and a drained WAL is reset.
#![cfg(any(target_os = "linux", windows))]
use rusqlite::{Connection, OpenFlags};
use se_store::*;
use std::{
    path::Path,
    time::{Duration, Instant},
};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::{host, options, wait};
const HARD_FRAMES: i64 = 16384;

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
fn poll<F>(what: &str, deadline: Duration, mut probe: F) -> Check
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < deadline {
        if probe() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(format!("timed out waiting for {what}").into())
}

/// Protects: a pinned reader blocks the WAL reset but not the copy; after the
/// reader releases, the background task resets the file instead of leaving it
/// at its high-water size (the stranded-WAL defect).
#[test]
fn background_task_resets_the_wal_after_the_reader_releases() -> Check {
    let f = Fixture::new()?;
    let (h, lease) = host(&f)?;
    let mut writer = h.start_writer(options(256)?, lease.clone())?;
    let client = writer.client();
    let path = f.options.state_directory.join("state.db");
    let pinned = observer(&path)?;
    pin(&pinned)?;
    let receipt = wait(client.submit(payload(&f, "bg-pinned")?)?)??;
    assert_eq!(receipt.state, CommitState::Committed);
    let outside = observer(&path)?;
    let (log, done, _) = wal(&outside)?;
    assert!(
        log >= 256 && log > done,
        "pinned fixture started without unfinished WAL maintenance"
    );
    pinned.execute_batch("ROLLBACK")?;
    poll(
        "background task to reset the released WAL",
        Duration::from_secs(10),
        || matches!(wal(&outside), Ok((0, 0, _))),
    )?;
    assert_eq!(
        std::fs::metadata(path.with_extension("db-wal"))?.len(),
        0,
        "reset left the WAL file behind"
    );
    drop(wait(writer.flush(Duration::from_secs(4))?)??);
    drop(wait(writer.drain(Duration::from_secs(4)))??);
    Ok(())
}

/// Protects: sustained writes stay far below the capacity cutoff with the
/// checkpoint off the writer task, and the WAL settles to zero once idle.
#[test]
fn background_task_keeps_sustained_writes_below_the_cutoff() -> Check {
    let f = Fixture::new()?;
    let (h, lease) = host(&f)?;
    let writer = h.start_writer(options(256)?, lease.clone())?;
    let client = writer.client();
    let outside = observer(&f.options.state_directory.join("state.db"))?;
    let mut largest_log = 0;
    for n in 0..64 {
        let key = format!("bg-sustained-{n}");
        let receipt = wait(client.submit(payload(&f, &key)?)?)??;
        assert_eq!(receipt.state, CommitState::Committed);
        largest_log = largest_log.max(wal(&outside)?.0);
        assert!(
            largest_log < HARD_FRAMES,
            "sustained writes reached the WAL cutoff at frame {largest_log}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    poll(
        "background task to drain the settled WAL",
        Duration::from_secs(10),
        || matches!(wal(&outside), Ok((0, 0, _))),
    )?;
    drop(wait(writer.drain(Duration::from_secs(4)))??);
    eprintln!("sustained controls: 64 groups, high_water_frames={largest_log} of {HARD_FRAMES}");
    Ok(())
}

/// Protects: the background task never runs while a backup pins the store;
/// the suppression stays effective from its own connection too.
#[test]
fn background_task_honors_backup_suppression() -> Check {
    let f = Fixture::new()?;
    let (h, lease) = host(&f)?;
    drop(h);
    drop(lease);
    let lease = Lease::acquire_with_backup_ports(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
        true,
    )?;
    let h = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    let writer = h.start_writer(options(256)?, lease.clone())?;
    let context = writer.backup_context();
    let path = f.options.state_directory.join("state.db");
    let outside = observer(&path)?;
    let receipt = wait(writer.client().submit(payload(&f, "bg-backup")?)?)??;
    assert_eq!(receipt.state, CommitState::Committed);
    let pinned = observer(&path)?;
    pin(&pinned)?;
    // Pinned: the task may copy up to the pin mark but must not reset, and a
    // concurrent backup must see the same suppression from the task side.
    let backup = se_store::SqliteFactory::backup(
        &f.options,
        lease.clone(),
        context,
        Duration::from_secs(10),
    )?;
    assert_eq!(backup.published.through, receipt.last);
    drop(backup);
    pinned.execute_batch("ROLLBACK")?;
    poll(
        "background task to reset the released WAL after backup",
        Duration::from_secs(10),
        || matches!(wal(&outside), Ok((0, 0, _))),
    )?;
    drop(wait(writer.drain(Duration::from_secs(4)))??);
    Ok(())
}
