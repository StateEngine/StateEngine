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
#[allow(
    dead_code,
    reason = "Only the deadline-bound poller is needed by this suite."
)]
mod native_host;
use native_host::{host, options, wait_until};
const HARD_FRAMES: i64 = 16384;
/// Per-1-MiB-batch allowance for the sustained phase: the claim is that
/// commits keep completing while the load runs, and a loaded runner is
/// allowed to spend this much per batch. One deadline is shared by all 64
/// batches, so the budget scales with the workload instead of slicing a
/// fixed window off each commit, and the 64-second total stays inside
/// nextest's 120-second termination threshold.
const BATCH_ALLOWANCE: Duration = Duration::from_secs(1);
/// No-progress bound per commit: the original five-second completion wait,
/// kept so a stuck writer fails its step instead of spending the whole
/// load budget.
const NO_PROGRESS: Duration = Duration::from_secs(5);
/// A one-shot batch has no workload to amortize over, so it gets eight batch
/// allowances of observation.
const SINGLE_ALLOWANCE: Duration = Duration::from_secs(8);
/// Close deadline for a case's own drain. The writer's drop seal is five
/// seconds, so the explicit drain names its own longer budget.
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);
/// Observation window for a drain: the join can spend the close deadline,
/// and the final flush I/O after it is not deadline-bounded.
const DRAIN_BUDGET: Duration = Duration::from_secs(20);
/// Settle window: the most the background task owes after the load is one
/// full checkpoint of a WAL at the 64 MiB cutoff, and a loaded runner can
/// stretch that single checkpoint well past a ten-second window.
const SETTLE_BUDGET: Duration = Duration::from_secs(20);

fn payload(f: &Fixture, key: &str) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let bodies = (0..40)
        .map(|n| {
            let pattern = format!("{key}-{n}-");
            let mut body = pattern.repeat(24500usize.div_ceil(pattern.len()));
            body.truncate(24500);
            Ok(EventBody::MessageSent {
                quiet: false,
                message: message()?,
                // Self-note: the load payload is a note to the sender, the
                // one mail shape the per-recipient rate cap exempts.
                recipient: Actor::Agent(f.a.clone()),
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
/// The writer owns the store until its drain joins the maintenance task and
/// the writer thread closes its connections; the fixture root cannot be
/// removed while that close cycle is live. Every case keeps the writer
/// behind this guard and takes it out only for the case's own drain
/// assertion, so a failed case still closes the store before cleanup.
struct Quiesce(Option<SqliteWriter>);
impl Quiesce {
    fn new(writer: SqliteWriter) -> Self {
        Self(Some(writer))
    }
    /// None once the case took the writer for its own drain assertion.
    fn take(&mut self) -> Option<SqliteWriter> {
        self.0.take()
    }
}
impl Drop for Quiesce {
    fn drop(&mut self) {
        let Some(writer) = self.0.take() else {
            return;
        };
        // Best effort: the case already failed, so the close result only
        // matters to the fixture cleanup that follows.
        let _ = wait_until(writer.drain(DRAIN_DEADLINE), Instant::now() + DRAIN_BUDGET);
    }
}

/// Protects: a pinned reader blocks the WAL reset but not the copy; after the
/// reader releases, the background task resets the file instead of leaving it
/// at its high-water size (the stranded-WAL defect).
#[test]
fn background_task_resets_the_wal_after_the_reader_releases() -> Check {
    let f = Fixture::new()?;
    let (h, lease) = host(&f)?;
    let writer = h.start_writer(options(256)?, lease.clone())?;
    let client = writer.client();
    let mut guard = Quiesce::new(writer);
    let path = f.options.state_directory.join("state.db");
    let pinned = observer(&path)?;
    pin(&pinned)?;
    let receipt = wait_until(
        client.submit(payload(&f, "bg-pinned")?)?,
        Instant::now() + SINGLE_ALLOWANCE,
    )??;
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
        SETTLE_BUDGET,
        || matches!(wal(&outside), Ok((0, 0, _))),
    )?;
    assert_eq!(
        std::fs::metadata(path.with_extension("db-wal"))?.len(),
        0,
        "reset left the WAL file behind"
    );
    let mut writer = guard.take().ok_or("writer was already drained")?;
    drop(wait_until(
        writer.flush(Duration::from_secs(4))?,
        Instant::now() + DRAIN_BUDGET,
    )??);
    drop(wait_until(
        writer.drain(DRAIN_DEADLINE),
        Instant::now() + DRAIN_BUDGET,
    )??);
    Ok(())
}

/// Protects: sustained writes stay available at the capacity cutoff and the
/// WAL settles to zero once idle. The checkpoint task keeps the WAL far below
/// the cutoff while it keeps up; under load it falls behind and the writer's
/// inline TRUNCATE backstop keeps every commit available instead. A commit may
/// therefore overshoot the cutoff by at most one in-flight batch (the
/// pre-append check passes only below it), so the first commit from an empty
/// WAL measures the bound.
#[test]
fn background_task_keeps_sustained_writes_below_the_cutoff() -> Check {
    let f = Fixture::new()?;
    let (h, lease) = host(&f)?;
    let writer = h.start_writer(options(256)?, lease.clone())?;
    let client = writer.client();
    let mut guard = Quiesce::new(writer);
    let outside = observer(&f.options.state_directory.join("state.db"))?;
    let mut largest_log = 0;
    let mut batch_frames = 0;
    let load_deadline = Instant::now() + BATCH_ALLOWANCE * 64;
    let mut last_progress;
    for n in 0..64 {
        let key = format!("bg-sustained-{n}");
        let pending = client.submit(payload(&f, &key)?)?;
        // Progress means the commit was handed to the writer; preparation
        // and sampling stay outside the no-progress window.
        last_progress = Instant::now();
        let step_deadline = (last_progress + NO_PROGRESS).min(load_deadline);
        let receipt = wait_until(pending, step_deadline)??;
        assert_eq!(receipt.state, CommitState::Committed);
        let log = wal(&outside)?.0;
        if n == 0 {
            batch_frames = log;
        }
        largest_log = largest_log.max(log);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        largest_log <= HARD_FRAMES + batch_frames,
        "sustained writes overshot the WAL cutoff by more than one in-flight batch: high water {largest_log} of {HARD_FRAMES} plus one batch of {batch_frames}"
    );
    poll(
        "background task to drain the settled WAL",
        SETTLE_BUDGET,
        || matches!(wal(&outside), Ok((0, 0, _))),
    )?;
    let writer = guard.take().ok_or("writer was already drained")?;
    drop(wait_until(
        writer.drain(DRAIN_DEADLINE),
        Instant::now() + DRAIN_BUDGET,
    )??);
    eprintln!(
        "sustained controls: 64 groups, high_water_frames={largest_log} of {HARD_FRAMES}, one batch {batch_frames}"
    );
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
    let client = writer.client();
    let context = writer.backup_context();
    let mut guard = Quiesce::new(writer);
    let path = f.options.state_directory.join("state.db");
    let outside = observer(&path)?;
    let receipt = wait_until(
        client.submit(payload(&f, "bg-backup")?)?,
        Instant::now() + SINGLE_ALLOWANCE,
    )??;
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
        SETTLE_BUDGET,
        || matches!(wal(&outside), Ok((0, 0, _))),
    )?;
    let writer = guard.take().ok_or("writer was already drained")?;
    drop(wait_until(
        writer.drain(DRAIN_DEADLINE),
        Instant::now() + DRAIN_BUDGET,
    )??);
    Ok(())
}
