//! Native feasibility only; production checkpoint policy is unchanged.
//! A frame eligibility bound cannot bound a filesystem write or sync duration.
use rusqlite::{Connection, OpenFlags, backup, params};
use serde::Serialize;
use serde_json::{Value, json};
use std::{error::Error, fs, io, path::Path, time::Duration};

type ProbeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
const TARGET_FRAMES: i64 = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct State {
    rows: i64,
    groups: i64,
}
#[derive(Clone, Copy, Debug, Serialize)]
struct Wal {
    busy: i64,
    log: i64,
    done: i64,
}
#[derive(Debug)]
struct Chunk {
    start: i64,
    end: i64,
    max_group: i64,
}
struct Pin {
    db: Connection,
    state: State,
}
#[derive(Default, Serialize)]
struct Report {
    platform: String,
    library: String,
    steps: Vec<Value>,
    cases: Vec<Value>,
    complete: bool,
    error: Option<String>,
}

fn connection(path: &Path, writable: bool) -> ProbeResult<Connection> {
    let flags = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let db = Connection::open_with_flags(path, flags)?;
    db.busy_timeout(Duration::ZERO)?;
    db.execute_batch("PRAGMA mmap_size=0; PRAGMA cache_size=-512; PRAGMA temp_store=FILE;")?;
    if writable {
        db.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA wal_autocheckpoint=0;")?;
    }
    Ok(db)
}
fn wal(db: &Connection, mode: &str) -> ProbeResult<Wal> {
    let row = db.query_row(&format!("PRAGMA wal_checkpoint({mode})"), [], |r| {
        Ok(Wal {
            busy: r.get(0)?,
            log: r.get(1)?,
            done: r.get(2)?,
        })
    })?;
    assert!(row.log >= 0 && row.done >= 0 && row.done <= row.log);
    Ok(row)
}
fn worker(path: &Path, mode: &'static str) -> ProbeResult<Wal> {
    // A separate native connection models one turn of the existing worker.
    // Thread startup is deliberately outside any performance claim.
    let path = path.to_owned();
    std::thread::spawn(move || wal(&connection(&path, true)?, mode))
        .join()
        .map_err(|_| io::Error::other("checkpoint fixture worker panicked"))?
}
fn state(db: &Connection) -> ProbeResult<State> {
    let (rows, max): (i64, i64) =
        db.query_row("SELECT count(*),coalesce(max(id),0) FROM events", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
    assert_eq!(rows, max, "committed event identities are discontinuous");
    let groups = db.query_row("SELECT serial FROM hot WHERE id=1", [], |r| r.get(0))?;
    Ok(State { rows, groups })
}
impl Pin {
    fn open(path: &Path, expected: State) -> ProbeResult<Self> {
        let db = connection(path, false)?;
        db.execute_batch("BEGIN")?;
        assert_eq!(state(&db)?, expected);
        Ok(Self {
            db,
            state: expected,
        })
    }
    fn verify(&self) -> ProbeResult<()> {
        assert_eq!(state(&self.db)?, self.state, "reader snapshot changed");
        Ok(())
    }
    fn release(self) -> ProbeResult<()> {
        self.verify()?;
        self.db.execute_batch("ROLLBACK")?;
        self.db.close().map_err(|(_, error)| error)?;
        Ok(())
    }
}
fn append(db: &Connection, live: &mut State, rows: i64) -> ProbeResult<i64> {
    let before = wal(db, "NOOP")?;
    let tx = db.unchecked_transaction()?;
    for id in live.rows + 1..=live.rows + rows {
        let payload = vec![(id % 251) as u8; 3500];
        tx.execute(
            "INSERT INTO events(id,payload) VALUES(?1,?2)",
            params![id, payload],
        )?;
    }
    tx.execute(
        "UPDATE hot SET serial=?1,payload=zeroblob(3500) WHERE id=1",
        [live.groups + 1],
    )?;
    tx.commit()?;
    live.rows += rows;
    live.groups += 1;
    let after = wal(db, "NOOP")?;
    assert!(after.log > before.log, "WAL reset inside a retained window");
    Ok(after.log - before.log)
}
fn chunk(db: &Connection, live: &mut State, group_rows: i64) -> ProbeResult<Chunk> {
    let start = wal(db, "NOOP")?.log;
    let mut max_group = 0;
    while wal(db, "NOOP")?.log - start < TARGET_FRAMES {
        max_group = max_group.max(append(db, live, group_rows)?);
    }
    let end = wal(db, "NOOP")?.log;
    assert!(end - start <= TARGET_FRAMES + max_group);
    Ok(Chunk {
        start,
        end,
        max_group,
    })
}
fn step(
    path: &Path,
    db: &Connection,
    target: &Chunk,
    pins: &[&Pin],
    report: &mut Report,
) -> ProbeResult<()> {
    let before = wal(db, "NOOP")?;
    let copied = worker(path, "PASSIVE")?;
    report.steps.push(json!({
        "before":before,"after":copied,"target":target.end,
        "chunk_start":target.start,"max_atomic_group_frames":target.max_group,
        "eligibility_bound":TARGET_FRAMES+target.max_group,"own_read_pins":pins.len()
    }));
    assert_eq!(copied.busy, 0);
    assert_eq!(copied.log, before.log);
    assert_eq!(
        copied.done, target.end,
        "copy did not finish its declared endmark"
    );
    assert!(copied.done >= before.done);
    assert!(copied.done - before.done <= TARGET_FRAMES + target.max_group);
    assert!(pins.len() <= 2);
    for pin in pins {
        pin.verify()?;
    }
    Ok(())
}
fn reset(path: &Path, db: &Connection) -> ProbeResult<()> {
    let before = wal(db, "NOOP")?;
    assert_eq!(before.log, before.done, "reset would still copy data");
    let after = worker(path, "TRUNCATE")?;
    assert_eq!((after.busy, after.log, after.done), (0, 0, 0));
    Ok(())
}
fn verify_events(path: &Path, expected: State) -> ProbeResult<()> {
    let db = connection(path, false)?;
    assert_eq!(state(&db)?, expected);
    let mut statement = db.prepare("SELECT id,payload FROM events ORDER BY id")?;
    let mut rows = statement.query([])?;
    let mut next = 1;
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let payload: Vec<u8> = row.get(1)?;
        assert_eq!(id, next);
        assert_eq!(payload.len(), 3500);
        assert!(payload.iter().all(|b| *b == (id % 251) as u8));
        next += 1;
    }
    assert_eq!(next - 1, expected.rows);
    Ok(())
}
fn rolling_window(
    path: &Path,
    db: &Connection,
    live: &mut State,
    group_rows: i64,
    report: &mut Report,
) -> ProbeResult<()> {
    let first = chunk(db, live, group_rows)?;
    let a = Pin::open(path, *live)?;
    let second = chunk(db, live, group_rows)?;
    let b = Pin::open(path, *live)?;
    // Production admission would pause here until the oldest turn finishes.
    step(path, db, &first, &[&a, &b], report)?;
    assert!(wal(db, "NOOP")?.done < second.end);
    a.release()?;
    let third = chunk(db, live, group_rows)?;
    let c = Pin::open(path, *live)?;
    step(path, db, &second, &[&b, &c], report)?;
    b.release()?;
    // Catch up to the current head with producer admission still paused.
    step(path, db, &third, &[&c], report)?;
    c.release()?;
    reset(path, db)?;
    verify_events(path, *live)?;
    report
        .cases
        .push(json!({"case":"rolling-window","group_rows":group_rows,
        "committed_events":live.rows,"wal_generation_reset":true,"producer_window_pins":2}));
    Ok(())
}
fn pinned_backup(
    path: &Path,
    db: &Connection,
    live: &mut State,
    report: &mut Report,
) -> ProbeResult<()> {
    append(db, live, 8)?;
    let source = Pin::open(path, *live)?;
    let source_end = wal(db, "NOOP")?.log;
    let mut destination = Connection::open_in_memory()?;
    let backup = backup::Backup::new(&source.db, &mut destination)?;
    assert!(matches!(backup.step(1)?, backup::StepResult::More));
    let target = chunk(db, live, 64)?;
    let a = Pin::open(path, *live)?;
    let next = chunk(db, live, 64)?;
    let b = Pin::open(path, *live)?;
    let pending = worker(path, "PASSIVE")?;
    assert_eq!(pending.done, source_end);
    assert!(pending.done < target.end);
    source.verify()?;
    a.verify()?;
    b.verify()?;
    // Abort the partial backup before releasing its source snapshot.
    drop(backup);
    source.release()?;
    step(path, db, &target, &[&a, &b], report)?;
    a.release()?;
    step(path, db, &next, &[&b], report)?;
    b.release()?;
    reset(path, db)?;
    verify_events(path, *live)?;
    report
        .cases
        .push(json!({"case":"backup-abort","pending_observed":pending,
        "producer_admission":"held while both own pins occupied","abort_released_progress":true}));
    Ok(())
}
fn readmark_pressure(
    path: &Path,
    db: &Connection,
    live: &mut State,
    report: &mut Report,
) -> ProbeResult<()> {
    let mut foreign = Vec::new();
    for _ in 0..3 {
        append(db, live, 8)?;
        foreign.push(Pin::open(path, *live)?);
    }
    let target = chunk(db, live, 64)?;
    let a = Pin::open(path, *live)?;
    let next = chunk(db, live, 64)?;
    let b = match Pin::open(path, *live) {
        Ok(pin) => Some(pin),
        Err(error)
            if matches!(error.downcast_ref::<rusqlite::Error>(),
                Some(rusqlite::Error::SqliteFailure(code, _))
                if matches!(code.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    let pending = worker(path, "PASSIVE")?;
    assert!(
        pending.done < target.end,
        "foreign readers did not retain debt"
    );
    for pin in foreign {
        pin.release()?;
    }
    // Finish the oldest declared target before retiring it. A newer snapshot
    // may share its older readmark when the native slots were occupied.
    let second_pin_acquired = b.is_some();
    if let Some(pin) = &b {
        step(path, db, &target, &[&a, pin], report)?;
    } else {
        step(path, db, &target, &[&a], report)?;
    }
    a.release()?;
    // Admission and checkpoint ownership remain held across this refresh.
    // Copying to the current head before this oldest turn would merge chunks.
    if let Some(pin) = b {
        pin.release()?;
    }
    let renewed = Pin::open(path, *live)?;
    step(path, db, &next, &[&renewed], report)?;
    let observed = wal(db, "NOOP")?;
    renewed.release()?;
    reset(path, db)?;
    verify_events(path, *live)?;
    report.cases.push(
        json!({"case":"readmark-pressure","distinct_foreign_snapshots":3,
        "pending":pending,"renewed":observed,"second_pin_acquired":second_pin_acquired}),
    );
    Ok(())
}
fn probe(root: &Path, report: &mut Report) -> ProbeResult<()> {
    let path = root.join("state.db");
    let db = Connection::open(&path)?;
    db.busy_timeout(Duration::ZERO)?;
    db.execute_batch(
        "PRAGMA page_size=4096; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
        PRAGMA wal_autocheckpoint=0; PRAGMA cache_size=-512; PRAGMA mmap_size=0;
        CREATE TABLE events(id INTEGER PRIMARY KEY,payload BLOB NOT NULL);
        CREATE TABLE hot(id INTEGER PRIMARY KEY,serial INTEGER NOT NULL,payload BLOB);
        INSERT INTO hot VALUES(1,0,zeroblob(3500));",
    )?;
    let page_size: i64 = db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    assert_eq!(page_size, 4096);
    let initial = wal(&db, "TRUNCATE")?;
    assert_eq!((initial.busy, initial.log, initial.done), (0, 0, 0));
    let mut live = State { rows: 0, groups: 0 };
    rolling_window(&path, &db, &mut live, 64, report)?;
    rolling_window(&path, &db, &mut live, 64, report)?;
    // The bound includes one atomic group; this deliberately exceeds 256 frames.
    rolling_window(&path, &db, &mut live, 1024, report)?;
    pinned_backup(&path, &db, &mut live, report)?;
    readmark_pressure(&path, &db, &mut live, report)?;
    db.close().map_err(|(_, error)| error)?;
    verify_events(&path, live)?;
    Ok(())
}

#[test]
fn committed_endmarks_bound_each_copy_before_latency_work() -> ProbeResult<()> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let root = std::env::temp_dir().join(format!("wal-endmark-{}-{nonce}", std::process::id()));
    fs::create_dir(&root)?;
    let mut report = Report {
        platform: std::env::consts::OS.into(),
        library: rusqlite::version().into(),
        ..Report::default()
    };
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| probe(&root, &mut report)));
    report.complete = matches!(&result, Ok(Ok(())));
    if let Ok(Err(error)) = &result {
        report.error = Some(error.to_string());
    } else if result.is_err() {
        report.error =
            Some("native frame-bound assertion failed; latency remains forbidden".into());
    }
    let output = std::env::var_os("WAL_ENDMARK_PROBE_OUTPUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("target/wal-endmark-proof.json"));
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, serde_json::to_vec_pretty(&report)?)?;
    fs::remove_dir_all(&root)?;
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
