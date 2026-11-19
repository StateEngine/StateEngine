//! Native process loss during cold construction, and a final-flush witness
//! independent of SQLite's clean-close checkpoint.
#![cfg(any(target_os = "linux", windows))]

use se_atlas::{
    cache::{connection::*, pointer, *},
    lifecycle::*,
    model::*,
};
use se_host::{
    atlas_cache::NativeAtlasCache,
    atlas_cold::{
        self,
        job::ColdJob,
        protocol::{Phase, Reply, Request},
    },
    atlas_source::NativeAtlasSource,
};
use se_proc::atlas_worker::AtlasWorker;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

#[path = "../../test-support/directory.rs"]
mod directory;

type Check<T = ()> = Result<T, Box<dyn Error>>;
const MARKER: &str = "completed_epoch_final_transaction";
const PROBE_ROOT: &str = "SE_ATLAS_FINAL_FLUSH_TEST_ROOT";

fn end() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn sql_error(error: impl std::fmt::Display) -> se_types::SeError {
    se_types::SeError::invalid("Atlas crash test SQL", &error.to_string())
}

fn request(base: &Path, index: u8) -> Check<Request> {
    let source = base.join("source");
    let home = base.join("atlas");
    let project = se_types::ProjectId::from_parts(1, [21; 10])?;
    let root = RootId::from_parts(1, [22; 10])?;
    let reg = RootRegistration {
        cache: CacheLocation {
            directory: home.join(project.as_str()).join(root.as_str()),
        },
        canonical_source_root: source.clone(),
        project: project.clone(),
        root: root.clone(),
        git_metadata: None,
    };
    let registered = NativeAtlasSource::open(
        reg,
        if cfg!(windows) {
            CaseMode::InsensitivePreserving
        } else {
            CaseMode::Sensitive
        },
    )?;
    Ok(Request {
        history_unavailable: None,
        job: AtlasJobId([index; 16]),
        project,
        root,
        source_root: se_types::NativePath::from_local(source)?,
        home: se_types::NativePath::from_local(home)?,
        physical_root: registered.scope.physical_root,
        expected_epoch: None,
        epoch: CacheEpoch::from_parts(1, [index; 10])?,
        max_files: 16,
        ignore_digest: ContentHash([0; 32]),
        global_patterns: Vec::new(),
        generated_prefixes: Vec::new(),
    })
}

fn worker_image() -> Check<PathBuf> {
    for entry in ["SE_ATLAS_WORKER_BIN", "SE_W3_SE_BIN"] {
        if let Some(image) = std::env::var_os(entry) {
            return Ok(PathBuf::from(image).canonicalize()?);
        }
    }
    Err("provide the real native Atlas worker image".into())
}

fn next_frame(worker: &mut AtlasWorker, deadline: Instant) -> Check<Reply> {
    while Instant::now() < deadline {
        worker.wait_ready(deadline.min(Instant::now() + Duration::from_millis(250)))?;
        if let Some(bytes) = worker.receive()? {
            return Ok(serde_json::from_slice(&bytes)?);
        }
        if let Some(status) = worker.try_reap()? {
            #[cfg(target_os = "linux")]
            let diagnostic = worker.stderr_report();
            #[cfg(windows)]
            let diagnostic = worker.failure_diagnostic()?;
            return Err(format!("cold worker exited {status}: {diagnostic}").into());
        }
    }
    Err("expected cold phase was not reached".into())
}

fn unfinished_worker(worker: &mut AtlasWorker, request: &Request, deadline: Instant) -> Check {
    let mut checkpoint = false;
    loop {
        match next_frame(worker, deadline)? {
            Reply::Working { job, phase, .. } => {
                assert_eq!(job, request.job);
                match phase {
                    // SourceRead waits for authorization. At the second file,
                    // the previous file's checkpoint has already returned.
                    Phase::SourceRead if checkpoint => return Ok(()),
                    Phase::SourceRead | Phase::Resolve | Phase::Commit => {
                        worker.send_control(b"source", deadline)?;
                    }
                    Phase::Checkpoint => checkpoint = true,
                    _ => (),
                }
            }
            Reply::Progress { job, .. } => assert_eq!(job, request.job),
            Reply::Failed { error, .. } => return Err(error.message().into()),
            Reply::Completed { .. } => return Err("worker completed before crash point".into()),
        }
    }
}

fn rows(connection: &mut CacheConnection<'_>) -> Check<Vec<String>> {
    Ok(connection.read(end(), |sql| {
        sql.prepare("SELECT path FROM files ORDER BY path")?
            .query_map([], |row| row.get(0))
            .map_err(sql_error)?
            .collect::<Result<Vec<String>, _>>()
            .map_err(sql_error)
    })?)
}

fn interrupted_row_count(base: &Path, pin: &DatabasePin) -> Check<i64> {
    // Read a copy so SQLite recovery cannot change the crashed epoch before
    // the actual restart sees it.
    let replica = base.join("interrupted");
    fs::create_dir(&replica)?;
    let database = replica.join("atlas.db");
    fs::copy(&pin.path, &database)?;
    match fs::copy(
        pin.path.with_file_name("atlas.db-wal"),
        replica.join("atlas.db-wal"),
    ) {
        Ok(_) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let db = rusqlite::Connection::open_with_flags(
        &database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(db.query_row("SELECT count(*) FROM files", [], |row| row.get(0))?)
}

#[test]
fn cold_child_crash_mid_build_restarts_without_adopting_the_incomplete_epoch() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let base = directory::private_case_directory()?;
    fs::create_dir(base.join("source"))?;
    for path in ["first.js", "second.js", "third.js"] {
        fs::write(
            base.join("source").join(path),
            "export function ready(){return 1;}\n",
        )?;
    }
    let image = worker_image()?;
    let interrupted = request(&base, 23)?;
    let home = interrupted.home.to_local()?;
    let source = interrupted.source()?;
    let deadline = end();
    let mut worker =
        AtlasWorker::spawn_bounded(&image, &serde_json::to_vec(&interrupted)?, deadline)?;
    unfinished_worker(&mut worker, &interrupted, deadline)?;

    let cache =
        NativeAtlasCache::open(&home, source.scope.clone())?.ok_or("private cache absent")?;
    assert!(
        cache.read_pointer()?.is_none(),
        "mid-build epoch reached current"
    );
    assert!(
        worker.try_reap()?.is_none(),
        "worker exited before the induced crash"
    );
    worker.cancel_until(Instant::now() + Duration::from_secs(5))?;
    assert!(
        worker.try_reap()?.is_some_and(|status| !status.success()),
        "worker did not die"
    );
    drop(worker);
    assert!(
        cache.read_pointer()?.is_none(),
        "crash created a current epoch"
    );
    let partial = cache
        .pin_database(&interrupted.epoch)?
        .ok_or("interrupted epoch absent")?;
    assert_eq!(
        interrupted_row_count(&base, &partial)?,
        1,
        "the crash must have happened after exactly one file committed"
    );
    drop(partial);
    drop(cache);

    let clean = request(&base, 24)?;
    let mut rebuild = ColdJob::spawn(&image, clean.clone())?;
    let resume_end = end();
    let completed = loop {
        rebuild.wait_ready((Instant::now() + Duration::from_millis(100)).min(resume_end))?;
        if let Some(summary) = rebuild.poll()? {
            break summary;
        }
        if Instant::now() >= resume_end {
            rebuild.cancel_until(Instant::now() + Duration::from_secs(5))?;
            return Err("replacement cold job did not publish".into());
        }
    };
    assert!(completed.coverage.discovery_complete);
    assert_eq!(completed.coverage.discovered_files, 3);
    let reopened = NativeAtlasCache::open(&home, source.scope.clone())?.ok_or("cache absent")?;
    let mut current = pointer::open_current(
        &reopened,
        &source.scope,
        ConnectionRole::ExternalReader,
        &SqlProfile::contained_cold(),
        end(),
    )?
    .ok_or("no rebuilt epoch was published")?;
    assert_eq!(current.connection.identity().epoch, clean.epoch);
    assert_eq!(
        rows(&mut current.connection)?,
        ["first.js", "second.js", "third.js"]
    );
    assert!(
        reopened.pin_database(&interrupted.epoch)?.is_none(),
        "abandoned epoch was retained"
    );
    drop(current);
    drop(reopened);
    drop(rebuild);
    base.finish(Ok(()))
}

fn empty_coverage(complete: bool) -> Coverage {
    Coverage {
        discovered_files: 0,
        indexed_files: 0,
        partial_files: 0,
        deferred_files: 0,
        failed_files: 0,
        discovery_complete: complete,
        stale_files: 0,
        resolved_references: 0,
        name_only_references: 0,
        watched_directories: 0,
        unwatched_directories: 0,
        watch_discovery_complete: false,
        watch_stats_started: None,
        watch_activation_attempts: 0,
        watch_limited_activations: 0,
        history_unavailable: None,
        reasons: Vec::new(),
    }
}

#[test]
#[ignore = "invoked only as the owned crash-test child"]
fn final_flush_probe_child() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let base = PathBuf::from(std::env::var_os(PROBE_ROOT).ok_or("probe root missing")?);
    let request = request(&base, 25)?;
    let source = request.source()?;
    let cache = NativeAtlasCache::create(&request.home.to_local()?, source.scope.clone())?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: source.scope.clone(),
            epoch: request.epoch,
        },
        extractor_version: atlas_cold::EXTRACTOR.into(),
        ignore_digest: ContentHash([0; 32]),
        coverage: empty_coverage(false),
        state: IndexState::VerificationNeeded {
            reason: CoverageReason::StaleSnapshot,
        },
    };
    let mut db = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::ColdWriter,
        &SqlProfile::contained_cold(),
        end(),
    )?;
    let mode = |db: &mut CacheConnection<'_>| {
        db.read(end(), |sql| {
            sql.prepare("PRAGMA synchronous")?
                .query_row([], |row| row.get::<_, i64>(0))
                .map_err(sql_error)
        })
    };
    assert_eq!(
        mode(&mut db)?,
        0,
        "cold construction must use its private setting"
    );
    db.prepare_cold_publication()?;
    assert_eq!(
        mode(&mut db)?,
        2,
        "the final write requires FULL synchronization"
    );
    let coverage = serde_json::to_string(&empty_coverage(true))?;
    let state = serde_json::to_string(&IndexState::Current)?;
    db.write(65536, end(), |sql| {
        sql.prepare("INSERT INTO names(text) VALUES(?1)")?
            .execute([MARKER])
            .map_err(sql_error)?;
        sql.prepare(
            "UPDATE meta SET coverage_json=?1,state_json=?2,discovery_complete=1 WHERE singleton=1",
        )?
        .execute((&coverage, &state))
        .map_err(sql_error)?;
        Ok(())
    })?;
    db.finish_cold_publication(end())?;
    pointer::publish(&cache, &mut db, None, end())?;
    fs::write(base.join("flushed-ready"), b"database handle is still open")?;
    // The coordinator kills this exact process with the database still open.
    // A normal close would supply an implicit checkpoint and mask the control.
    loop {
        std::hint::black_box(&db);
        std::thread::park_timeout(Duration::from_secs(1));
    }
}

fn abort_after_publication(base: &Path) -> Check {
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "final_flush_probe_child",
            "--nocapture",
        ])
        .env(PROBE_ROOT, base)
        .spawn()?;
    let deadline = end();
    while !base.join("flushed-ready").is_file() {
        if let Some(status) = child.try_wait()? {
            return Err(format!("flush child exited before its witness: {status}").into());
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("flush child never reached its durable publication".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        child.try_wait()?.is_none(),
        "probe returned before the crash"
    );
    child.kill()?;
    assert!(
        !child.wait()?.success(),
        "the abrupt process end reported success"
    );
    Ok(())
}

#[test]
fn final_flush_survives_process_crash_without_a_close_checkpoint_or_wal_replay() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let base = directory::private_case_directory()?;
    fs::create_dir(base.join("source"))?;
    abort_after_publication(&base)?;

    let request = request(&base, 25)?;
    let source = request.source()?;
    let cache = NativeAtlasCache::open(&request.home.to_local()?, source.scope.clone())?
        .ok_or("cache missing after crash")?;
    let pointer = pointer::decode(
        &cache.read_pointer()?.ok_or("published pointer missing")?,
        &source.scope,
    )?;
    assert_eq!(pointer.epoch, request.epoch);
    let pin = cache
        .pin_database(&pointer.epoch)?
        .ok_or("published main database missing")?;
    let replica = base.join("standalone");
    fs::create_dir(&replica)?;
    let standalone = replica.join("atlas.db");
    fs::copy(&pin.path, &standalone)?;
    let db = rusqlite::Connection::open_with_flags(
        &standalone,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let integrity: String = db.query_row("PRAGMA integrity_check(1)", [], |row| row.get(0))?;
    assert_eq!(integrity, "ok");
    let finished: (i64, i64) = db.query_row(
        "SELECT discovery_complete,(SELECT count(*) FROM names WHERE text=?1) FROM meta WHERE singleton=1",
        [MARKER], |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(
        finished,
        (1, 1),
        "final transaction was not in the main database at crash"
    );
    drop(db);
    drop(pin);
    drop(cache);
    base.finish(Ok(()))
}
