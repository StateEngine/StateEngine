use super::*;
use se_atlas::cache::{connection::*, pointer, *};
use se_host::atlas_cache::NativeAtlasCache;
use std::{hint::black_box, time::Duration};

const OPEN_SAMPLES: usize = 200;
const READ_SAMPLES: usize = 1_000;
const WARMUP: usize = 25;
const META: &str =
    "SELECT published_generation,coverage_json,state_json FROM meta WHERE singleton=1";
const LOOKUP: &str = "SELECT path FROM files WHERE path_key=?1";
const PATH: &str = "src/00500.rs";

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

// SQLite's own process-wide allocation counter, measured only while this
// fixture has no connection or its single warm reader. It excludes allocations
// outside SQLite's general allocator and is not a per-connection hard limit.
fn sqlite_heap(reset_high_water: bool) -> Observed<(i64, i64)> {
    se_atlas::native_diagnostic::sqlite_heap(reset_high_water)
        .map_err(|status| format!("SQLite heap counter returned {status}").into())
}

fn coverage() -> Coverage {
    Coverage {
        discovered_files: 1_000,
        indexed_files: 1_000,
        partial_files: 0,
        deferred_files: 0,
        failed_files: 0,
        discovery_complete: true,
        stale_files: 0,
        resolved_references: 0,
        name_only_references: 0,
        watched_directories: 12,
        unwatched_directories: 0,
        watch_discovery_complete: true,
        watch_stats_started: None,
        watch_activation_attempts: 12,
        watch_limited_activations: 0,
        history_unavailable: None,
        reasons: Vec::new(),
    }
}

pub fn status(fixture: &Fixture) -> Observed<Value> {
    let registration = &fixture.source.scope.registration;
    let project = &registration.project;
    let work = project_work::ProjectWork::new(fixture.directory.join("atlas-catalogue"));
    assert!(work.register(project, vec![registration.clone()])?);
    let summary = IndexSummary {
        project: project.clone(),
        root: registration.root.clone(),
        epoch: Some(CacheEpoch::from_parts(1, [3; 10])?),
        generation: Some(Generation(1)),
        state: IndexState::Current,
        coverage: coverage(),
        memory: None,
    };
    work.publish(registration, summary.clone())?;
    let mut elapsed = Vec::with_capacity(READ_SAMPLES);
    let before = native::load()?;
    for repetition in 0..(WARMUP + READ_SAMPLES) {
        let (view, duration) = timed(|| {
            // Service::status checks for registration, then reader_root re-reads it;
            // the steady resident entry supplies the current summary without SQLite.
            assert_eq!(black_box(work.roots(project)?).len(), 1);
            let mut roots = work.roots(project)?.into_iter();
            let root = roots.next().ok_or("registered catalogue root absent")?;
            assert!(roots.next().is_none());
            assert_eq!(
                root.registration.canonical_source_root,
                registration.canonical_source_root
            );
            Ok(se_core::ops::status::atlas_view(Ok(
                se_types::Read::Present {
                    value: black_box(summary.clone()),
                },
            )))
        })?;
        assert_eq!(view.state, "current");
        assert_eq!(view.summary.as_ref(), Some(&summary));
        if repetition >= WARMUP {
            elapsed.push(duration);
        }
    }
    let after = native::load()?;
    let absent = se_core::ops::status::atlas_view(
        se_host::atlas_runtime::read_port::AtlasOwnerPort::default().status(project, None),
    );
    assert_eq!(absent.state, "unavailable");
    Ok(json!({
        "scope": "steady one-root Atlas publication read and view mapping",
        "catalogue_reads_per_sample": 2,
        "sqlite_connections_per_sample": 0,
        "warmup": WARMUP,
        "read_ns": elapsed,
        "load": [before, after],
    }))
}

fn populate(db: &mut CacheConnection<'_>) -> Observed<()> {
    db.write(1_000_000, deadline(), |sql| {
        let changed = sql.prepare(
            "WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n<1000)
             INSERT INTO files(key,path,path_key,coverage_json,last_code_generation,last_author_generation,baseline_reset)
             SELECT CAST(printf('%016d',n) AS BLOB),printf('src/%05d.rs',n),
                    printf('src/%05d.rs',n),'\"Indexed\"',1,0,0 FROM numbers",
        )?
        .execute([])
        .map_err(|e| se_types::SeError::invalid("native observation", &e.to_string()))?;
        assert_eq!(changed, 1_000);
        Ok(())
    })?;
    Ok(())
}

fn warm_query(connection: &mut CacheConnection<'_>) -> Observed<(String, u64)> {
    timed(|| {
        Ok(connection.read(deadline(), |sql| {
            sql.prepare(LOOKUP)?
                .query_row([PATH], |row| row.get(0))
                .map_err(|e| se_types::SeError::invalid("native observation", &e.to_string()))
        })?)
    })
}

fn warm_meta(connection: &mut CacheConnection<'_>) -> Observed<((i64, String, String), u64)> {
    timed(|| {
        Ok(connection.read(deadline(), |sql| {
            sql.prepare(META)?
                .query_row([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .map_err(|e| se_types::SeError::invalid("native observation", &e.to_string()))
        })?)
    })
}

pub fn observe(fixture: &Fixture) -> Observed<Value> {
    let scope = &fixture.source.scope;
    let cache = NativeAtlasCache::create(&fixture.home, scope.clone())?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: scope.clone(),
            epoch: CacheEpoch::from_parts(1, [3; 10])?,
        },
        extractor_version: se_host::atlas_cold::EXTRACTOR.into(),
        ignore_digest: ContentHash([0; 32]),
        coverage: coverage(),
        state: IndexState::Current,
    };
    // This parameter enables the unqualified test reader. It does not change
    // SQLite limits or imply a Windows memory admission.
    let profile = SqlProfile::from_qualified_overhead(1)?;
    let mut seed_db = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::HostWriter,
        &profile,
        deadline(),
    )?;
    pointer::publish(&cache, &mut seed_db, None, deadline())?;
    drop(seed_db);
    let mut writer =
        pointer::open_checked_writer(&cache, scope, &profile, &seed.identity.epoch, deadline())?
            .ok_or("writer publication absent")?;
    populate(&mut writer.connection)?;
    drop(writer);

    let pin = cache
        .pin_database(&seed.identity.epoch)?
        .ok_or("database absent")?;
    let wal_bytes = cache.wal_bytes(&pin)?;
    assert!(wal_bytes > 0, "the retained WAL control has no frames");
    drop(pin);
    drop(cache);

    let mut adapter = Vec::with_capacity(OPEN_SAMPLES);
    let mut opening = Vec::with_capacity(OPEN_SAMPLES);
    let mut closing = Vec::with_capacity(OPEN_SAMPLES);
    let open_before = native::load()?;
    for repetition in 0..(WARMUP + OPEN_SAMPLES) {
        let (reader, adapter_ns) = timed(|| {
            Ok(NativeAtlasCache::open(&fixture.home, scope.clone())?.ok_or("reader absent")?)
        })?;
        let (current, open_ns) = timed(|| {
            Ok(pointer::open_current(
                &reader,
                scope,
                ConnectionRole::QueryReader,
                &profile,
                deadline(),
            )?
            .ok_or("published epoch absent")?)
        })?;
        assert!(!current.epoch_retired);
        let ((), close_ns) = timed(|| {
            drop(current);
            Ok(())
        })?;
        if repetition >= WARMUP {
            adapter.push(adapter_ns);
            opening.push(open_ns);
            closing.push(close_ns);
        }
    }
    let open_after = native::load()?;

    let reader = NativeAtlasCache::open(&fixture.home, scope.clone())?.ok_or("reader absent")?;
    let private_commit_before_open = native::commit()?;
    let sqlite_before_open = sqlite_heap(true)?.0;
    let mut current = pointer::open_current(
        &reader,
        scope,
        ConnectionRole::QueryReader,
        &profile,
        deadline(),
    )?
    .ok_or("warm reader absent")?;
    let private_commit_after_open = native::commit()?;
    let sqlite_after_open = sqlite_heap(false)?.0;
    let mut queries = Vec::with_capacity(READ_SAMPLES);
    let mut meta_queries = Vec::with_capacity(READ_SAMPLES);
    let read_before = native::load()?;
    for repetition in 0..(WARMUP + READ_SAMPLES) {
        let (path, query_ns) = warm_query(&mut current.connection)?;
        assert_eq!(path, PATH);
        let ((generation, coverage_json, state_json), meta_ns) =
            warm_meta(&mut current.connection)?;
        assert_eq!(generation, 0);
        assert_eq!(
            serde_json::from_str::<Coverage>(&coverage_json)?,
            seed.coverage
        );
        assert_eq!(
            serde_json::from_str::<IndexState>(&state_json)?,
            IndexState::Current
        );
        if repetition >= WARMUP {
            queries.push(query_ns);
            meta_queries.push(meta_ns);
        }
    }
    let read_after = native::load()?;
    let private_commit_after_queries = native::commit()?;
    let (sqlite_after_queries, sqlite_high_water) = sqlite_heap(false)?;
    let pin = reader
        .pin_database(&seed.identity.epoch)?
        .ok_or("database absent for identity timing")?;
    let mut identity_validation = Vec::with_capacity(READ_SAMPLES);
    for repetition in 0..(WARMUP + READ_SAMPLES) {
        let ((), elapsed) = timed(|| Ok(reader.validate_database(&pin)?))?;
        if repetition >= WARMUP {
            identity_validation.push(elapsed);
        }
    }
    drop(pin);
    drop(current);
    let private_commit_after_close = native::commit()?;
    let sqlite_after_close = sqlite_heap(false)?.0;
    Ok(json!({
        "sqlite": rusqlite::version(),
        "files": 1000,
        "retained_wal_bytes": wal_bytes,
        "warmup": WARMUP,
        "sql_total_reservation_bytes": SQL_QUERY_BYTES,
        "per_handle_overhead_limit_bytes": (SQL_QUERY_BYTES - 262_144) / 2,
        "open": {
            "adapter_ns": adapter,
            "pointer_and_connection_ns": opening,
            "connection_close_ns": closing,
            "load": [open_before, open_after],
        },
        "warm": {
            "database_identity_validation_ns": identity_validation,
            "sqlite_general_heap_bytes": {
                "scope": "process-wide SQLite general allocator; fixture has one warm reader; excludes non-SQLite memory",
                "before_open": sqlite_before_open,
                "after_open": sqlite_after_open,
                "after_queries": sqlite_after_queries,
                "high_water": sqlite_high_water,
                "after_close": sqlite_after_close,
            },
            "path_lookup": LOOKUP,
            "path_lookup_ns": queries,
            "meta_lookup": META,
            "meta_lookup_ns": meta_queries,
            "process_private_commit_bytes": {
                "before_open": private_commit_before_open,
                "after_open": private_commit_after_open,
                "after_queries": private_commit_after_queries,
                "after_close": private_commit_after_close,
            },
            "load": [read_before, read_after],
        }
    }))
}
