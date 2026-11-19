//! A native overflow waits behind a controlled delay before writer admission.
#![cfg(all(windows, feature = "atlas-drain-probe"))]
#[path = "../../test-support/directory.rs"]
mod directory;

use se_atlas::{
    cache::{CacheIdentity, CacheSeed, connection::*, pointer},
    controller::Controller,
    errors::AtlasResult,
    lifecycle::*,
    model::*,
};
use se_host::{
    NativeAtlasQualification,
    atlas_cache::NativeAtlasCache,
    atlas_renewal::{NativeRenewal, drive_owner_events, drive_quantum},
    atlas_runtime::{NativeController, NativeRuntime},
    atlas_source::NativeAtlasSource,
};
use se_types::{ProjectId, SeError};
use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

type Native = NativeController<NativeRenewal>;
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn policy() -> AtlasPolicy {
    AtlasPolicy {
        enabled: true,
        max_files: 16,
        max_change_rows: 128,
        change_retention_days: 7,
        max_cache_bytes: 32_000_000,
        total_reserved_bytes: ANONYMOUS_BYTES,
        parse: ParseBudget {
            max_source_bytes: 16_384,
            max_rows: 512,
            max_work: Duration::from_millis(150),
            reserved_bytes: PARSER_BYTES,
        },
        ignore: IgnorePolicy {
            global_patterns: vec!["generated/".into()],
            generated_prefixes: Vec::new(),
            digest: ContentHash([1; 32]),
        },
        watch: WatchBudget {
            max_directories: 8,
            max_mapping_bytes: 128,
            observed_os_limit: None,
        },
    }
}

fn seed(home: &Path, registration: &RootRegistration, profile: &SqlProfile) -> Check {
    let source = NativeAtlasSource::open(registration.clone(), CaseMode::InsensitivePreserving)?;
    let cache = NativeAtlasCache::create(home, source.scope.clone())?;
    let coverage = serde_json::from_value(serde_json::json!({
        "discovered_files": 0, "indexed_files": 0, "partial_files": 0, "deferred_files": 0,
        "failed_files": 0, "discovery_complete": false, "stale_files": 0,
        "resolved_references": 0, "name_only_references": 0, "watched_directories": 0,
        "unwatched_directories": 0, "watch_discovery_complete": false,
        "watch_stats_started": null, "watch_activation_attempts": 0,
        "watch_limited_activations": 0, "history_unavailable": null, "reasons": []
    }))?;
    let snapshot = CacheSeed {
        identity: CacheIdentity {
            scope: source.scope.clone(),
            epoch: CacheEpoch::from_parts(1, [3; 10])?,
        },
        extractor_version: se_host::atlas_cold::EXTRACTOR.into(),
        ignore_digest: policy().ignore.digest,
        coverage,
        state: IndexState::VerificationNeeded {
            reason: CoverageReason::StaleSnapshot,
        },
    };
    let end = Instant::now() + Duration::from_secs(5);
    let mut connection =
        CacheConnection::create(&cache, &snapshot, ConnectionRole::HostWriter, profile, end)?;
    pointer::publish(&cache, &mut connection, None, end)?;
    Ok(())
}

fn file_hash(controller: &Native, root: &RootId) -> AtlasResult<Vec<u8>> {
    controller.with_reader(root.clone(), |db, _| {
        db.read(Instant::now() + Duration::from_secs(5), |sql| {
            sql.prepare("SELECT observed_hash FROM files WHERE path='src/value.txt'")?
                .query_row([], |row| row.get(0))
                .map_err(|error| SeError::invalid("overflow witness", &error.to_string()))
        })
    })
}

fn settle(controller: &mut Native, root: &RootId) -> Check<bool> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut reconciled = false;
    while Instant::now() < deadline {
        if let Some(report) = drive_quantum(controller, Duration::from_millis(200))? {
            reconciled |= report.phase == WorkPhase::Discover;
        }
        if matches!(controller.summary(root)?.state, IndexState::Current)
            && controller.next_work() == NextWork::Park
        {
            return Ok(reconciled);
        }
        std::thread::sleep(Duration::from_millis(3));
    }
    Err("overflow judge did not publish current".into())
}

fn judge(home: &Path, source: &Path) -> Check {
    fs::create_dir(source.join("src"))?;
    fs::create_dir(source.join("generated"))?;
    let path = source.join("src/value.txt");
    fs::write(&path, "before native overflow\n")?;
    let project = ProjectId::from_parts(1, [1; 10])?;
    let root = RootId::from_parts(1, [2; 10])?;
    let registration = RootRegistration {
        cache: CacheLocation {
            directory: home.join(project.as_str()).join(root.as_str()),
        },
        project,
        root: root.clone(),
        canonical_source_root: source.to_path_buf(),
        git_metadata: None,
    };
    let profile = NativeAtlasQualification::measured_windows_components()?
        .sql
        .ok_or("native SQL qualification absent")?;
    seed(home, &registration, &profile)?;
    let runtime = NativeRuntime::new(
        home.to_path_buf(),
        std::env::current_exe()?,
        NativeRenewal::new(Vec::new())?,
        Some(profile),
    )?;
    let mut controller = Controller::with_publication_delay(runtime, Duration::from_millis(50));
    controller.register(registration, policy())?;
    controller.activate(root.clone(), ReconcileReason::FirstSession)?;
    assert!(
        settle(&mut controller, &root)?,
        "warm watch must be installed by reconciliation"
    );
    let before = file_hash(&controller, &root)?;
    assert_eq!(before.len(), 32);

    fs::write(&path, "after a real native queue overflow\n")?;
    let suffix = "a".repeat(120);
    for index in 0..384 {
        fs::write(source.join(format!("generated/{index:04}_{suffix}")), [])?;
    }
    controller
        .runtime_mut()
        .driver_mut()
        .probe_wait_overflow(&root)?;
    eprintln!("witnessed native overflow before delaying writer setup");
    fs::write(home.join("atlas-probe-slow-event-setup"), [])?;
    let hints = drive_owner_events(&mut controller, &root)
        .map_err(|error| format!("overflow owner event drain: {error:?}"))?;
    assert!(hints > 0, "the overflow wake silently skipped native work");
    assert!(
        settle(&mut controller, &root)?,
        "native loss requires reconciliation"
    );
    assert_ne!(before, file_hash(&controller, &root)?);
    assert!(matches!(
        controller.close(root, CloseReason::HostDrain, Duration::from_secs(5))?,
        CloseResult::Closed
    ));
    Ok(())
}

#[test]
fn native_overflow_survives_slow_event_setup() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let home = directory::private_case_directory()?;
    let source = directory::private_case_directory()?;
    let result = judge(&home, &source);
    source.finish(home.finish(result))
}
