#![cfg(target_os = "linux")]
//! Native enumeration resumes the exact entry whose SQL was preempted.
//! The authorizer only pauses one prepare; it grants no extra SQL authority.
use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use se_atlas::{
    cache::{connection::*, *},
    lifecycle::*,
    model::*,
    scheduler::Scheduled,
};
use se_host::{
    atlas_cache::NativeAtlasCache, atlas_renewal::NativeRenewal, atlas_source::NativeAtlasSource,
};
use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;
struct PausedCache {
    native: NativeAtlasCache,
    armed: Arc<AtomicBool>,
}
impl CacheFiles for PausedCache {
    fn configure_connection(&self, db: &NativeSqlConnection) -> se_types::Result<()> {
        self.native.configure_connection(db)?;
        let armed = self.armed.clone();
        db.authorizer(Some(move |context: AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Read {
                    table_name: "files",
                    column_name: "key"
                }
            ) && armed.swap(false, Ordering::AcqRel)
            {
                // Like scheduler preemption, this consumes the original
                // allowance after enumeration has consumed the source entry.
                std::thread::sleep(Duration::from_millis(250));
            }
            Authorization::Allow
        }))
        .map_err(|e| se_types::SeError::invalid("native pause authorizer", &e.to_string()))?;
        Ok(())
    }
    fn read_pointer(&self) -> se_types::Result<Option<Vec<u8>>> {
        self.native.read_pointer()
    }
    fn replace_pointer(&self, expected: Option<&[u8]>, bytes: &[u8]) -> se_types::Result<()> {
        self.native.replace_pointer(expected, bytes)
    }
    fn pin_database(&self, epoch: &CacheEpoch) -> se_types::Result<Option<DatabasePin>> {
        self.native.pin_database(epoch)
    }
    fn reserve_database(&self, epoch: &CacheEpoch) -> se_types::Result<DatabasePin> {
        self.native.reserve_database(epoch)
    }
    fn discard_unpublished(&self, pin: &DatabasePin) -> se_types::Result<()> {
        self.native.discard_unpublished(pin)
    }
    fn validate_database(&self, pin: &DatabasePin) -> se_types::Result<()> {
        self.native.validate_database(pin)
    }
    fn wal_bytes(&self, pin: &DatabasePin) -> se_types::Result<u64> {
        self.native.wal_bytes(pin)
    }
    fn reserve_growth(&self, bytes: u64) -> se_types::Result<Box<dyn GrowthReservation + '_>> {
        self.native.reserve_growth(bytes)
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
#[test]
fn expired_directory_entry_is_retried_without_another_source_event() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let base = std::env::temp_dir().join(format!(
        "se-quantum-entry-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&base)?;
    let repo = base.join("source");
    fs::create_dir(&repo)?;
    fs::write(repo.join("last.py"), "def retained_entry(): return 1\n")?;
    let home = base.join("cache");
    let project = se_types::ProjectId::from_parts(1, [51; 10])?;
    let root = RootId::from_parts(1, [52; 10])?;
    let source = NativeAtlasSource::open(
        RootRegistration {
            project: project.clone(),
            root: root.clone(),
            canonical_source_root: repo,
            cache: CacheLocation {
                directory: home.join(project.as_str()).join(root.as_str()),
            },
            git_metadata: None,
        },
        CaseMode::Sensitive,
    )?;
    let policy = AtlasPolicy {
        enabled: true,
        max_files: 16,
        ignore: IgnorePolicy {
            global_patterns: Vec::new(),
            generated_prefixes: Vec::new(),
            digest: ContentHash([0; 32]),
        },
        watch: WatchBudget {
            max_directories: 4,
            max_mapping_bytes: 64,
            observed_os_limit: None,
        },
        parse: ParseBudget {
            max_source_bytes: 1024,
            max_rows: 512,
            max_work: Duration::from_millis(200),
            reserved_bytes: 1_000_000,
        },
        total_reserved_bytes: 2_000_000,
        change_retention_days: 7,
        max_change_rows: 1000,
        max_cache_bytes: 32_000_000,
    };
    let coverage: Coverage = serde_json::from_value(
        serde_json::json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":false,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":false,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
    )?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: source.scope.clone(),
            epoch: CacheEpoch::from_parts(1, [53; 10])?,
        },
        extractor_version: "native-quantum-test".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage,
        state: IndexState::VerificationNeeded {
            reason: CoverageReason::StaleSnapshot,
        },
    };
    let armed = Arc::new(AtomicBool::new(false));
    let cache = PausedCache {
        native: NativeAtlasCache::create(&home, source.scope.clone())?,
        armed: armed.clone(),
    };
    // Synthetic reservation is behavior evidence, never native memory admission.
    let db = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        deadline(),
    )?;
    let work = Scheduled {
        root: root.clone(),
        serial: 1,
        hint: SourceHint::Reconcile(ReconcileReason::FirstSession),
    };
    let mut driver = NativeRenewal::new(Vec::new())?;
    armed.store(true, Ordering::Release);
    let error = driver
        .step(
            &source,
            &db,
            &policy,
            &work,
            Instant::now() + Duration::from_millis(200),
        )
        .err()
        .ok_or("preempted source entry completed")?;
    assert!(
        !armed.load(Ordering::Acquire),
        "native file lookup was not preempted"
    );
    assert!(
        matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)),
        "{error}"
    );
    let mut complete = false;
    for _ in 0..16 {
        if driver
            .step(
                &source,
                &db,
                &policy,
                &work,
                Instant::now() + Duration::from_millis(200),
            )?
            .complete
        {
            complete = true;
            break;
        }
    }
    assert!(complete, "finite retry never completed");
    let paths: Vec<String> = db.read(deadline(), |sql| {
        sql.prepare("SELECT path FROM files ORDER BY path")?
            .query_map([], |row| row.get(0))
            .map_err(|error| {
                se_types::SeError::invalid("native entry readback", &error.to_string())
            })?
            .collect::<Result<_, _>>()
            .map_err(|error| {
                se_types::SeError::invalid("native entry readback", &error.to_string())
            })
    })?;
    assert_eq!(
        paths,
        ["last.py"],
        "consumed source entry was lost after expiry"
    );
    driver.close(&root, Some(&db), deadline())?;
    let published = pointer::publish(&cache, &db, None, deadline())?;
    let pin = cache
        .pin_database(&published.epoch)?
        .ok_or("legacy epoch disappeared")?;
    drop(db);
    let legacy = rusqlite::Connection::open(&pin.path)?;
    legacy.pragma_update(None, "user_version", 3)?;
    drop(legacy);
    let old = CachePointer {
        schema: 3,
        ..published
    };
    let old_bytes = serde_json::to_vec(&old)?;
    let current = cache.read_pointer()?.ok_or("published pointer absent")?;
    cache.replace_pointer(Some(&current), &old_bytes)?;
    drop(cache);
    // Exercise the real owner's admission and request seam: an existing legacy
    // epoch must launch a replacement fenced to those exact old bytes/identity.
    use se_atlas::controller::Runtime;
    let mut owner = se_host::atlas_runtime::NativeRuntime::new(
        home.clone(),
        base.join("unspawned-image"),
        NativeRenewal::new(Vec::new())?,
        Some(SqlProfile::from_qualified_overhead(1)?),
    )?;
    let step = owner.step(&source.scope.registration, &policy, &work, deadline())?;
    assert!(matches!(
        step.summary.state,
        IndexState::ColdIndexing { .. }
    ));
    let request = owner
        .child_request()?
        .ok_or("legacy cache was not scheduled for rebuilding")?;
    assert_eq!(request.expected_epoch.as_ref(), Some(&old.epoch));
    assert!(matches!(request.purpose, WorkerPurpose::ColdIndex));
    assert!(matches!(
        owner.close(&root, CloseReason::HostDrain, deadline())?,
        CloseResult::Closed
    ));
    fs::remove_dir_all(base)?;
    Ok(())
}
