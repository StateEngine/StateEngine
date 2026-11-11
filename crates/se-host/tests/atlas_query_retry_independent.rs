//! Protects: the public Atlas adapter retries one expired read, never errors or writes.
//! Real native SQLite; injected delays model preemption, not memory qualification.
use rusqlite::hooks::{AuthAction, Authorization, TransactionOperation};
use se_atlas::{
    cache::{connection::*, *},
    lifecycle::CaseMode,
    model::*,
    query::{QueryReader, ReaderContext, RecordReader},
};
use se_host::{atlas_cache::NativeAtlasCache, atlas_source::NativeAtlasSource};
use se_types::{Read, code::*};
use std::{
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

// The production SQL writer slot is process-global.
static CASE_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct Fault {
    pauses: AtomicUsize,
    paused_transaction: AtomicBool,
    selects: AtomicUsize,
    writes: AtomicUsize,
    delay_count: AtomicUsize,
    deny: AtomicBool,
    expire_write: AtomicBool,
}
struct ControlledCache {
    native: NativeAtlasCache,
    fault: Arc<Fault>,
}
impl CacheFiles for ControlledCache {
    fn configure_connection(&self, db: &NativeSqlConnection) -> se_types::Result<()> {
        self.native.configure_connection(db)?;
        let fault = self.fault.clone();
        db.authorizer(Some(move |context: rusqlite::hooks::AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Transaction {
                    operation: TransactionOperation::Begin
                }
            ) {
                fault.paused_transaction.store(false, Ordering::SeqCst);
            }
            if matches!(context.action, AuthAction::Select) {
                fault.selects.fetch_add(1, Ordering::SeqCst);
                if fault.deny.load(Ordering::SeqCst) {
                    return Authorization::Deny;
                }
                if !fault.paused_transaction.load(Ordering::SeqCst)
                    && fault
                        .delay_count
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok()
                {
                    fault.paused_transaction.store(true, Ordering::SeqCst);
                    fault.pauses.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
            if matches!(
                context.action,
                AuthAction::Update {
                    table_name: "meta",
                    column_name: "published_generation"
                }
            ) && fault.expire_write.load(Ordering::SeqCst)
            {
                fault.writes.fetch_add(1, Ordering::SeqCst);
            }
            Authorization::Allow
        }))
        .map_err(|e| failure(&e.to_string()))?;
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
        if self.fault.expire_write.load(Ordering::SeqCst) {
            // Native write admission must finish before the injected expiry.
            // Keep it slower than the former 50 ms fixture deadline.
            std::thread::sleep(Duration::from_millis(150));
        }
        self.native.reserve_growth(bytes)
    }
}
struct NoRecords;
fn failure(reason: &str) -> se_types::SeError {
    se_types::SeError::invalid("query retry fixture", reason)
}
impl RecordReader for NoRecords {
    fn read(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> se_types::Result<Read<RecordHit>> {
        Err(failure("unexpected record read"))
    }
    fn literal_read(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: &QueryText,
    ) -> se_types::Result<Read<RecordHit>> {
        Err(failure("unexpected literal record read"))
    }
    fn body(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> se_types::Result<Read<HitBody>> {
        Err(failure("unexpected record body"))
    }
}
// Native fixture creation has no product-latency assertion; query slices remain unchanged.
fn end() -> Instant {
    Instant::now() + Duration::from_secs(60)
}
enum Case {
    Once,
    Twice,
    Denied,
    Write,
}
type Setup = (
    Fixture,
    se_atlas::source::RegisteredSource<NativeAtlasSource>,
    ControlledCache,
    CacheSeed,
);
fn setup(state: IndexState) -> Result<Setup, Box<dyn std::error::Error>> {
    let f = Fixture::new().map_err(|e| format!("store setup: {e}"))?;
    let home = f.home.join("atlas");
    let directory = f.home.join("source");
    fs::create_dir(&directory)?;
    let root = RootId::from_parts(1, [72; 10])?;
    let source = NativeAtlasSource::open(
        RootRegistration {
            project: f.project.clone(),
            root: root.clone(),
            canonical_source_root: directory,
            cache: CacheLocation {
                directory: home.join(f.project.as_str()).join(root.as_str()),
            },
            git_metadata: None,
        },
        CaseMode::Sensitive,
    )?;
    let fault = Arc::new(Fault::default());
    let native = ControlledCache {
        native: NativeAtlasCache::create(&home, source.scope.clone())?,
        fault: fault.clone(),
    };
    let coverage = serde_json::from_value(serde_json::json!({
        "discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,
        "failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":0,
        "name_only_references":0,"watched_directories":0,"unwatched_directories":0,
        "watch_discovery_complete":true,"watch_stats_started":null,"watch_activation_attempts":0,
        "watch_limited_activations":0,"reasons":[]}))?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: source.scope.clone(),
            epoch: CacheEpoch::from_parts(1, [73; 10])?,
        },
        extractor_version: "public-retry-fixture".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage,
        state,
    };
    Ok((f, source, native, seed))
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn exercise(case: Case) -> Check {
    let _case = CASE_LOCK.lock().map_err(|_| "fixture lock poisoned")?;
    let (f, source, native, seed) = setup(IndexState::Current)?;
    let fault = native.fault.clone();
    let cache = CacheConnection::create(
        &native,
        &seed,
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        end(),
    )?;
    fault.selects.store(0, Ordering::SeqCst);
    if matches!(case, Case::Write) {
        fault.expire_write.store(true, Ordering::SeqCst);
        // This is a fixture admission budget, not the public read-slice limit.
        let deadline = Instant::now() + Duration::from_secs(5);
        let error = cache
            .write(1_000_000, deadline, |sql| {
                let changed = sql
                    .prepare("UPDATE meta SET published_generation=published_generation+1")?
                    .execute([])
                    .map_err(|e| failure(&e.to_string()))?;
                assert_eq!(changed, 1, "native UPDATE did not execute");
                // Expire the same write deadline only after real mutation, so
                // generation zero below proves rollback rather than non-admission.
                std::thread::sleep(
                    deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(25),
                );
                Ok(())
            })
            .err()
            .ok_or("expired write unexpectedly completed")?;
        assert!(
            matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)),
            "{error}"
        );
        assert_eq!(
            fault.writes.load(Ordering::SeqCst),
            1,
            "expected exactly one admitted write"
        );
        fault.expire_write.store(false, Ordering::SeqCst);
        let generation: i64 = cache.read(end(), |sql| {
            sql.prepare("SELECT published_generation FROM meta")?
                .query_row([], |row| row.get(0))
                .map_err(|e| failure(&e.to_string()))
        })?;
        assert_eq!(generation, 0, "expired write changed durable generation");
        return Ok(());
    }
    pointer::publish(&native, &cache, None, end())?;
    drop(cache);
    drop(native);
    // The real foreground adapter has no cache-writer lease. Read success
    // must not depend on obtaining write-growth or WAL-accounting authority.
    let read_files = ControlledCache {
        native: NativeAtlasCache::open(&f.home.join("atlas"), source.scope.clone())?
            .ok_or("published read-only cache absent")?,
        fault: fault.clone(),
    };
    let cache = CacheConnection::open(
        &read_files,
        seed.identity,
        ConnectionRole::QueryReader,
        &SqlProfile::from_qualified_overhead(1)?,
        end(),
    )?
    .ok_or("published read-only epoch absent")?;
    fault.selects.store(0, Ordering::SeqCst);
    fault.delay_count.store(
        match case {
            Case::Once => 1,
            Case::Twice => 2,
            _ => 0,
        },
        Ordering::SeqCst,
    );
    fault
        .deny
        .store(matches!(case, Case::Denied), Ordering::SeqCst);
    let reader = QueryReader::new(
        &cache,
        ReaderContext {
            memory: None,
            viewer: AtlasPrincipal::Agent(f.a.clone()),
            records: &NoRecords,
            source: Some(&source),
            hostless: false,
            epoch_retired: false,
            now_unix_ms: Some(1),
            record_feed_current: true,
        },
    );
    let se_core::ops::AnyOp::AtlasFind(input) = se_core::ops::decode_tool(
        "stateengine_atlas_find",
        serde_json::json!({"query":"missing_symbol","kind":"symbol","mode":"exact"}),
    )?
    else {
        return Err("query family mismatch".into());
    };
    let answer = se_host::atlas_queries::execute(&reader, &se_core::ops::AtlasRead::Find(input));
    match case {
        Case::Once => {
            let se_core::ops::AnyOutput::AtlasFind(output) = answer? else {
                return Err("output family mismatch".into());
            };
            assert!(present(output.value.answer.data)?.page.items().is_empty());
            assert_eq!(fault.pauses.load(Ordering::SeqCst), 1);
        }
        Case::Twice => {
            let error = answer.err().ok_or("repeated timeout was hidden")?;
            assert!(
                matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(detail) if detail.op=="Atlas SQL"),
                "{error}"
            );
            assert!(
                matches!(error.body.retry(), se_types::Retry::After(delay) if *delay==Duration::from_secs(1)),
                "repeated deadline has no retry delay: {error}"
            );
            assert_eq!(
                fault.pauses.load(Ordering::SeqCst),
                2,
                "read was retried other than once"
            );
        }
        Case::Denied => {
            let error = answer.err().ok_or("SQL authorization failure was hidden")?;
            assert!(
                !matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)),
                "wrong refusal: {error}"
            );
            assert_eq!(
                fault.selects.load(Ordering::SeqCst),
                1,
                "non-timeout read was replayed"
            );
        }
        Case::Write => panic!("write fixture reached read-only result assertions"),
    }
    Ok(())
}
#[test]
fn one_expired_public_read_gets_one_fresh_slice() -> Check {
    exercise(Case::Once)
}
#[test]
fn repeated_expiry_remains_explicit_with_retry_delay() -> Check {
    exercise(Case::Twice)
}
#[test]
fn non_timeout_failure_is_not_replayed() -> Check {
    exercise(Case::Denied)
}
#[test]
fn accepted_write_timeout_is_not_replayed() -> Check {
    exercise(Case::Write)
}

#[cfg(target_os = "linux")]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn native_quantum(prior_failure: bool) -> Check {
    let _case = CASE_LOCK.lock().map_err(|_| "fixture lock poisoned")?;
    use se_atlas::{controller::Controller, lifecycle::*};
    use se_host::{atlas_renewal::NativeRenewal, atlas_runtime::NativeRuntime};
    let retained_failure = failure("retained source-file failure").body;
    let state = if prior_failure {
        IndexState::Partial {
            error: retained_failure.clone(),
        }
    } else {
        IndexState::Current
    };
    let (_f, source, native, mut seed) = setup(state)?;
    seed.coverage.failed_files = u64::from(prior_failure);
    let registration = source.scope.registration.clone();
    fs::write(
        registration.canonical_source_root.join("pending.py"),
        "def pending_entry(): return 1\n",
    )?;
    let home = registration
        .cache
        .directory
        .parent()
        .ok_or("project directory absent")?
        .parent()
        .ok_or("cache home absent")?
        .to_owned();
    let profile = SqlProfile::from_qualified_overhead(1)?;
    let cache =
        CacheConnection::create(&native, &seed, ConnectionRole::HostWriter, &profile, end())?;
    pointer::publish(&native, &cache, None, end())?;
    drop(cache);
    drop(native);
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
    let mut runtime = NativeRuntime::new(
        home,
        std::env::current_exe()?,
        NativeRenewal::new(Vec::new())?,
        Some(profile),
    )?;
    runtime.prepare_registered(&registration, &policy, end())?;
    let mut controller = Controller::new(runtime);
    controller.register(registration.clone(), policy)?;
    controller.activate(registration.root.clone(), ReconcileReason::FirstSession)?;
    if let NextWork::AfterEventDebounce(wait) = controller.next_work() {
        std::thread::sleep(wait + Duration::from_millis(1));
    }
    assert_eq!(controller.next_work(), NextWork::Ready);
    // Expire before SQLite opens, without changing native SQL or source budgets.
    let report = controller
        .work_quantum(Duration::from_nanos(1))?
        .ok_or("expired work vanished")?;
    if prior_failure {
        assert!(
            matches!(report.state, IndexState::Partial {error} if error == retained_failure),
            "expiry erased the prior file failure"
        );
    } else {
        assert!(
            matches!(
                report.state,
                IndexState::VerificationNeeded {
                    reason: CoverageReason::TimeLimit
                }
            ),
            "expiry claimed current work or hid the time limit"
        );
    }
    assert!(
        controller.work_pending(&registration.root),
        "expiry discarded unfinished work"
    );
    let summary = controller.runtime().summary(&registration.root)?;
    assert_eq!(summary.coverage.failed_files, u64::from(prior_failure));
    assert!(
        summary
            .coverage
            .reasons
            .contains(&CoverageReason::TimeLimit),
        "time limit was hidden"
    );
    assert_eq!(controller.next_work(), NextWork::Ready);
    // Resume that same pending work: no new source event or activation is supplied.
    for _ in 0..32 {
        if !controller.work_pending(&registration.root) {
            break;
        }
        controller
            .work_quantum(Duration::from_millis(500))?
            .ok_or("pending quantum disappeared")?;
    }
    assert!(
        !controller.work_pending(&registration.root),
        "pending work did not finish"
    );
    controller.with_reader(registration.root.clone(), |db, _| {
        let paths: Vec<String> = db.read(end(), |sql| {
            sql.prepare("SELECT path FROM files ORDER BY path")?
                .query_map([], |row| row.get(0))
                .map_err(|e| failure(&e.to_string()))?
                .collect::<Result<_, _>>()
                .map_err(|e| failure(&e.to_string()))
        })?;
        assert_eq!(paths, ["pending.py"], "resumed work lost its source entry");
        Ok(())
    })?;
    assert!(matches!(
        controller.close(
            registration.root,
            CloseReason::HostDrain,
            Duration::from_secs(60)
        )?,
        CloseResult::Closed
    ));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn expired_native_quantum_retains_work_and_prior_file_failure() -> Check {
    native_quantum(true)
}
#[cfg(target_os = "linux")]
#[test]
fn expired_native_quantum_is_incomplete_and_resumes() -> Check {
    native_quantum(false)
}
