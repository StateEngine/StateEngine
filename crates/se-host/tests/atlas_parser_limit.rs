#![cfg(target_os = "linux")]
//! Regression from the qualified Linux 1 KiB/512-row parser counterexample.
//! Real source/controller/cache consumer; the synthetic SQL profile proves no memory bound.
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
use se_atlas::{
    cache::{connection::*, *},
    controller::Controller,
    lifecycle::*,
    model::*,
    parse::{ParserPlacement, ParserProfile},
};
use se_host::{
    atlas_cache::NativeAtlasCache, atlas_renewal::NativeRenewal, atlas_runtime::NativeRuntime,
    atlas_source::NativeAtlasSource,
};
use se_types::code::AtlasText;
use std::{
    fs,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn policy(watches: u32) -> se_types::Result<AtlasPolicy> {
    Ok(AtlasPolicy {
        ignore: IgnorePolicy {
            global_patterns: vec!["*.global".into()],
            generated_prefixes: vec![RelativePath::new("generated")?],
            digest: ContentHash([0; 32]),
        },
        watch: WatchBudget {
            max_directories: watches,
            max_mapping_bytes: watches * 16,
            observed_os_limit: None,
        },
        enabled: true,
        max_files: 1000,
        parse: ParseBudget {
            max_source_bytes: 524288,
            max_rows: 512,
            max_work: Duration::from_millis(150),
            reserved_bytes: 1_000_000,
        },
        total_reserved_bytes: 2_000_000,
        change_retention_days: 30,
        max_change_rows: 50_000,
        max_cache_bytes: 512_000_000,
    })
}
fn strings(
    connection: &mut CacheConnection<'_>,
    query: &str,
) -> se_atlas::errors::AtlasResult<Vec<String>> {
    connection.read(deadline(), |sql| {
        let mut statement = sql.prepare(query)?;
        let mut rows = statement
            .query([])
            .map_err(|e| se_types::SeError::invalid("test SQL", &e.to_string()))?;
        let mut out = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| se_types::SeError::invalid("test SQL", &e.to_string()))?
        {
            out.push(
                row.get(0)
                    .map_err(|e| se_types::SeError::invalid("test SQL", &e.to_string()))?,
            );
        }
        Ok(out)
    })
}
fn drain(
    controller: &mut Controller<NativeRuntime<NativeRenewal>>,
) -> Result<u32, Box<dyn std::error::Error>> {
    // This is the source-event-armed debounce, not an idle product timer.
    std::thread::sleep(Duration::from_millis(20));
    let mut steps = 0;
    for _ in 0..1000 {
        match controller.next_work() {
            NextWork::Ready => {
                let _report =
                    se_host::atlas_renewal::drive_quantum(controller, Duration::from_millis(200))?
                        .ok_or("ready work absent")?;
                steps += 1;
            }
            NextWork::AfterEventDebounce(wait) if wait <= Duration::from_millis(20) => {
                std::thread::sleep(wait + Duration::from_millis(1))
            }
            NextWork::AfterEventDebounce(_) | NextWork::Park => {
                return if steps > 0 {
                    Ok(steps)
                } else {
                    Err("pending renewal did not expose executable work".into())
                };
            }
        }
    }
    Err("bounded consumer did not finish".into())
}
fn runtime(
    home: &std::path::Path,
) -> Result<NativeRuntime<NativeRenewal>, Box<dyn std::error::Error>> {
    let profiles = [Language::Rust, Language::JavaScript, Language::Python]
        .into_iter()
        .map(|language| {
            ParserProfile::from_qualified_measurement(
                language,
                ParserPlacement::Incremental,
                1024,
                512,
                678_298,
                256_000,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NativeRuntime::new(
        home.to_owned(),
        std::env::current_exe()?,
        NativeRenewal::new(profiles)?,
        Some(SqlProfile::from_qualified_overhead(1)?),
    )?)
}

#[test]
#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn parser_limit_retains_stale_graph_and_other_files_keep_renewing() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let root = std::env::temp_dir().join(format!(
        "atlas-parser-limit-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&root)?;
    let _root_owner = cleanup_directory::PrivateDirectory::adopt(root.clone());
    fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let repo = root.join("repo");
    fs::create_dir(&repo)?;
    let home = root.join("atlas");
    fs::write(
        repo.join("budget.js"),
        "export function retained_before_limit(){return retained_before_limit;}",
    )?;
    fs::write(
        repo.join("healthy.js"),
        "export function before(){return 1;}",
    )?;
    let registration = RootRegistration {
        project: se_types::ProjectId::from_parts(1, [41; 10])?,
        root: RootId::from_parts(1, [42; 10])?,
        canonical_source_root: repo.clone(),
        cache: CacheLocation {
            directory: home
                .join(se_types::ProjectId::from_parts(1, [41; 10])?.as_str())
                .join(RootId::from_parts(1, [42; 10])?.as_str()),
        },
        git_metadata: None,
    };
    let source = NativeAtlasSource::open(registration.clone(), CaseMode::Sensitive)?;
    let cache = NativeAtlasCache::create(&home, source.scope.clone())?;
    let coverage: Coverage = serde_json::from_value(
        serde_json::json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":false,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":false,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
    )?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: source.scope.clone(),
            epoch: CacheEpoch::from_parts(1, [43; 10])?,
        },
        extractor_version: "development".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage,
        state: IndexState::VerificationNeeded {
            reason: CoverageReason::StaleSnapshot,
        },
    };
    let mut db = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        deadline(),
    )?;
    pointer::publish(&cache, &mut db, None, deadline())?;
    drop(db);
    drop(cache);
    for number in 0..48 {
        fs::write(
            repo.join(format!("quantum-{number:02}.py")),
            format!("def quantum_{number}(): return {number}\n"),
        )?;
    }
    let mut controller = Controller::new(runtime(&home)?);
    controller.register(registration.clone(), policy(2)?)?;
    controller.activate(registration.root.clone(), ReconcileReason::FirstSession)?;
    std::thread::sleep(Duration::from_millis(20));
    let expired = controller
        .work_quantum(Duration::from_nanos(1))?
        .ok_or("expired native work disappeared")?;
    assert!(matches!(
        expired.state,
        IndexState::VerificationNeeded {
            reason: CoverageReason::TimeLimit
        }
    ));
    assert!(expired.remaining_known > 0);
    assert!(controller.work_pending(&registration.root));
    assert_eq!(controller.next_work(), NextWork::Ready);
    assert!(matches!(
        controller.summary(&registration.root)?.state,
        IndexState::VerificationNeeded {
            reason: CoverageReason::TimeLimit
        }
    ));
    // Short native allowances exercise expiry while directory enumeration and
    // SQL aggregation retain progress. The final allowance must recover every
    // consumed directory entry, including the one in flight at expiry.
    for _ in 0..16 {
        if let Err(error) = controller.work_quantum(Duration::from_millis(1)) {
            assert!(
                matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_))
                    || matches!(error.body.detail(), se_types::Detail::AtlasResourceBudget(d)
                    if d.resource == "renewal work deadline")
            );
            assert_eq!(controller.next_work(), NextWork::Ready);
        }
    }
    drain(&mut controller)?;
    let discovered = controller.with_reader(registration.root.clone(), |db, _| {
        strings(
            db,
            "SELECT count(*)||'' FROM files WHERE path LIKE 'quantum-%.py'",
        )
    })?;
    assert_eq!(discovered, ["48"], "expiry lost an enumerated source entry");
    // The same registration can still process a later Python edit without a
    // restart, another activation, or a second source event to recover it.
    fs::write(
        repo.join("resume.py"),
        "def resumed_python():\n    return 42\n",
    )?;
    controller.enqueue(
        registration.root.clone(),
        SourceHint::FileChanged(RelativePath::new("resume.py")?),
    )?;
    std::thread::sleep(Duration::from_millis(20));
    let paused = controller
        .work_quantum(Duration::from_nanos(1))?
        .ok_or("expired Python edit disappeared")?;
    assert!(matches!(
        paused.state,
        IndexState::VerificationNeeded {
            reason: CoverageReason::TimeLimit
        }
    ));
    assert!(paused.remaining_known > 0);
    assert!(controller.work_pending(&registration.root));
    assert_eq!(controller.next_work(), NextWork::Ready);
    drain(&mut controller)?;
    let resumed = controller.with_reader(registration.root.clone(), |db, _| {
        strings(db, "SELECT n.text FROM symbols s JOIN names n ON n.id=s.name WHERE s.file=(SELECT id FROM files WHERE path='resume.py')")
    })?;
    assert!(resumed.iter().any(|name| name == "resumed_python"));
    println!("PASS expired native activation and Python edit resume without another event");
    let read = |controller: &mut Controller<NativeRuntime<NativeRenewal>>, query: &str| {
        controller.with_reader(registration.root.clone(), |db, _| strings(db, query))
    };
    let coverage_sql = "SELECT coverage_json FROM files WHERE path='budget.js'";
    let symbols_sql = "SELECT n.text FROM symbols s JOIN names n ON n.id=s.name WHERE s.file=(SELECT id FROM files WHERE path='budget.js') ORDER BY s.id";
    assert_eq!(read(&mut controller, coverage_sql)?, ["\"Indexed\""]);
    let original_symbols = read(&mut controller, symbols_sql)?;
    assert!(
        original_symbols
            .iter()
            .any(|name| name == "retained_before_limit")
    );
    fs::write(repo.join("budget.js"), "a;".repeat(512))?;
    fs::write(repo.join("fresh.js"), "a;".repeat(512))?;
    for path in ["budget.js", "fresh.js"] {
        controller.enqueue(
            registration.root.clone(),
            SourceHint::FileChanged(RelativePath::new(path)?),
        )?;
    }
    drain(&mut controller)?;
    let observed = read(&mut controller, coverage_sql)?;
    let stale: FileCoverage = serde_json::from_str(&observed[0])?;
    let SourceRead::Bytes(current) =
        source.read(&RelativePath::new("budget.js")?, policy(2)?.parse)?
    else {
        return Err("changed source bytes were unavailable".into());
    };
    let changed_hash = current.content_hash;
    assert!(
        matches!(&stale, FileCoverage::Stale { observed_hash: Some(hash), diagnostic: Some(error), .. } if *hash == changed_hash && matches!(error.detail(), se_types::Detail::AtlasResourceBudget(_))),
        "ROW_LIMIT_LEFT_OLD_FILE_INDEXED: {observed:?}"
    );
    assert_eq!(
        read(&mut controller, symbols_sql)?,
        original_symbols,
        "parser limit erased the last-good graph"
    );
    assert_eq!(
        read(
            &mut controller,
            "SELECT count(*)||'' FROM refs WHERE file=(SELECT id FROM files WHERE path='budget.js') AND (accuracy<>'NameOnly' OR target IS NOT NULL)"
        )?,
        ["0"]
    );
    let fresh = read(
        &mut controller,
        "SELECT coverage_json FROM files WHERE path='fresh.js'",
    )?;
    assert!(
        matches!(serde_json::from_str::<FileCoverage>(&fresh[0])?, FileCoverage::Failed { error } if matches!(error.detail(), se_types::Detail::AtlasResourceBudget(_)))
    );
    let summary = controller.summary(&registration.root)?;
    assert!(!matches!(summary.state, IndexState::Suspended { .. }));
    assert_eq!(
        (summary.coverage.stale_files, summary.coverage.failed_files),
        (1, 1)
    );
    fs::write(
        repo.join("healthy.js"),
        "export function after_limit(){return 2;}",
    )?;
    controller.enqueue(
        registration.root.clone(),
        SourceHint::FileChanged(RelativePath::new("healthy.js")?),
    )?;
    drain(&mut controller)?;
    assert_eq!(
        read(
            &mut controller,
            "SELECT n.text FROM symbols s JOIN names n ON n.id=s.name JOIN files f ON f.id=s.file WHERE f.path='healthy.js' AND n.text='after_limit'"
        )?,
        ["after_limit"]
    );
    fs::write(
        repo.join("budget.js"),
        "export function recovered(){return 3;}",
    )?;
    controller.enqueue(
        registration.root.clone(),
        SourceHint::FileChanged(RelativePath::new("budget.js")?),
    )?;
    drain(&mut controller)?;
    assert_eq!(read(&mut controller, coverage_sql)?, ["\"Indexed\""]);
    let recovered = read(&mut controller, symbols_sql)?;
    assert!(
        recovered.iter().any(|name| name == "recovered")
            && !recovered.iter().any(|name| name == "retained_before_limit")
    );
    // A source above the qualified 1 KiB cap must be hashed with fixed scratch,
    // never retained in the parser's arena or substituted with a stat-only claim.
    fs::write(repo.join("budget.js"), "a;".repeat(1024))?;
    controller.enqueue(
        registration.root.clone(),
        SourceHint::FileChanged(RelativePath::new("budget.js")?),
    )?;
    drain(&mut controller)?;
    let oversized = read(&mut controller, coverage_sql)?;
    assert!(
        matches!(
            serde_json::from_str::<FileCoverage>(&oversized[0])?,
            FileCoverage::Stale {
                reason: CoverageReason::SourceBytesLimit,
                observed_hash: Some(_),
                ..
            }
        ),
        "{oversized:?}"
    );
    assert_eq!(read(&mut controller, symbols_sql)?, recovered);
    let SourceRead::Bytes(oversized_source) =
        source.read(&RelativePath::new("budget.js")?, policy(2)?.parse)?
    else {
        return Err(
            "oversized source must fit the policy while exceeding its parser profile".into(),
        );
    };
    let facts = read(&mut controller, "SELECT payload_json FROM staged_changes")?
        .iter()
        .map(|json| serde_json::from_str::<se_atlas::update::diff::Fact>(json))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(
        facts.iter().any(|fact| fact.path.as_str() == "budget.js"
            && fact.kind == ChangeKind::FileOnly
            && fact.current == Some(oversized_source.content_hash)),
        "hashed semantic deferral lost its file-only change"
    );
    // Recovery is limited to budget expiry. A malformed native pointer still
    // suspends the registration and remains a visible failure.
    let pointer_path = registration.cache.directory.join("current.json");
    let pointer_bytes = fs::read(&pointer_path)?;
    fs::write(&pointer_path, b"{invalid-pointer")?;
    controller.enqueue(
        registration.root.clone(),
        SourceHint::FileChanged(RelativePath::new("healthy.js")?),
    )?;
    std::thread::sleep(Duration::from_millis(20));
    let failure = controller.work_quantum(Duration::from_millis(200));
    fs::write(&pointer_path, pointer_bytes)?;
    assert!(failure.is_err(), "malformed cache pointer was accepted");
    assert!(
        matches!(
            controller.summary(&registration.root)?.state,
            IndexState::Suspended { .. }
        ),
        "non-deadline failure was silently retried"
    );
    println!("PASS malformed native cache remains a visible suspension");
    controller.close(
        registration.root.clone(),
        CloseReason::HostDrain,
        Duration::from_secs(2),
    )?;
    fs::remove_dir_all(root)?;
    Ok(())
}
