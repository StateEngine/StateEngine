//! Independent Linux consumer of the public native controller/watch pair.
//! SQL reservation is synthetic for behavior only; native RAM/parser qualification
//! belongs to the separate platform reviewer. No author fixtures are reused.
#![cfg(target_os = "linux")]
use se_atlas::{
    cache::{CacheIdentity, CacheSeed, connection::*, pointer},
    controller::Controller,
    errors::AtlasResult,
    lifecycle::*,
    model::*,
};
use se_host::{
    atlas_cache::NativeAtlasCache,
    atlas_renewal::{NativeRenewal, drive_events, drive_quantum},
    atlas_runtime::{NativeController, NativeRuntime},
    atlas_source::NativeAtlasSource,
};
use se_types::{ProjectId, SeError};
use std::{
    fs::{self, OpenOptions},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[path = "../../test-support/directory.rs"]
mod directory;

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
type Native = NativeController<NativeRenewal>;
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn sql_error(error: impl std::fmt::Display) -> SeError {
    SeError::invalid("independent Atlas readback", &error.to_string())
}
fn profile() -> AtlasResult<SqlProfile> {
    // Behavior-only synthetic reservation, never a measured admission claim.
    SqlProfile::from_qualified_overhead(16_384)
}
fn coverage() -> Coverage {
    Coverage {
        discovered_files: 0,
        indexed_files: 0,
        partial_files: 0,
        deferred_files: 0,
        failed_files: 0,
        discovery_complete: false,
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
fn policy() -> AtlasPolicy {
    AtlasPolicy {
        enabled: true,
        max_files: 128,
        ignore: IgnorePolicy {
            global_patterns: vec!["build/".into()],
            generated_prefixes: Vec::new(),
            digest: ContentHash([7; 32]),
        },
        watch: WatchBudget {
            max_directories: 24,
            max_mapping_bytes: 384,
            observed_os_limit: None,
        },
        parse: ParseBudget {
            max_source_bytes: 65536,
            max_rows: 1024,
            max_work: Duration::from_millis(150),
            reserved_bytes: 262144,
        },
        total_reserved_bytes: 2_000_000,
        change_retention_days: 7,
        max_change_rows: 1000,
        max_cache_bytes: 32_000_000,
    }
}
fn registration(base: &Path, home: &Path, n: u8) -> Check<RootRegistration> {
    let source = base.join(format!("source-{n}"));
    fs::create_dir_all(source.join("src"))?;
    let project = ProjectId::from_parts(1, [1; 10])?;
    let root = RootId::from_parts(1, [n; 10])?;
    Ok(RootRegistration {
        cache: CacheLocation {
            directory: home.join(project.as_str()).join(root.as_str()),
        },
        project,
        root,
        canonical_source_root: source,
        git_metadata: None,
    })
}
fn seed(home: &Path, registration: &RootRegistration, n: u8) -> Check {
    let source = NativeAtlasSource::open(registration.clone(), CaseMode::Sensitive)?;
    let files = NativeAtlasCache::create(home, source.scope.clone())?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: source.scope.clone(),
            epoch: CacheEpoch::from_parts(1, [n; 10])?,
        },
        extractor_version: "independent-renewal-judge".into(),
        ignore_digest: policy().ignore.digest,
        coverage: coverage(),
        state: IndexState::VerificationNeeded {
            reason: CoverageReason::StaleSnapshot,
        },
    };
    let mut connection = CacheConnection::create(
        &files,
        &seed,
        ConnectionRole::HostWriter,
        &profile()?,
        deadline(),
    )?;
    pointer::publish(&files, &mut connection, None, deadline())?;
    Ok(())
}
fn scalar(controller: &Native, root: &RootId, query: &str) -> AtlasResult<i64> {
    controller.with_reader(root.clone(), |connection, _| {
        connection.read(deadline(), |sql| {
            sql.prepare(query)?
                .query_row([], |row| row.get(0))
                .map_err(sql_error)
        })
    })
}
fn hash(controller: &Native, root: &RootId, path: &str) -> AtlasResult<String> {
    controller.with_reader(root.clone(), |connection, _| {
        connection.read(deadline(), |sql| {
            sql.prepare(
                "SELECT coalesce((SELECT hex(observed_hash) FROM files WHERE path=?1),'absent')",
            )?
            .query_row([path], |row| row.get(0))
            .map_err(sql_error)
        })
    })
}
fn pump(
    controller: &mut Native,
    root: &RootId,
    until: impl Fn(&Native) -> AtlasResult<bool>,
) -> Check {
    let limit = Instant::now() + Duration::from_secs(15);
    loop {
        drive_events(controller, root, deadline())
            .map_err(|e| format!("native event dispatch: {e:?}"))?;
        drive_quantum(controller, Duration::from_millis(200)).map_err(|e| {
            format!(
                "native work quantum: {e:?}; next={:?}",
                controller.next_work()
            )
        })?;
        if until(controller).map_err(|e| format!("outside cache readback: {e:?}"))? {
            return Ok(());
        }
        if Instant::now() >= limit {
            return Err(format!("renewal did not finish: {:?}", controller.summary(root)?).into());
        }
        std::thread::park_timeout(Duration::from_millis(5));
    }
}
fn start(controller: &mut Native, registration: &RootRegistration) -> Check {
    controller.register(registration.clone(), policy())?;
    controller.activate(registration.root.clone(), ReconcileReason::ConfigEnabled)?;
    std::thread::park_timeout(Duration::from_millis(20));
    drive_quantum(controller, Duration::from_millis(200)).map_err(|e| {
        format!(
            "first native quantum: {e:?}; next={:?}; summary={:?}",
            controller.next_work(),
            controller.summary(&registration.root)
        )
    })?;
    pump(controller, &registration.root, |c| {
        let summary = c.summary(&registration.root)?;
        Ok(summary.coverage.discovery_complete
            && summary.coverage.watch_discovery_complete
            && summary.coverage.discovered_files > 0)
    })
}
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn native_events_repair_after_writer_contention_and_release_root_slots() -> Check {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let base = std::env::temp_dir().join(format!("se-atlas-native-{}-{nonce}", std::process::id()));
    fs::create_dir(&base)?;
    // Passing and returned-error paths remove the tree. A panic deliberately
    // retains it, and the shared owner prints that exact diagnostic path.
    let base = directory::PrivateDirectory::adopt(base);
    let home = base.join("cache");
    let first = registration(&base, &home, 2)?;
    fs::write(
        first.canonical_source_root.join("src/lib.rs"),
        "pub fn before() {}\n",
    )?;
    fs::create_dir(first.canonical_source_root.join("build"))?;
    fs::write(
        first.canonical_source_root.join("build/ignored.rs"),
        "pub fn ignored() {}\n",
    )?;
    fs::write(
        first.canonical_source_root.join(".env"),
        "SYNTHETIC_PRIVATE_VALUE\n",
    )?;
    fs::write(first.canonical_source_root.join(".gitignore"), "!.env\n")?;
    eprintln!("phase: seed native cache");
    seed(&home, &first, 2).map_err(|e| format!("seed native cache: {e:?}"))?;
    let driver = NativeRenewal::new(Vec::new())?;
    let runtime = NativeRuntime::new(
        home.clone(),
        std::env::current_exe()?,
        driver,
        Some(profile()?),
    )?;
    let mut controller = Controller::new(runtime);
    eprintln!("phase: activate and discover");
    start(&mut controller, &first).map_err(|e| format!("initial activation: {e:?}"))?;
    assert!(
        controller
            .runtime_mut()
            .driver_mut()
            .event_fd(&first.root)
            .is_some()
    );
    assert_eq!(
        scalar(
            &controller,
            &first.root,
            "SELECT count(*) FROM files WHERE path='.env' OR path LIKE 'build/%'"
        )?,
        0
    );
    let original = hash(&controller, &first.root, "src/lib.rs")?;
    assert_ne!(original, "absent");
    assert_eq!(
        original.len(),
        64,
        "a real native source hash must be observed"
    );
    assert_eq!(
        controller.summary(&first.root)?.coverage.indexed_files,
        0,
        "no qualified parser was supplied"
    );
    assert!(controller.summary(&first.root)?.coverage.deferred_files > 0);
    println!("PASS real source discovery, exclusions, native watch and honest semantic deferral");

    // Contention is the actual kernel writer lease, not a mocked SQL exception.
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(home.join("writer.lock"))?;
    lock.lock()?;
    fs::write(
        first.canonical_source_root.join("src/lib.rs"),
        "pub fn after_() {}\n",
    )?;
    let refusal = drive_events(&mut controller, &first.root, deadline());
    assert!(refusal.is_err(), "held native writer lease must refuse");
    assert_ne!(
        controller.next_work(),
        NextWork::Park,
        "failed event dispatch must retain reconciliation"
    );
    assert!(
        matches!(
            controller.summary(&first.root)?.state,
            IndexState::Updating {
                pending_files: 1,
                ..
            }
        ),
        "failed native dispatch must publish pending reconciliation"
    );
    assert_eq!(hash(&controller, &first.root, "src/lib.rs")?, original);
    drop(lock);
    // No new source mutation or manual enqueue follows the consumed/refused wake.
    pump(&mut controller, &first.root, |c| {
        Ok(hash(c, &first.root, "src/lib.rs")? != original)
    })?;
    println!(
        "PASS native writer contention retained reconciliation and recovered without another edit"
    );

    fs::create_dir(first.canonical_source_root.join("nested"))?;
    for n in 0..12 {
        fs::write(
            first
                .canonical_source_root
                .join(format!("nested/file-{n}.rs")),
            format!("pub const N: u8 = {n};\n"),
        )?;
    }
    pump(&mut controller, &first.root, |c| {
        Ok(scalar(
            c,
            &first.root,
            "SELECT count(*) FROM files WHERE path LIKE 'nested/%'",
        )? == 12)
    })?;
    fs::rename(
        first.canonical_source_root.join("nested/file-0.rs"),
        first.canonical_source_root.join("nested/renamed.rs"),
    )?;
    fs::remove_file(first.canonical_source_root.join("nested/file-1.rs"))?;
    pump(&mut controller, &first.root, |c| {
        Ok(hash(c, &first.root, "nested/renamed.rs")? != "absent"
            && hash(c, &first.root, "nested/file-0.rs")? == "absent"
            && hash(c, &first.root, "nested/file-1.rs")? == "absent")
    })?;
    println!("PASS directory burst, rename and removal through native event dispatch");

    // Close is public lifecycle work; it releases native handles and admission.
    assert!(matches!(
        controller.close(
            first.root.clone(),
            CloseReason::HostDrain,
            Duration::from_secs(2)
        )?,
        CloseResult::Closed
    ));
    assert!(
        controller
            .runtime_mut()
            .driver_mut()
            .event_fd(&first.root)
            .is_none()
    );
    assert_eq!(controller.summary(&first.root)?.state, IndexState::Closed);
    let second = registration(&base, &home, 3)?;
    let third = registration(&base, &home, 4)?;
    for (registration, n) in [(&second, 3), (&third, 4)] {
        fs::write(
            registration.canonical_source_root.join("src/main.rs"),
            "fn main() {}\n",
        )?;
        seed(&home, registration, n)?;
        start(&mut controller, registration)?;
    }
    let fourth = registration(&base, &home, 5)?;
    assert!(
        controller.register(fourth.clone(), policy()).is_err(),
        "third active root must refuse"
    );
    for registration in [&second, &third] {
        assert!(matches!(
            controller.close(
                registration.root.clone(),
                CloseReason::HostDrain,
                Duration::from_secs(2)
            )?,
            CloseResult::Closed
        ));
        assert!(
            controller
                .runtime_mut()
                .driver_mut()
                .event_fd(&registration.root)
                .is_none()
        );
    }
    assert_eq!(controller.next_work(), NextWork::Park);
    println!(
        "PASS native close, root-slot recycling, two-active-root cap and final parked controller"
    );
    Ok(())
}
