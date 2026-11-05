//! Native renewal through the production controller.
use super::*;
#[test]
fn real_runtime_renews_watches_reconciles_and_preserves_failed_baselines() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let root = std::env::temp_dir().join(format!(
        "vera-renewal-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&root)?;
    fs::set_permissions(&root, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let repo = root.join("repo");
    fs::create_dir(&repo)?;
    let home = root.join("atlas");
    for dir in ["src", "extra", "ignored", "generated"] {
        fs::create_dir(repo.join(dir))?;
    }
    fs::write(repo.join(".gitignore"), "/ignored/\n*.skip\n!keep.skip\n")?;
    fs::write(repo.join("src/.gitignore"), "hidden.rs\n")?;
    for path in [
        "ignored/no.rs",
        "generated/no.rs",
        "src/hidden.rs",
        "no.global",
        "no.skip",
    ] {
        fs::write(repo.join(path), "fn hidden() {}")?;
    }
    fs::write(repo.join("src/live.rs"), "pub fn retained() { let a=1; }")?;
    fs::write(repo.join("keep.skip"), "ordinary unsupported source")?;
    for n in 0..100 {
        fs::write(
            repo.join(format!("file{n:03}.rs")),
            format!("pub fn item{n}() {{}}"),
        )?;
    }
    for (path, body) in [
        (
            "cycle-a.js",
            "import {b} from './cycle-b.js'; export function a(){return b();}",
        ),
        (
            "cycle-b.js",
            "import {a} from './cycle-a.js'; export function b(){return a();}",
        ),
        ("src/barrel.js", "export {target} from './target.js';"),
        (
            "src/use.js",
            "import {target} from './barrel.js'; export function use(){return target();}",
        ),
    ] {
        fs::write(repo.join(path), body)?;
    }
    let metadata = root.join("git-metadata");
    fs::create_dir(&metadata)?;
    fs::create_dir(metadata.join("refs"))?;
    fs::create_dir(metadata.join("refs/heads"))?;
    fs::create_dir(metadata.join("info"))?;
    fs::write(metadata.join("HEAD"), "ref: refs/heads/main\n")?;
    fs::write(metadata.join("index.lock"), "checkout in flight")?;
    fs::write(
        metadata.join("refs/heads/main"),
        "1111111111111111111111111111111111111111\n",
    )?;
    fs::write(metadata.join("info/exclude"), "extra/excluded.rs\n")?;
    fs::write(repo.join("extra/excluded.rs"), "fn excluded() {}")?;
    let metadata_identity = se_proc::NativeSourceRoot::open(&metadata)?.physical_identity()?;
    fs::create_dir(repo.join("secrets"))?;
    for (path, contents) in [
        (".env", "PRIVATE_CANARY=never_index"),
        ("src/config.js", "export const private_value='never_index';"),
        ("src/credentials.rs", "pub fn private_credentials() {}"),
        ("secrets/inside.rs", "pub fn private_tree() {}"),
        ("client.pem", "never_index"),
    ] {
        fs::write(repo.join(path), contents)?;
    }
    fs::write(
        repo.join(".gitignore"),
        "/ignored/\n*.skip\n!keep.skip\n!.env\n!secrets/\n!secrets/**\n!src/config.js\n",
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
        git_metadata: Some(GitMetadataRegistration {
            physical_git_directory: metadata.clone(),
            physical_common_directory: metadata.clone(),
            git_directory_identity: metadata_identity,
            common_directory_identity: metadata_identity,
        }),
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
    let db = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        deadline(),
    )?;
    pointer::publish(&cache, &db, None, deadline())?;
    drop(db);
    drop(cache);
    let mut controller = Controller::new(runtime(&home)?);
    controller.register(registration.clone(), policy(2)?)?;
    controller.activate(registration.root.clone(), ReconcileReason::FirstSession)?;
    assert!(
        drain(&mut controller)? > 1,
        "root reconciliation lost its finite cursor"
    );
    let summary = controller.runtime().summary(&registration.root)?;
    assert!(summary.coverage.watch_discovery_complete && summary.coverage.discovery_complete);
    assert_eq!(summary.coverage.watched_directories, 2);
    assert!(summary.coverage.unwatched_directories > 0);
    assert!(matches!(
        summary.state,
        IndexState::VerificationNeeded {
            reason: CoverageReason::PartialWatch
        }
    ));
    let paths = controller.with_reader(registration.root.clone(), |db, _| {
        strings(db, "SELECT path FROM files ORDER BY path")
    })?;
    for absent in [
        "ignored/no.rs",
        "generated/no.rs",
        "src/hidden.rs",
        "no.global",
        "no.skip",
        "extra/excluded.rs",
    ] {
        assert!(
            !paths.iter().any(|p| p == absent),
            "ignored source was indexed: {absent}"
        );
    }
    for path in [
        ".env",
        "src/config.js",
        "src/credentials.rs",
        "secrets/inside.rs",
        "client.pem",
    ] {
        assert!(
            !paths.iter().any(|p| p == path),
            "built-in denied path was indexed: {path}"
        );
    }
    println!("PASS built-in private paths stay excluded before reads despite ignore negations");
    assert!(paths.iter().any(|p| p == "src/live.rs") && paths.iter().any(|p| p == "keep.skip"));
    println!(
        "PASS multi-quantum reconciliation, nested/global/generated ignores and honest partial-watch coverage"
    );
    assert_eq!(
        controller.with_reader(registration.root.clone(), |db, _| strings(
            db,
            "SELECT CAST(count(*) AS TEXT) FROM pending_paths"
        ))?,
        ["0"]
    );
    let cycle = controller.with_reader(registration.root.clone(), |db, _| strings(db,
        "SELECT f.path FROM refs r JOIN files f ON f.id=r.file WHERE f.path IN ('cycle-a.js','cycle-b.js') AND r.target IS NOT NULL AND r.accuracy='ExplicitImport' ORDER BY f.path"))?;
    assert_eq!(cycle, ["cycle-a.js", "cycle-b.js"]);
    println!(
        "PASS mutual-import repair converges through the renewal queue without suppressing graph work"
    );
    assert_eq!(
        controller.next_work(),
        NextWork::Park,
        "held checkout lock armed a publication timer"
    );
    fs::remove_file(metadata.join("index.lock"))?;
    se_host::atlas_renewal::drive_events(&mut controller, &registration.root, deadline())?;
    drain(&mut controller)?;
    println!("PASS pre-existing checkout lock parks publication until its native removal event");
    publish(&mut controller)?;
    assert!(matches!(
        controller.runtime().summary(&registration.root)?.state,
        IndexState::VerificationNeeded {
            reason: CoverageReason::PartialWatch
        }
    ));
    let bulk = controller.with_reader(registration.root.clone(), |db, _| {
        strings(db, "SELECT bulk_json FROM changes WHERE kind='Bulk'")
    })?;
    assert_eq!(bulk.len(), 1);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&bulk[0])?["complete"],
        true
    );
    println!("PASS source-armed publication emits one complete Bulk and preserves PartialWatch");
    controller.close(
        registration.root.clone(),
        CloseReason::HostDrain,
        Duration::from_secs(1),
    )?;
    assert!(controller.runtime().event_fd(&registration.root).is_none());
    controller.register(registration.clone(), policy(64)?)?;
    controller.activate(registration.root.clone(), ReconcileReason::FirstSession)?;
    drain(&mut controller)?;
    let summary = controller.runtime().summary(&registration.root)?;
    assert_eq!(summary.coverage.watch_activation_attempts, 2);
    assert_eq!(summary.coverage.unwatched_directories, 0);
    fs::write(
        metadata.join("info/exclude"),
        "extra/excluded.rs\nfile001.rs\n",
    )?;
    let hints = controller
        .runtime_mut()
        .poll_events(&registration.root, deadline())?;
    assert!(hints.iter().any(|h| matches!(
        h,
        SourceHint::Reconcile(ReconcileReason::IgnoreRulesChanged)
    )));
    for hint in hints {
        controller.enqueue(registration.root.clone(), hint)?;
    }
    drain(&mut controller)?;
    assert!(
        controller
            .with_reader(registration.root.clone(), |db, _| strings(
                db,
                "SELECT path FROM files WHERE path='file001.rs'"
            ))?
            .is_empty()
    );
    fs::write(metadata.join("HEAD"), "ref: refs/heads/next\n")?;
    fs::write(
        metadata.join("refs/heads/next"),
        "2222222222222222222222222222222222222222\n",
    )?;
    let hints = controller
        .runtime_mut()
        .poll_events(&registration.root, deadline())?;
    assert!(
        hints
            .iter()
            .any(|h| matches!(h, SourceHint::Reconcile(ReconcileReason::GitHeadChanged)))
    );
    for hint in hints {
        controller.enqueue(registration.root.clone(), hint)?;
    }
    drain(&mut controller)?;
    fs::write(
        metadata.join("objects"),
        "unrelated registered-directory churn",
    )?;
    // Draining known HEAD events may add a reconciliation; objects themselves
    // never supply a hint and no object bytes are read.
    for _ in 0..4 {
        if se_host::atlas_renewal::drive_events(&mut controller, &registration.root, deadline())?
            == 0
        {
            break;
        }
        drain(&mut controller)?;
    }
    fs::write(metadata.join("objects"), "second unrelated write")?;
    assert!(
        controller
            .runtime_mut()
            .poll_events(&registration.root, deadline())?
            .is_empty()
    );
    println!(
        "PASS registered info/exclude and per-worktree HEAD events reconcile; unrelated metadata does not enqueue"
    );
    fs::write(
        repo.join("src/config.js"),
        "export const private_value='second_canary';",
    )?;
    for _ in 0..8 {
        if se_host::atlas_renewal::drive_events(&mut controller, &registration.root, deadline())?
            == 0
        {
            break;
        }
        drain(&mut controller)?;
    }
    fs::write(
        repo.join("src/config.js"),
        "export const private_value='third_canary';",
    )?;
    assert_eq!(
        se_host::atlas_renewal::drive_events(&mut controller, &registration.root, deadline())?,
        0
    );
    controller.enqueue(
        registration.root.clone(),
        SourceHint::FileChanged(RelativePath::new("src/config.js")?),
    )?;
    drain(&mut controller)?;
    assert!(
        controller
            .with_reader(registration.root.clone(), |db, _| strings(
                db,
                "SELECT path FROM files WHERE path='src/config.js'"
            ))?
            .is_empty()
    );
    let watched = controller.with_reader(registration.root.clone(), |db, _| {
        strings(db, "SELECT path FROM watch_directories")
    })?;
    assert!(!watched.iter().any(|p| p == "secrets"));
    println!("PASS denied native churn and direct hints cannot bypass private-path exclusion");
    for body in [
        "export function target(){return 1;}",
        "export function target(value){return value+2;}",
    ] {
        fs::write(repo.join("src/target.js"), body)?;
        controller.enqueue(
            registration.root.clone(),
            SourceHint::FileChanged(RelativePath::new("src/target.js")?),
        )?;
        drain(&mut controller)?;
        let repaired = controller.with_reader(registration.root.clone(), |db, _| strings(db,
            "SELECT target.path FROM refs r JOIN files f ON f.id=r.file JOIN symbols s ON s.id=r.target JOIN files target ON target.id=s.file WHERE f.path='src/use.js' AND r.accuracy='ExplicitImport'"))?;
        assert_eq!(repaired, ["src/target.js"]);
        assert_eq!(
            controller.with_reader(registration.root.clone(), |db, _| strings(
                db,
                "SELECT CAST(count(*) AS TEXT) FROM pending_paths"
            ))?,
            ["0"]
        );
    }
    fs::write(
        repo.join("cycle-a.js"),
        "import {b} from './cycle-b.js'; export function a(){return b()+1;}",
    )?;
    controller.enqueue(
        registration.root.clone(),
        SourceHint::FileChanged(RelativePath::new("cycle-a.js")?),
    )?;
    drain(&mut controller)?;
    assert_eq!(
        controller.with_reader(registration.root.clone(), |db, _| strings(
            db,
            "SELECT CAST(count(*) AS TEXT) FROM pending_paths"
        ))?,
        ["0"]
    );
    assert!(
        controller
            .runtime()
            .summary(&registration.root)?
            .coverage
            .resolved_references
            > 0
    );
    println!(
        "PASS late target creation and changed export repair propagate through unchanged re-export text and cyclic imports settle"
    );
    // The explicit graph hints above leave genuine source events unread. Deliver
    // that known burst before asserting the next isolated file notification.
    for _ in 0..4 {
        if se_host::atlas_renewal::drive_events(&mut controller, &registration.root, deadline())?
            == 0
        {
            break;
        }
        drain(&mut controller)?;
    }
    fs::create_dir(repo.join("src/choice"))?;
    fs::write(
        repo.join("src/choice.js"),
        "export function selected(){return 1;}",
    )?;
    fs::write(
        repo.join("src/choice/index.js"),
        "export function selected(){return 2;}",
    )?;
    fs::write(
        repo.join("src/chooser.js"),
        "import {selected} from './choice'; export function choose(){return selected();}",
    )?;
    controller.enqueue(
        registration.root.clone(),
        SourceHint::Reconcile(ReconcileReason::DirectoryChanged),
    )?;
    drain(&mut controller)?;
    fs::write(
        metadata.join("info/exclude"),
        "extra/excluded.rs\nfile001.rs\nsrc/choice.js\n",
    )?;
    for _ in 0..4 {
        if se_host::atlas_renewal::drive_events(&mut controller, &registration.root, deadline())?
            == 0
        {
            break;
        }
        drain(&mut controller)?;
    }
    let selected = controller.with_reader(registration.root.clone(), |db,_| strings(db,
        "SELECT target.path FROM refs r JOIN files f ON f.id=r.file JOIN symbols s ON s.id=r.target JOIN files target ON target.id=s.file WHERE f.path='src/chooser.js' AND r.accuracy='ExplicitImport'"))?;
    assert_eq!(
        selected,
        ["src/choice/index.js"],
        "ignore removal failed to repair an importer whose ambiguity disappeared"
    );
    println!(
        "PASS ignored candidates retire without a fabricated source removal and repair newly unambiguous imports"
    );
    fs::write(repo.join("src/live.rs"), "pub fn retained() { let a=2; }")?;
    let hints = controller
        .runtime_mut()
        .poll_events(&registration.root, deadline())?;
    assert!(
        hints
            .iter()
            .any(|h| matches!(h,SourceHint::FileChanged(p) if p.as_str()=="src/live.rs"))
    );
    for hint in hints {
        controller.enqueue(registration.root.clone(), hint)?;
    }
    drain(&mut controller)?;
    let hashes = controller.with_reader(registration.root.clone(), |db, _| {
        strings(
            db,
            "SELECT hex(indexed_hash) FROM files WHERE path='src/live.rs'",
        )
    })?;
    assert_eq!(hashes.len(), 1);
    println!(
        "PASS native file event reaches the same scoped writer and renews the semantic baseline"
    );
    fs::create_dir(repo.join("moved"))?;
    fs::write(repo.join("moved/first.rs"), "fn first() {}")?;
    for hint in controller
        .runtime_mut()
        .poll_events(&registration.root, deadline())?
    {
        controller.enqueue(registration.root.clone(), hint)?;
    }
    std::thread::sleep(Duration::from_millis(20));
    let mut subscribed = false;
    for _ in 0..100 {
        let report =
            se_host::atlas_renewal::drive_quantum(&mut controller, Duration::from_millis(200))?
                .ok_or("directory work absent")?;
        let watched = controller.with_reader(registration.root.clone(), |db, _| {
            strings(db, "SELECT path FROM watch_directories")
        })?;
        if watched.iter().any(|p| p == "moved") {
            subscribed = true;
            fs::write(repo.join("moved/raced.rs"), "fn raced() {}")?;
            break;
        }
        assert_ne!(
            report.remaining_known, 0,
            "directory reconciliation completed before subscription"
        );
    }
    assert!(subscribed);
    for hint in controller
        .runtime_mut()
        .poll_events(&registration.root, deadline())?
    {
        controller.enqueue(registration.root.clone(), hint)?;
    }
    if controller.next_work() != NextWork::Park {
        drain(&mut controller)?;
    }
    let paths = controller.with_reader(registration.root.clone(), |db, _| {
        strings(db, "SELECT path FROM files")
    })?;
    assert!(paths.iter().any(|p| p == "moved/raced.rs"));
    println!(
        "PASS subscribe-before-descendant-scan and dirty-event replay retain a moved-in directory edit"
    );
    fs::remove_file(repo.join("src/live.rs"))?;
    std::os::unix::fs::symlink(repo.join("file000.rs"), repo.join("src/live.rs"))?;
    controller.enqueue(
        registration.root.clone(),
        SourceHint::FileChanged(RelativePath::new("src/live.rs")?),
    )?;
    drain(&mut controller)?;
    let stale = controller.with_reader(registration.root.clone(), |db, _| {
        strings(
            db,
            "SELECT coverage_json FROM files WHERE path='src/live.rs'",
        )
    })?;
    assert!(stale[0].contains("Stale"));
    let after = controller.with_reader(registration.root.clone(), |db, _| {
        strings(
            db,
            "SELECT hex(indexed_hash) FROM files WHERE path='src/live.rs'",
        )
    })?;
    assert_eq!(after, hashes);
    fs::remove_file(repo.join("src/live.rs"))?;
    controller.enqueue(
        registration.root.clone(),
        SourceHint::FileRemoved(RelativePath::new("src/live.rs")?),
    )?;
    drain(&mut controller)?;
    assert!(
        controller
            .with_reader(registration.root.clone(), |db, _| strings(
                db,
                "SELECT path FROM files WHERE path='src/live.rs'"
            ))?
            .is_empty()
    );
    println!(
        "PASS no-follow read refusal preserves one stale baseline; confirmed absence alone retires it"
    );
    controller
        .runtime()
        .with_writer(&registration.root, deadline(), |db, _| {
            db.write(65536, deadline(), |sql| {
                sql.prepare("DELETE FROM watch_directories WHERE path=''")?
                    .execute([])
                    .map_err(|e| se_types::SeError::invalid("test SQL", &e.to_string()))?;
                Ok(())
            })
        })?;
    fs::write(repo.join("file000.rs"), "fn source_mapping_recovery() {}")?;
    assert!(
        se_host::atlas_renewal::drive_events(&mut controller, &registration.root, deadline())
            .is_err(),
        "missing mapping silently discarded native events"
    );
    drain(&mut controller)?;
    let watched = controller.with_reader(registration.root.clone(), |db, _| {
        strings(db, "SELECT path FROM watch_directories")
    })?;
    assert!(watched.iter().any(String::is_empty) && watched.iter().any(|p| p == "src"));
    println!(
        "PASS failed mapping lookup preserves a sticky scheduler reconciliation and rebuilds native coverage"
    );
    controller.runtime().with_writer(&registration.root, deadline(), |db, _| db.write(65536, deadline(), |sql| {
        sql.prepare("INSERT INTO pending_paths(path_key,serial) SELECT 'src/use.js',observed_serial FROM meta")?.execute([])
            .map_err(|e| se_types::SeError::invalid("test SQL", &e.to_string()))?;
        Ok(())
    }))?;
    controller.close(
        registration.root.clone(),
        CloseReason::HostDrain,
        Duration::from_secs(1),
    )?;
    assert!(controller.runtime().event_fd(&registration.root).is_none());
    assert_eq!(
        retained(
            &home,
            &registration,
            "SELECT CAST(count(*) AS TEXT) FROM watch_directories"
        )?,
        ["0"]
    );
    assert_eq!(
        retained(
            &home,
            &registration,
            "SELECT CAST(count(*) AS TEXT) FROM renewal_directories"
        )?,
        ["0"]
    );
    assert_eq!(
        retained(
            &home,
            &registration,
            "SELECT CAST(count(*) AS TEXT) FROM active_batch"
        )?,
        ["0"]
    );
    let closed = retained(&home, &registration, "SELECT state_json FROM meta")?;
    assert!(closed[0].contains("StaleSnapshot"));
    let closed_coverage: Coverage = serde_json::from_str(
        &retained(&home, &registration, "SELECT coverage_json FROM meta")?[0],
    )?;
    assert_eq!(closed_coverage.watched_directories, 0);
    assert!(!closed_coverage.watch_discovery_complete);
    let last = retained(
        &home,
        &registration,
        "SELECT bulk_json FROM changes WHERE kind='Bulk' ORDER BY generation DESC LIMIT 1",
    )?;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&last[0])?["complete"],
        false
    );
    println!(
        "PASS qualified close releases native descriptors and SQL mappings and publishes interrupted Bulk"
    );
    assert_eq!(
        retained(&home, &registration, "SELECT path_key FROM pending_paths")?,
        ["src/use.js"]
    );
    drop(controller);
    let mut controller = Controller::new(runtime(&home)?);
    controller.register(registration.clone(), policy(64)?)?;
    controller.activate(registration.root.clone(), ReconcileReason::FirstSession)?;
    drain(&mut controller)?;
    publish(&mut controller)?;
    assert!(matches!(
        controller.runtime().summary(&registration.root)?.state,
        IndexState::Current
    ));
    println!(
        "PASS a fresh runtime reconciles and publishes an existing cache with its prior serial fence"
    );
    // A pointer change outside runtime adoption must refuse the old serial
    // domain. Explicit close/rebind releases its old native directory IDs.
    let mut replacement_seed = seed.clone();
    replacement_seed.identity.epoch = CacheEpoch::from_parts(1, [44; 10])?;
    let cache = NativeAtlasCache::create(&home, source.scope.clone())?;
    let writer = CacheConnection::create(
        &cache,
        &replacement_seed,
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        deadline(),
    )?;
    let expected = cache.read_pointer()?.ok_or("previous pointer absent")?;
    pointer::publish(&cache, &writer, Some(&expected), deadline())?;
    drop(writer);
    drop(cache);
    controller.enqueue(
        registration.root.clone(),
        SourceHint::Reconcile(ReconcileReason::WatchFailure),
    )?;
    let Err(error) = drain(&mut controller) else {
        return Err("unannounced epoch change was accepted".into());
    };
    assert!(error.to_string().contains("cache epoch changed"));
    controller.close(
        registration.root.clone(),
        CloseReason::HostDrain,
        Duration::from_secs(1),
    )?;
    controller.register(registration.clone(), policy(64)?)?;
    controller.activate(registration.root.clone(), ReconcileReason::FirstSession)?;
    drain(&mut controller)?;
    assert_eq!(
        controller
            .runtime()
            .summary(&registration.root)?
            .coverage
            .watch_activation_attempts,
        2
    );
    assert!(
        controller
            .with_reader(registration.root.clone(), |db, _| strings(
                db,
                "SELECT path FROM files WHERE path='src/target.js'"
            ))?
            .contains(&"src/target.js".into())
    );
    println!(
        "PASS an unannounced epoch refuses renewal; close/rebind rebuilds native directory IDs"
    );
    controller.close(
        registration.root.clone(),
        CloseReason::HostDrain,
        Duration::from_secs(1),
    )?;
    for marker in [45, 46] {
        let mut other = registration.clone();
        other.root = RootId::from_parts(1, [marker; 10])?;
        other.cache.directory = home.join(other.project.as_str()).join(other.root.as_str());
        let other_source = NativeAtlasSource::open(other.clone(), CaseMode::Sensitive)?;
        let cache = NativeAtlasCache::create(&home, other_source.scope.clone())?;
        let mut other_seed = seed.clone();
        other_seed.identity.scope = other_source.scope;
        let db = CacheConnection::create(
            &cache,
            &other_seed,
            ConnectionRole::HostWriter,
            &SqlProfile::from_qualified_overhead(1)?,
            deadline(),
        )?;
        pointer::publish(&cache, &db, None, deadline())?;
        drop(db);
        drop(cache);
        controller.register(other.clone(), policy(64)?)?;
        controller.activate(other.root.clone(), ReconcileReason::FirstSession)?;
        drain(&mut controller)?;
        controller.close(other.root, CloseReason::HostDrain, Duration::from_secs(1))?;
    }
    controller.register(registration.clone(), policy(64)?)?;
    controller.activate(registration.root.clone(), ReconcileReason::FirstSession)?;
    drain(&mut controller)?;
    assert_eq!(
        controller
            .runtime()
            .summary(&registration.root)?
            .coverage
            .watch_activation_attempts,
        3
    );
    controller.close(
        registration.root.clone(),
        CloseReason::HostDrain,
        Duration::from_secs(1),
    )?;
    let count = retained(
        &home,
        &registration,
        "SELECT CAST(count(*) AS TEXT) FROM files",
    )?[0]
        .parse::<u32>()?;
    let mut bounded = policy(64)?;
    bounded.max_files = count;
    controller.register(registration.clone(), bounded)?;
    controller.activate(registration.root.clone(), ReconcileReason::FirstSession)?;
    drain(&mut controller)?;
    fs::remove_file(repo.join("file002.rs"))?;
    fs::write(repo.join("replacement.rs"), "pub fn replacement() {}")?;
    controller.enqueue(
        registration.root.clone(),
        SourceHint::Reconcile(ReconcileReason::DirectoryChanged),
    )?;
    drain(&mut controller)?;
    assert_eq!(
        controller.with_reader(registration.root.clone(), |db, _| strings(
            db,
            "SELECT path FROM files WHERE path IN ('file002.rs','replacement.rs')"
        ))?,
        ["replacement.rs"]
    );
    controller.close(
        registration.root.clone(),
        CloseReason::HostDrain,
        Duration::from_secs(1),
    )?;
    println!(
        "PASS confirmed retirements free file admission before bounded replacement enumeration"
    );
    println!(
        "PASS sequential roots reuse bounded native slots and recover same-process activation counts"
    );
    Ok(())
}
