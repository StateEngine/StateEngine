//! Development consumer of the production controller/child/pointer path.
//! Run on a real repository; this supplies no incremental RAM qualification.
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use se_atlas::{
        cache::{connection::*, *},
        controller::Step,
        errors::AtlasResult,
        lifecycle::*,
        model::*,
        scheduler::Scheduled,
        source::RegisteredSource,
    };
    use se_host::{
        atlas_cache::NativeAtlasCache,
        atlas_runtime::{NativeController, NativeRuntime, RenewalDriver, drive_child},
        atlas_source::NativeAtlasSource,
    };
    use std::{
        path::PathBuf,
        time::{Duration, Instant},
    };
    struct ColdOnly;
    impl RenewalDriver for ColdOnly {
        fn step(
            &mut self,
            _: &RegisteredSource<NativeAtlasSource>,
            _: &mut CacheConnection<'_>,
            _: &AtlasPolicy,
            _: &Scheduled,
            _: Instant,
        ) -> AtlasResult<Step> {
            Err(se_types::SeError::invalid(
                "development cold consumer",
                "renewal is deliberately not qualified here",
            ))
        }
        fn poll_events(
            &mut self,
            _: &RegisteredSource<NativeAtlasSource>,
            _: &mut CacheConnection<'_>,
            _: &AtlasPolicy,
            _: Instant,
        ) -> AtlasResult<Vec<SourceHint>> {
            Err(se_types::SeError::invalid(
                "development cold consumer",
                "native watches are not installed by this consumer",
            ))
        }
        fn close(
            &mut self,
            _: &RootId,
            _: Option<&mut CacheConnection<'_>>,
            _: Instant,
        ) -> AtlasResult<()> {
            Ok(())
        }
    }
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 4 {
        return Err("usage: atlas_cold_once ABSOLUTE_SE_IMAGE REPOSITORY NEW_ATLAS_HOME".into());
    }
    se_proc::initialize_file_creation_owner()?;
    let image = PathBuf::from(&arguments[1]).canonicalize()?;
    let source = PathBuf::from(&arguments[2]).canonicalize()?;
    let home = PathBuf::from(&arguments[3]);
    let project = se_types::ProjectId::from_parts(1, [42; 10])?;
    let root = RootId::from_parts(1, [43; 10])?;
    let registration = RootRegistration {
        project: project.clone(),
        root: root.clone(),
        canonical_source_root: source,
        cache: CacheLocation {
            directory: home.join(project.as_str()).join(root.as_str()),
        },
        git_metadata: None,
    };
    let policy = AtlasPolicy {
        enabled: true,
        max_files: 100_000,
        parse: ParseBudget {
            max_source_bytes: 524288,
            max_rows: 65536,
            max_work: Duration::from_millis(200),
            reserved_bytes: 1_000_000,
        },
        total_reserved_bytes: 2_000_000,
        change_retention_days: 30,
        max_change_rows: 50_000,
        max_cache_bytes: 512_000_000,
        ignore: IgnorePolicy {
            global_patterns: vec!["target/".into(), "node_modules/".into()],
            generated_prefixes: Vec::new(),
            digest: ContentHash([0; 32]),
        },
        watch: WatchBudget {
            max_directories: 0,
            max_mapping_bytes: 0,
            observed_os_limit: None,
        },
    };
    let mut controller =
        NativeController::new(NativeRuntime::new(home.clone(), image, ColdOnly, None)?);
    controller.register(registration.clone(), policy)?;
    controller.activate(root.clone(), ReconcileReason::FirstSession)?;
    // A real activation event arms this single debounce; no idle work exists.
    if let NextWork::AfterEventDebounce(wait) = controller.next_work() {
        std::thread::sleep(wait);
    }
    controller.work_quantum(Duration::from_millis(200))?;
    drive_child(&mut controller)?;
    eprintln!("cold child pid {:?}", controller.runtime().child_pid());
    let deadline = Instant::now() + Duration::from_secs(900);
    while controller.runtime().child_pid().is_some() {
        if Instant::now() >= deadline {
            return Err("consumer deadline exhausted".into());
        }
        controller
            .runtime_mut()
            .wait_child_ready(Instant::now() + Duration::from_millis(200))?;
        drive_child(&mut controller)?;
    }
    let summary = controller.runtime().summary(&root)?;
    eprintln!("{}", serde_json::to_string(&summary)?);
    if let IndexState::Suspended { reason } = summary.state {
        return Err(se_types::SeError::from(reason).into());
    }
    let source = NativeAtlasSource::open(registration, CaseMode::Sensitive)?;
    let cache =
        NativeAtlasCache::open(&home, source.scope.clone())?.ok_or("cache absent after child")?;
    let mut current = pointer::open_current(
        &cache,
        &source.scope,
        ConnectionRole::ExternalReader,
        &SqlProfile::contained_cold(),
        Instant::now() + Duration::from_secs(5),
    )?
    .ok_or("pointer absent after child")?;
    let epoch = current.connection.identity().epoch.clone();
    let epoch_retired = current.epoch_retired;
    let counts=current.connection.read(Instant::now()+Duration::from_secs(5),|sql| {
        let files:i64=sql.prepare("SELECT count(*) FROM files")?.query_row([],|r|r.get(0)).map_err(|e|se_types::SeError::invalid("consumer SQL",&e.to_string()))?;
        let symbols:i64=sql.prepare("SELECT count(*) FROM symbols")?.query_row([],|r|r.get(0)).map_err(|e|se_types::SeError::invalid("consumer SQL",&e.to_string()))?;
        Ok(serde_json::json!({"files":files,"symbols":symbols,"epoch":epoch,"epoch_retired":epoch_retired}))
    })?;
    println!("{}", serde_json::to_string_pretty(&counts)?);
    if counts["files"].as_i64().unwrap_or(0) == 0 || counts["symbols"].as_i64().unwrap_or(0) == 0 {
        return Err("cold consumer did not produce semantic rows".into());
    }
    drop(current);
    drop(cache);
    controller.close(root, CloseReason::HostDrain, Duration::from_secs(2))?;
    Ok(())
}
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("native cold containment is not implemented on this platform".into())
}
