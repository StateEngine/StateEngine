//! Independent native cold-to-current test with a real worker and source watch.
#[cfg(any(target_os = "linux", windows))]
#[path = "../../test-support/directory.rs"]
mod directory;

#[cfg(any(target_os = "linux", windows))]
mod native {
    #[cfg(windows)]
    use futures_util::FutureExt;
    use se_atlas::{controller::Controller, errors::AtlasResult, lifecycle::*, model::*};
    #[cfg(windows)]
    use se_host::atlas_renewal::drive_events;
    #[cfg(windows)]
    use se_host::atlas_runtime::RenewalDriver;
    use se_host::{
        NativeAtlasQualification,
        atlas_renewal::{NativeRenewal, drive_quantum},
        atlas_runtime::{NativeController, NativeRuntime, drive_child},
    };
    use se_types::{ProjectId, SeError};
    use std::{
        fs,
        io::Write,
        path::Path,
        process::Command,
        time::{Duration, Instant},
    };

    type Native = NativeController<NativeRenewal>;
    type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

    const MAIN: &str = "src/main.js";
    const HIDDEN: &str = "src/hidden.js";
    const VISIBLE: &str = "src/visible.js";

    #[derive(Clone, Copy)]
    enum Case {
        Edit,
        Overflow,
        Ignore,
    }

    impl Case {
        fn name(self) -> &'static str {
            match self {
                Self::Edit => "edit",
                Self::Overflow => "overflow",
                Self::Ignore => "ignore",
            }
        }

        fn modify(self, source: &Path) -> Check {
            match self {
                Self::Edit => write_symbol(source, MAIN, "after_edit")?,
                Self::Overflow => {
                    // The bounded native queue must forget the earlier edit.
                    // Ignored churn cannot itself request a source scan.
                    write_symbol(source, MAIN, "after_overflow")?;
                    let suffix = "a".repeat(120);
                    for index in 0..384 {
                        fs::write(source.join(format!("generated/{index:04}_{suffix}")), [])?;
                    }
                }
                Self::Ignore => {
                    persist(&source.join(".gitignore"), b"/src/hidden.js\n")?;
                }
            }
            Ok(())
        }
    }

    fn write_symbol(source: &Path, path: &str, name: &str) -> std::io::Result<()> {
        let text = format!("export function {name}() {{ return 1; }}\n");
        persist(&source.join(path), text.as_bytes())
    }

    fn persist(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let mut file = fs::File::create(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn policy() -> AtlasPolicy {
        AtlasPolicy {
            enabled: true,
            ignore: IgnorePolicy {
                global_patterns: vec!["generated/".into()],
                generated_prefixes: Vec::new(),
                digest: ContentHash([8; 32]),
            },
            watch: WatchBudget {
                max_directories: 32,
                max_mapping_bytes: 512,
                observed_os_limit: None,
            },
            parse: ParseBudget {
                max_source_bytes: 65_536,
                max_rows: 8_192,
                max_work: Duration::from_millis(200),
                reserved_bytes: PARSER_BYTES,
            },
            total_reserved_bytes: ANONYMOUS_BYTES,
            max_files: 32,
            change_retention_days: 7,
            max_change_rows: 1_024,
            max_cache_bytes: 32_000_000,
        }
    }

    fn wait_for_child(controller: &mut Native, ready: impl Fn(&Native) -> Check<bool>) -> Check {
        let end = Instant::now() + Duration::from_secs(60);
        while !ready(controller)? {
            if Instant::now() >= end || controller.runtime().child_pid().is_none() {
                return Err("cold worker exited or timed out before its expected milestone".into());
            }
            controller
                .runtime_mut()
                .wait_child_ready(Instant::now() + Duration::from_millis(20))?;
            drive_child(controller)?;
        }
        Ok(())
    }

    fn names(controller: &Native, root: &RootId, path: &str) -> AtlasResult<Vec<String>> {
        controller.with_reader(root.clone(), |connection, _| {
            connection.read(Instant::now() + Duration::from_secs(3), |sql| {
                let sql_error =
                    |e: rusqlite::Error| SeError::invalid("cold watch witness", &e.to_string());
                let mut statement = sql.prepare(
                    "SELECT names.text FROM files JOIN symbols ON symbols.file=files.id
                     JOIN names ON names.id=symbols.name
                     WHERE files.path=?1 AND symbols.kind='Function' ORDER BY names.text",
                )?;
                let mut rows = statement.query([path]).map_err(sql_error)?;
                let mut found = Vec::new();
                while let Some(row) = rows.next().map_err(sql_error)? {
                    found.push(row.get(0).map_err(sql_error)?);
                }
                Ok(found)
            })
        })
    }

    fn settle(controller: &mut Native, root: &RootId) -> Check<(IndexSummary, bool)> {
        #[cfg(windows)]
        let signal = controller.runtime_mut().driver_mut().signal();
        let end = Instant::now() + Duration::from_secs(60);
        let mut walked = false;
        loop {
            #[cfg(windows)]
            if signal.notified().now_or_never().is_some() || controller.watch_pending(root) {
                drive_events(
                    controller,
                    root,
                    Instant::now() + Duration::from_millis(100),
                )?;
            }
            if let Some(report) = drive_quantum(controller, Duration::from_millis(200))? {
                walked |= report.phase == WorkPhase::Discover;
            }
            let summary = controller.summary(root)?;
            if matches!(
                summary.state,
                IndexState::Current
                    | IndexState::VerificationNeeded {
                        reason: CoverageReason::PartialWatch
                    }
            ) && controller.next_work() == NextWork::Park
            {
                return Ok((summary, walked));
            }
            if Instant::now() >= end || matches!(summary.state, IndexState::Suspended { .. }) {
                return Err(format!("adopted index did not publish current: {summary:?}").into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn check_result(controller: &Native, root: &RootId, case: Case, walked: bool) -> Check {
        let expected = match case {
            Case::Edit => "after_edit",
            Case::Overflow => "after_overflow",
            Case::Ignore => "before_edit",
        };
        let main = names(controller, root, MAIN)?;
        let hidden = names(controller, root, HIDDEN)?;
        let visible = names(controller, root, VISIBLE)?;
        let eligibility = match case {
            Case::Ignore => hidden.is_empty() && visible == ["visible_after"],
            _ => hidden == ["hidden_before"] && visible.is_empty(),
        };
        let expect_walk = cfg!(target_os = "linux") || !matches!(case, Case::Edit);
        if main != [expected] || !eligibility || walked != expect_walk {
            return Err(format!(
                "cold-watch assertion [{}]: first current had main={main:?}, hidden={hidden:?}, visible={visible:?}, reconciliation={walked}",
                case.name()
            ).into());
        }
        Ok(())
    }

    fn run_case(base: &Path, case: Case, drop_event: bool) -> Check {
        let home = base;
        let source = base.join("source");
        fs::create_dir_all(source.join("src"))?;
        fs::create_dir(source.join("generated"))?;
        fs::write(source.join(".gitignore"), "/src/visible.js\n")?;
        write_symbol(&source, MAIN, "before_edit")?;
        write_symbol(&source, HIDDEN, "hidden_before")?;
        write_symbol(&source, VISIBLE, "visible_after")?;
        fs::write(
            home.join("watch-probe"),
            if drop_event { case.name() } else { "" },
        )?;
        let mut controller = native_controller(home)?;
        let root = pause_cold(&mut controller, home, &source, 5, policy())?;
        case.modify(&source)?;
        #[cfg(windows)]
        {
            let event = match case {
                Case::Edit => Some(MAIN),
                Case::Overflow => None,
                Case::Ignore => Some(".gitignore"),
            };
            controller
                .runtime_mut()
                .driver_mut()
                .probe_retained_event(&root, event)?;
        }
        release_cold(&mut controller, home)?;
        #[cfg(windows)]
        eprintln!(
            "cold watch adopted with pending={}, discovery_complete={}",
            controller.watch_pending(&root),
            controller.summary(&root)?.coverage.discovery_complete
        );
        if names(&controller, &root, MAIN)? != ["before_edit"]
            || names(&controller, &root, HIDDEN)? != ["hidden_before"]
            || !names(&controller, &root, VISIBLE)?.is_empty()
        {
            return Err("the cold snapshot did not retain the intended before-state".into());
        }
        let (summary, walked) = settle(&mut controller, &root)?;
        if !matches!(summary.state, IndexState::Current) {
            return Err(format!("event case never reached current: {summary:?}").into());
        }
        #[cfg(windows)]
        if !home
            .join(format!("watch-probe-saw-{}", case.name()))
            .try_exists()?
        {
            return Err(format!(
                "native watch never delivered the {} stimulus after adoption; reconciliation={walked}, current={:?}",
                case.name(), names(&controller, &root, MAIN)?
            ).into());
        }
        let result = check_result(&controller, &root, case, walked);
        close(&mut controller, root)?;
        result?;
        println!(
            "PASS cold-watch {} at first current; reconciliation={walked}",
            case.name()
        );
        Ok(())
    }

    fn native_controller(home: &Path) -> Check<Native> {
        #[cfg(windows)]
        let qualification = NativeAtlasQualification::measured_windows_components()?;
        #[cfg(target_os = "linux")]
        let qualification = NativeAtlasQualification::measured_linux_components()?;
        Ok(Controller::new(NativeRuntime::new(
            home.to_path_buf(),
            std::env::current_exe()?,
            NativeRenewal::new(qualification.parsers)?,
            qualification.sql,
        )?))
    }

    fn pause_cold(
        controller: &mut Native,
        home: &Path,
        source: &Path,
        marker: u8,
        policy: AtlasPolicy,
    ) -> Check<RootId> {
        let project = ProjectId::from_parts(1, [4; 10])?;
        let root = RootId::from_parts(1, [marker; 10])?;
        controller.register(
            RootRegistration {
                cache: CacheLocation {
                    directory: home.join(project.as_str()).join(root.as_str()),
                },
                project,
                root: root.clone(),
                canonical_source_root: source.to_path_buf(),
                git_metadata: None,
            },
            policy,
        )?;
        controller.activate(root.clone(), ReconcileReason::FirstSession)?;
        if let NextWork::AfterEventDebounce(wait) = controller.next_work() {
            std::thread::sleep(wait + Duration::from_millis(1));
        }
        drive_quantum(controller, Duration::from_millis(200))?;
        drive_child(controller)?;
        wait_for_child(controller, |_| {
            Ok(home.join("watch-probe-arrived").try_exists()?)
        })?;
        Ok(root)
    }

    fn release_cold(controller: &mut Native, home: &Path) -> Check {
        fs::write(home.join("watch-probe-release"), [])?;
        wait_for_child(controller, |c| Ok(c.runtime().child_pid().is_none()))
    }

    fn close(controller: &mut Native, root: RootId) -> Check {
        match controller.close(root, CloseReason::HostDrain, Duration::from_secs(5))? {
            CloseResult::Closed => Ok(()),
            other => Err(format!("the native controller did not close: {other:?}").into()),
        }
    }

    #[cfg(windows)]
    fn capacity(home: &Path, drop_limit: bool) -> Check {
        fs::write(
            home.join("watch-probe"),
            if drop_limit { "capacity" } else { "" },
        )?;
        let mut controller = native_controller(home)?;
        let mut constrained = policy();
        constrained.watch.max_directories = 1;
        constrained.watch.max_mapping_bytes = 16;
        let first_source = home.join("first");
        let second_source = home.join("second");
        for source in [&first_source, &second_source] {
            fs::create_dir_all(source.join("src"))?;
            write_symbol(source, MAIN, "capacity_witness")?;
        }
        let first = pause_cold(&mut controller, home, &first_source, 5, constrained.clone())?;
        release_cold(&mut controller, home)?;
        let (summary, _) = settle(&mut controller, &first)?;
        if !matches!(summary.state, IndexState::Current)
            || summary.coverage.watched_directories == 0
        {
            return Err("the first source did not claim the available recursive watch".into());
        }
        fs::remove_file(home.join("watch-probe-arrived"))?;
        fs::remove_file(home.join("watch-probe-release"))?;
        let second = pause_cold(&mut controller, home, &second_source, 6, constrained)?;
        let captured = controller
            .runtime_mut()
            .driver_mut()
            .cold_capture_available(&second);
        release_cold(&mut controller, home)?;
        let (summary, walked) = settle(&mut controller, &second)?;
        let indexed = names(&controller, &second, MAIN)? == ["capacity_witness"];
        close(&mut controller, second)?;
        close(&mut controller, first)?;
        if captured
            || !walked
            || !indexed
            || summary.coverage.watched_directories != 0
            || !matches!(
                summary.state,
                IndexState::VerificationNeeded {
                    reason: CoverageReason::PartialWatch
                }
            )
        {
            return Err(format!(
                "cold-watch assertion [capacity]: second capture={captured}, full reconciliation={walked}, indexed={indexed}, summary={summary:?}"
            ).into());
        }
        println!("PASS cold-watch capacity held across both roots");
        Ok(())
    }

    fn matrix() -> Check {
        let exe = std::env::current_exe()?;
        let cases: &[&str] = if cfg!(windows) {
            &["edit", "overflow", "ignore", "capacity"]
        } else {
            &["edit"]
        };
        let mut failed = Vec::new();
        for case in cases {
            if !Command::new(&exe).arg(case).status()?.success() {
                failed.push((*case, "unmodified implementation"));
                continue;
            }
            if cfg!(windows) {
                let mutant = Command::new(&exe).args([case, "--drop"]).output()?;
                let failure = String::from_utf8_lossy(&mutant.stderr);
                eprint!("{failure}");
                if mutant.status.success()
                    || !failure.contains(&format!("cold-watch assertion [{case}]"))
                {
                    failed.push((*case, "mutant did not fail the intended assertion"));
                    continue;
                }
                println!("PASS cold-watch {case} mutant failed its readiness assertion");
            }
        }
        if failed.is_empty() {
            Ok(())
        } else {
            Err(format!("cold watch cases failed: {failed:?}").into())
        }
    }

    pub fn run() -> Check {
        se_proc::initialize_file_creation_owner()?;
        if std::env::args_os()
            .nth(1)
            .is_some_and(|arg| arg == se_proc::atlas_worker::ENTRY)
        {
            return match se_host::atlas_cold::private_entry()? {
                0 => Ok(()),
                _ => Err("native Atlas child failed".into()),
            };
        }
        let mut args = std::env::args().skip(1).filter(|arg| arg != "--nocapture");
        let selected = args.next();
        if matches!(selected.as_deref(), Some("matrix")) && args.next().is_none() {
            return matrix();
        }
        let drop_event = match (args.next().as_deref(), args.next()) {
            (None, None) => false,
            (Some("--drop"), None) if cfg!(windows) => true,
            _ => return Err("unsupported cold watch probe arguments".into()),
        };
        #[cfg(windows)]
        if selected.as_deref() == Some("capacity") {
            let base = super::directory::private_case_directory()?;
            return base.finish(capacity(&base, drop_event));
        }
        let case = match selected.as_deref() {
            Some("edit") => Case::Edit,
            Some("overflow") if cfg!(windows) => Case::Overflow,
            Some("ignore") if cfg!(windows) => Case::Ignore,
            None => return Ok(()),
            _ => {
                return Err(
                    "usage: atlas_cold_watch_probe edit|overflow|ignore|capacity [--drop]".into(),
                );
            }
        };
        let base = super::directory::private_case_directory()?;
        base.finish(run_case(&base, case, drop_event))
    }
}

#[cfg(any(target_os = "linux", windows))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    native::run()
}

#[cfg(not(any(target_os = "linux", windows)))]
fn main() {}
