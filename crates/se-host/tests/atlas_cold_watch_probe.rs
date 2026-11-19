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
    use se_host::{
        NativeAtlasQualification,
        atlas_renewal::{NativeRenewal, drive_quantum},
        atlas_runtime::{NativeController, NativeRuntime, drive_child},
    };
    use se_types::{ProjectId, SeError};
    use std::{
        fs,
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
                    fs::write(source.join(".gitignore"), "/src/hidden.js\n")?;
                }
            }
            Ok(())
        }
    }

    fn write_symbol(source: &Path, path: &str, name: &str) -> std::io::Result<()> {
        fs::write(
            source.join(path),
            format!("export function {name}() {{ return 1; }}\n"),
        )
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
                reserved_bytes: 8_000_000,
            },
            total_reserved_bytes: 20_000_000,
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
                     JOIN names ON names.id=symbols.name WHERE files.path=?1 ORDER BY names.text",
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

    fn reach_current(controller: &mut Native, root: &RootId) -> Check<bool> {
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
            if matches!(summary.state, IndexState::Current)
                && controller.next_work() == NextWork::Park
            {
                return Ok(walked);
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
        let home = base.join("atlas");
        let source = base.join("source");
        fs::create_dir(&home)?;
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
        let project = ProjectId::from_parts(1, [4; 10])?;
        let root = RootId::from_parts(1, [5; 10])?;
        let registration = RootRegistration {
            cache: CacheLocation {
                directory: home.join(project.as_str()).join(root.as_str()),
            },
            project,
            root: root.clone(),
            canonical_source_root: source.clone(),
            git_metadata: None,
        };
        #[cfg(windows)]
        let qualification = NativeAtlasQualification::measured_windows_components()?;
        #[cfg(target_os = "linux")]
        let qualification = NativeAtlasQualification::measured_linux_components()?;
        let mut controller = Controller::new(NativeRuntime::new(
            home.clone(),
            std::env::current_exe()?,
            NativeRenewal::new(qualification.parsers)?,
            qualification.sql,
        )?);
        controller.register(registration, policy())?;
        controller.activate(root.clone(), ReconcileReason::FirstSession)?;
        if let NextWork::AfterEventDebounce(wait) = controller.next_work() {
            std::thread::sleep(wait + Duration::from_millis(1));
        }
        drive_quantum(&mut controller, Duration::from_millis(200))?;
        drive_child(&mut controller)?;
        wait_for_child(&mut controller, |_| {
            Ok(home.join("watch-probe-arrived").try_exists()?)
        })?;
        case.modify(&source)?;
        #[cfg(windows)]
        controller
            .runtime_mut()
            .driver_mut()
            .probe_flush_cold_watch(&root)?;
        fs::write(home.join("watch-probe-release"), [])?;
        wait_for_child(&mut controller, |c| Ok(c.runtime().child_pid().is_none()))?;
        if names(&controller, &root, MAIN)? != ["before_edit"]
            || names(&controller, &root, HIDDEN)? != ["hidden_before"]
            || !names(&controller, &root, VISIBLE)?.is_empty()
        {
            return Err("the cold snapshot did not retain the intended before-state".into());
        }
        let walked = reach_current(&mut controller, &root)?;
        #[cfg(windows)]
        if !home
            .join(format!("watch-probe-saw-{}", case.name()))
            .try_exists()?
        {
            return Err(
                format!("native watch never delivered the {} stimulus", case.name()).into(),
            );
        }
        let result = check_result(&controller, &root, case, walked);
        if !matches!(
            controller.close(root, CloseReason::HostDrain, Duration::from_secs(5))?,
            CloseResult::Closed
        ) {
            return Err("the native controller did not close".into());
        }
        result?;
        println!(
            "PASS cold-watch {} at first current; reconciliation={walked}",
            case.name()
        );
        Ok(())
    }

    fn matrix() -> Check {
        let exe = std::env::current_exe()?;
        let cases: &[&str] = if cfg!(windows) {
            &["edit", "overflow", "ignore"]
        } else {
            &["edit"]
        };
        for case in cases {
            if !Command::new(&exe).arg(case).status()?.success() {
                return Err(format!("unmodified cold watch case failed: {case}").into());
            }
            if cfg!(windows) {
                let mutant = Command::new(&exe).args([case, "--drop"]).output()?;
                let failure = String::from_utf8_lossy(&mutant.stderr);
                eprint!("{failure}");
                if mutant.status.success()
                    || !failure.contains(&format!("cold-watch assertion [{case}]"))
                {
                    return Err(format!("mutant did not fail the intended {case} assertion").into());
                }
                println!("PASS cold-watch {case} mutant failed its readiness assertion");
            }
        }
        Ok(())
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
        let mut args = std::env::args().skip(1);
        let case = match args.next().as_deref() {
            Some("matrix") if args.next().is_none() => return matrix(),
            Some("edit") => Case::Edit,
            Some("overflow") if cfg!(windows) => Case::Overflow,
            Some("ignore") if cfg!(windows) => Case::Ignore,
            None => return Ok(()),
            _ => return Err("usage: atlas_cold_watch_probe edit|overflow|ignore [--drop]".into()),
        };
        let drop_event = match (args.next().as_deref(), args.next()) {
            (None, None) => false,
            (Some("--drop"), None) if cfg!(windows) => true,
            _ => return Err("unsupported cold watch probe arguments".into()),
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
