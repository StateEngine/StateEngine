//! Real process groups distinguish a transient census miss from positive escape.
use super::*;
use std::process::Command;

fn wait_for(path: &std::path::Path) -> Check {
    let until = Instant::now() + Duration::from_secs(10);
    while !path.try_exists()? {
        assert!(
            Instant::now() < until,
            "fixture marker absent: {}",
            path.display()
        );
        std::thread::park_timeout(Duration::from_millis(5));
    }
    Ok(())
}

struct Release(PathBuf, Option<ProcessIdentity>);
impl Drop for Release {
    fn drop(&mut self) {
        if let Err(error) = fs::write(self.0.join("finish"), b"finish owned fixture") {
            eprintln!("owned census fixture release failed: {error}");
        }
        if let Some(root) = &self.1 {
            let until = Instant::now() + Duration::from_secs(12);
            loop {
                match read_process(root.machine.clone(), root.pid) {
                    Ok(ProcessRead::Absent { .. } | ProcessRead::ExitedRecord { .. }) => break,
                    Ok(ProcessRead::Present(live)) if live.identity.start != root.start => break,
                    _ if Instant::now() < until => {
                        std::thread::park_timeout(Duration::from_millis(5))
                    }
                    other => {
                        eprintln!("owned fixture closure unproved: {other:?}");
                        break;
                    }
                }
            }
        }
    }
}

#[test]
fn census_miss_is_recoverable_but_real_escape_remains_unproved() -> Check {
    let home = Home::new()?;
    let library = home.0.join("census-fault.so");
    let compiler = Command::new("cc")
        .args([
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/stop_census_fault.c"
        ))
        .args(["-ldl", "-o"])
        .arg(&library)
        .output()?;
    assert!(
        compiler.status.success(),
        "{}",
        String::from_utf8_lossy(&compiler.stderr)
    );
    let mut failures = Vec::new();
    for mode in ["miss", "exec-miss", "escape"] {
        let result = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "stop_census_review::native_census_observer",
                "--ignored",
                "--nocapture",
            ])
            .env("LD_PRELOAD", &library)
            .env("SE_CENSUS_MODE", mode)
            .env("SE_CENSUS_ARM", home.0.join(format!("{mode}.arm")))
            .env("SE_CENSUS_HIT", home.0.join(format!("{mode}.hit")))
            .output()?;
        println!(
            "{mode}: {}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        if !result.status.success() {
            failures.push(mode);
        }
    }
    println!(
        "native census: {} passed, {} failed",
        3 - failures.len(),
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "native census cases failed: {failures:?}"
    );
    Ok(())
}

#[test]
#[ignore = "standalone native observer with one process-local census fault"]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn native_census_observer() -> Check {
    let mode = std::env::var("SE_CENSUS_MODE")?;
    let home = Home::new()?;
    let machine = MachineId::new("census-review")?;
    let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let host = HostInstanceId(nonce);
    let generation = GenerationId::new(1)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
    let runtime = open_runtime(machine.clone(), host)?;
    let until = Instant::now() + Duration::from_secs(15);
    let prepared = runtime
        .prepare_launch(
            LaunchReservation {
                format_version: 1,
                lifecycle: lifecycle.clone(),
                host,
                owner: current_process_identity(machine.clone()).map_err(error)?,
                generation,
                scope_nonce: nonce,
                parent: ReservationParent::LinuxTracked,
                created_at_unix_ns: 1,
            },
            LaunchSpec {
                executable_custody: None,
                lifecycle,
                generation,
                executable: std::env::current_exe()?,
                arguments: [
                    "--exact",
                    "stop_census_review::native_census_root",
                    "--ignored",
                    "--nocapture",
                ]
                .map(Into::into)
                .into(),
                cwd: home.0.clone(),
                environment: Environment {
                    entries: vec![
                        ("SE_CENSUS_ROOT".into(), home.0.as_os_str().into()),
                        ("SE_CENSUS_MODE".into(), mode.clone().into()),
                    ],
                },
                stdio: empty(),
                mode: LaunchMode::Headless,
                window: None,
                policy: LaunchPolicy {
                    containment: ContainmentRequirement::BestAvailable,
                    writes: WritePolicy::Workspace {
                        roots: vec![home.0.clone()],
                        scratch: home.0.clone(),
                    },
                    network: NetworkPolicy::Allow,
                    hardening: OptionalHardening::Off,
                },
                deadline: until,
                notifications: Arc::new(Notices),
            },
        )
        .map_err(error)?;
    runtime
        .bind_stdio(&prepared.prepared, home.endpoints("census")?)
        .map_err(error)?;
    let process = prepared.process;
    let mut release = Release(home.0.clone(), None);
    let ticket = match runtime.begin_launch(prepared.prepared) {
        LaunchStart::Pending { ticket, .. } => ticket,
        LaunchStart::Failed(failure) => return Err(format!("launch: {:?}", failure.error).into()),
    };
    let record = loop {
        match runtime.poll_launch(&ticket).map_err(error)? {
            LaunchProgress::Started(value) => break value.record,
            LaunchProgress::AwaitingExecCommit(_) => {
                runtime.authorize_exec(&ticket).map_err(error)?
            }
            LaunchProgress::Pending if Instant::now() < until => {
                std::thread::park_timeout(Duration::from_millis(5))
            }
            LaunchProgress::Failed(failure) => {
                return Err(format!("launch: {:?}", failure.error).into());
            }
            _ => return Err("launch exceeded the original bound".into()),
        }
    };
    release.1 = Some(record.root.clone());
    wait_for(&home.0.join("ready"))?;
    let before = runtime.observe(&process).map_err(error)?;
    assert!(
        matches!(before.scope.remaining.extent, EnumerationExtent::Complete),
        "{before:?}"
    );
    let target = if mode == "miss" {
        fs::write(
            std::env::var_os("SE_CENSUS_ARM").ok_or("arm absent")?,
            record.root.pid.0.to_string(),
        )?;
        record.root.pid
    } else {
        let child = ProcessId(fs::read_to_string(home.0.join("child-pid"))?.parse()?);
        assert!(
            before
                .scope
                .remaining
                .known_live
                .iter()
                .any(|p| p.pid == child),
            "child was never retained"
        );
        if mode == "escape" {
            fs::write(home.0.join("escape"), b"escape")?;
            wait_for(&home.0.join("escaped"))?;
            // SAFETY: read-only group query for this exact owned child.
            let group = unsafe { libc::getpgid(child.0 as i32) };
            assert_ne!(group, record.root.pid.0 as i32);
        } else {
            fs::write(
                std::env::var_os("SE_CENSUS_ARM").ok_or("arm absent")?,
                format!("{} {}", child.0, home.0.join("exec").display()),
            )?;
        }
        child
    };
    let during = runtime.observe(&process).map_err(error)?;
    assert!(
        during
            .scope
            .remaining
            .known_live
            .iter()
            .any(|p| p.pid == target),
        "retained live member lost: {during:?}"
    );
    if mode != "escape" {
        assert!(
            PathBuf::from(std::env::var_os("SE_CENSUS_HIT").ok_or("hit absent")?).exists(),
            "fault did not fire"
        );
        // SAFETY: read-only query proves the omitted member never changed groups.
        let group = unsafe { libc::getpgid(target.0 as i32) };
        assert_eq!(group, record.root.pid.0 as i32);
        if mode == "exec-miss" {
            let ProcessRead::Present(live) =
                read_process(machine.clone(), target).map_err(error)?
            else {
                return Err("exec child absent".into());
            };
            assert!(
                live.identity.image.file_name() == Some(std::ffi::OsStr::new("sleep")),
                "exec did not occur: {live:?}"
            );
        }
    }
    let recovered = runtime.observe(&process).map_err(error)?;
    drop(release);
    let closed = loop {
        let observed = runtime.witness_exit(&process).map_err(error)?;
        if matches!(
            observed,
            StopObservation::Complete(_) | StopObservation::Bounded(_)
        ) {
            let root = read_process(machine.clone(), record.root.pid).map_err(error)?;
            assert!(
                !matches!(root, ProcessRead::Present(_)),
                "witness preceded exact root exit"
            );
            break observed;
        }
        assert!(Instant::now() < until, "owned root did not exit");
        std::thread::park_timeout(Duration::from_millis(5));
    };
    if mode != "escape" {
        let StopObservation::Complete(witness) = closed else {
            return Err(format!("one census omission permanently poisoned exact exit: {closed:?}; during={during:?}; recovered={recovered:?}").into());
        };
        runtime.release(&process, &witness).map_err(error)?;
        assert!(
            matches!(
                recovered.scope.remaining.extent,
                EnumerationExtent::Complete
            ),
            "transient omission stayed partial: {recovered:?}"
        );
    } else {
        assert!(
            matches!(
                during.scope.remaining.extent,
                EnumerationExtent::Partial { .. }
            ),
            "positive escape was erased: {during:?}"
        );
        assert!(
            !matches!(closed, StopObservation::Complete(_)),
            "real escape became a complete exit: {closed:?}"
        );
    }
    println!(
        "{mode}: exact root {} exited; native census and retained identity checked",
        record.root.pid.0
    );
    Ok(())
}

#[test]
#[ignore = "owned native root; launches an actual group-escaping child only in escape mode"]
fn native_census_root() -> Check {
    let home = PathBuf::from(std::env::var_os("SE_CENSUS_ROOT").ok_or("root absent")?);
    let child = if std::env::var("SE_CENSUS_MODE")? != "miss" {
        let child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "stop_census_review::native_escape_child",
                "--ignored",
                "--nocapture",
            ])
            .spawn()?;
        fs::write(home.join("child-pid"), child.id().to_string())?;
        wait_for(&home.join("child-ready"))?;
        Some(child)
    } else {
        None
    };
    fs::write(home.join("ready"), b"ready")?;
    wait_for(&home.join("finish"))?;
    if let Some(mut child) = child {
        assert!(child.wait()?.success(), "owned escaped child failed");
    }
    Ok(())
}

#[test]
#[ignore = "owned descendant changes its real kernel group after being retained"]
fn native_escape_child() -> Check {
    let home = PathBuf::from(std::env::var_os("SE_CENSUS_ROOT").ok_or("root absent")?);
    fs::write(home.join("child-ready"), b"ready")?;
    if std::env::var("SE_CENSUS_MODE")? == "exec-miss" {
        use std::os::unix::process::CommandExt;
        wait_for(&home.join("exec"))?;
        return Err(Command::new("/usr/bin/sleep").arg("2").exec().into());
    }
    wait_for(&home.join("escape"))?;
    // SAFETY: changes only this fixture child's own session and process group.
    assert!(unsafe { libc::setsid() } > 0);
    fs::write(home.join("escaped"), b"escaped")?;
    wait_for(&home.join("finish"))?;
    Ok(())
}
