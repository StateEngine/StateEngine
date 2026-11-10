//! Native group capacity counts obligations that can still exist, not historical births.
use super::*;
use std::{mem::ManuallyDrop, path::Path, process::Command};

fn wait_for(path: &Path) -> Check {
    let until = Instant::now() + Duration::from_secs(12);
    while !path.try_exists()? {
        assert!(Instant::now() < until, "missing marker: {}", path.display());
        std::thread::park_timeout(Duration::from_millis(5));
    }
    Ok(())
}

struct Finish(PathBuf, Option<ProcessIdentity>);
impl Drop for Finish {
    fn drop(&mut self) {
        if let Err(error) = fs::write(self.0.join("finish"), b"finish owned children") {
            eprintln!("fixture release failed: {error}");
        }
        if let Some(root) = &self.1 {
            let until = Instant::now() + Duration::from_secs(15);
            loop {
                match read_process(root.machine.clone(), root.pid) {
                    Ok(ProcessRead::Absent { .. } | ProcessRead::ExitedRecord { .. }) => break,
                    Ok(ProcessRead::Present(found)) if found.identity.start != root.start => break,
                    _ if Instant::now() < until => {
                        std::thread::park_timeout(Duration::from_millis(5));
                    }
                    observed => {
                        eprintln!("exact fixture root closure unproved: {observed:?}");
                        break;
                    }
                }
            }
        }
    }
}

fn launch(home: &Path) -> Check<(NativeProcessRuntime, OwnedProcess, Finish)> {
    let machine = MachineId::new("tracked-capacity-control")?;
    let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let host = HostInstanceId(nonce);
    let generation = GenerationId::new(1)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
    // The existing real-runtime fixture limits retained members to eight.
    let runtime = open_runtime(machine.clone(), host)?;
    let until = Instant::now() + Duration::from_secs(15);
    let prepared = runtime
        .prepare_launch(
            LaunchReservation {
                format_version: 1,
                lifecycle: lifecycle.clone(),
                host,
                owner: current_process_identity(machine).map_err(error)?,
                generation,
                scope_nonce: nonce,
                parent: ReservationParent::LinuxTracked,
                created_at_unix_ns: 1,
            },
            LaunchSpec {
                lifecycle,
                generation,
                executable: std::env::current_exe()?,
                arguments: [
                    "--exact",
                    "tracked_capacity_review::controlled_root",
                    "--ignored",
                    "--nocapture",
                ]
                .map(Into::into)
                .into(),
                cwd: home.to_owned(),
                environment: Environment {
                    entries: vec![("SE_TRACKED_CONTROL_ROOT".into(), home.as_os_str().into())],
                },
                stdio: empty(),
                mode: LaunchMode::Headless,
                window: None,
                policy: LaunchPolicy {
                    containment: ContainmentRequirement::TrackedTree,
                    writes: WritePolicy::Workspace {
                        roots: vec![home.to_owned()],
                        scratch: home.to_owned(),
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
        .bind_stdio(
            &prepared.prepared,
            StandardIo {
                stdin: Some(File::open("/dev/null")?),
                stdout: Some(File::create(home.join("root.stdout"))?),
                stderr: Some(File::create(home.join("root.stderr"))?),
            },
        )
        .map_err(error)?;
    let process = prepared.process;
    let ticket = match runtime.begin_launch(prepared.prepared) {
        LaunchStart::Pending { ticket, .. } => ticket,
        LaunchStart::Failed(failure) => return Err(format!("launch: {:?}", failure.error).into()),
    };
    let mut release = Finish(home.to_owned(), None);
    loop {
        match runtime.poll_launch(&ticket).map_err(error)? {
            LaunchProgress::Started(value) => {
                release.1 = Some(value.record.root.clone());
                wait_for(&home.join("root-ready"))?;
                return Ok((runtime, process, release));
            }
            LaunchProgress::AwaitingExecCommit(_) => {
                runtime.authorize_exec(&ticket).map_err(error)?
            }
            LaunchProgress::Pending if Instant::now() < until => {
                std::thread::park_timeout(Duration::from_millis(5))
            }
            LaunchProgress::Failed(failure) => {
                return Err(format!("original native launch failed: {:?}", failure.error).into());
            }
            LaunchProgress::Pending => {
                return Err("original native launch exceeded its deadline".into());
            }
        }
    }
}

fn child(home: &Path, index: usize) -> Check<ProcessId> {
    fs::write(
        home.join(format!("spawn-{index}")),
        b"spawn one owned child",
    )?;
    let marker = home.join(format!("ready-{index}"));
    let until = Instant::now() + Duration::from_secs(12);
    loop {
        match fs::read_to_string(&marker)
            .ok()
            .and_then(|text| text.parse::<u32>().ok())
        {
            Some(pid) => return Ok(ProcessId(pid)),
            None if Instant::now() < until => std::thread::park_timeout(Duration::from_millis(5)),
            None => {
                return Err(
                    format!("incomplete or invalid pid marker: {}", marker.display()).into(),
                );
            }
        }
    }
}

fn finish_child(home: &Path, index: usize) -> Check {
    fs::write(
        home.join(format!("release-{index}")),
        b"release exact child",
    )?;
    wait_for(&home.join(format!("joined-{index}")))
}

fn closed(runtime: &NativeProcessRuntime, process: &OwnedProcess) -> Check {
    let until = Instant::now() + Duration::from_secs(12);
    loop {
        if let StopObservation::Complete(witness) = runtime.witness_exit(process).map_err(error)? {
            runtime.release(process, &witness).map_err(error)?;
            return Ok(());
        }
        assert!(
            Instant::now() < until,
            "native exit did not become complete"
        );
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

/// Protects: a long-lived root can supervise more distinct births than its simultaneous capacity.
#[test]
fn reaped_children_do_not_exhaust_a_long_lived_group() -> Check {
    let home = ManuallyDrop::new(Home::new()?);
    println!("retained turnover control: {}", home.0.display());
    let (runtime, process, release) = launch(&home.0)?;
    for index in 0..24 {
        let pid = child(&home.0, index)?;
        let observed = runtime.observe(&process).map_err(error)?;
        assert!(
            observed
                .scope
                .remaining
                .known_live
                .iter()
                .any(|p| p.pid == pid),
            "live child missing: {observed:?}"
        );
        finish_child(&home.0, index)?;
        let observed = runtime.observe(&process).map_err(error)?;
        assert!(
            !observed
                .scope
                .remaining
                .known_live
                .iter()
                .any(|p| p.pid == pid),
            "reaped child remains live: {observed:?}"
        );
    }
    drop(release);
    closed(&runtime, &process)?;
    drop(ManuallyDrop::into_inner(home));
    Ok(())
}

/// Protects: genuine simultaneous capacity refuses explicitly and recovers after exact children exit.
#[test]
fn live_children_still_exhaust_the_configured_group_capacity() -> Check {
    let home = ManuallyDrop::new(Home::new()?);
    println!("retained live-capacity control: {}", home.0.display());
    let (runtime, process, release) = launch(&home.0)?;
    for index in 0..8 {
        child(&home.0, index)?;
    }
    let refusal = match runtime.observe(&process) {
        Err(refusal) => refusal,
        Ok(observed) => {
            return Err(format!("nine live members exceeded the bound: {observed:?}").into());
        }
    };
    assert_eq!(refusal.code, ProcErrorCode::ResourceLimit, "{refusal:?}");
    for index in 0..8 {
        finish_child(&home.0, index)?;
    }
    let recovered = runtime.observe(&process).map_err(error)?;
    assert_eq!(
        recovered.scope.remaining.known_live.len(),
        1,
        "{recovered:?}"
    );
    drop(release);
    closed(&runtime, &process)?;
    drop(ManuallyDrop::into_inner(home));
    Ok(())
}

/// Protects: a live escaped identity is retained when native executable metadata becomes unreadable.
#[test]
fn unreadable_live_escape_cannot_be_pruned_as_departed() -> Check {
    let home = ManuallyDrop::new(Home::new()?);
    println!("retained unreadable control: {}", home.0.display());
    let (runtime, process, release) = launch(&home.0)?;
    let pid = child(&home.0, 0)?;
    assert!(
        runtime
            .observe(&process)
            .map_err(error)?
            .scope
            .remaining
            .known_live
            .iter()
            .any(|p| p.pid == pid)
    );
    fs::write(
        home.0.join("restrict-0"),
        b"make exact live child unreadable",
    )?;
    wait_for(&home.0.join("restricted-0"))?;
    let refusal = match runtime.observe(&process) {
        Err(refusal) => refusal,
        Ok(observed) => {
            return Err(format!("unreadable live escape became absence: {observed:?}").into());
        }
    };
    assert_eq!(
        refusal.code,
        ProcErrorCode::IdentityUnreadable,
        "{refusal:?}"
    );
    fs::write(home.0.join("restore-0"), b"restore exact child readability")?;
    wait_for(&home.0.join("restored-0"))?;
    let restored = runtime.observe(&process).map_err(error)?;
    assert!(
        restored
            .scope
            .remaining
            .known_live
            .iter()
            .any(|p| p.pid == pid),
        "escaped identity was lost: {restored:?}"
    );
    assert!(
        matches!(
            restored.scope.remaining.extent,
            EnumerationExtent::Partial { .. }
        ),
        "escape debt erased: {restored:?}"
    );
    finish_child(&home.0, 0)?;
    drop(release);
    assert!(
        !matches!(
            runtime.witness_exit(&process).map_err(error)?,
            StopObservation::Complete(_)
        ),
        "escape history became an exact closure"
    );
    drop(ManuallyDrop::into_inner(home));
    Ok(())
}

#[test]
#[ignore = "owned group root selected by the native capacity controls"]
fn controlled_root() -> Check {
    let home =
        PathBuf::from(std::env::var_os("SE_TRACKED_CONTROL_ROOT").ok_or("control root absent")?);
    fs::write(home.join("root-ready"), b"root running")?;
    let mut children = Vec::new();
    let until = Instant::now() + Duration::from_secs(45);
    while !home.join("finish").try_exists()? && Instant::now() < until {
        let index = children.len();
        if home.join(format!("spawn-{index}")).try_exists()? {
            let child = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "tracked_capacity_review::controlled_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("SE_TRACKED_CONTROL_ROOT", &home)
                .env("SE_TRACKED_CONTROL_INDEX", index.to_string())
                .spawn()?;
            children.push((child, false));
        }
        for (index, (child, joined)) in children.iter_mut().enumerate() {
            if !*joined && let Some(status) = child.try_wait()? {
                assert!(status.success(), "owned child {index}: {status}");
                *joined = true;
                fs::write(
                    home.join(format!("joined-{index}")),
                    b"native wait complete",
                )?;
            }
        }
        std::thread::park_timeout(Duration::from_millis(5));
    }
    fs::write(home.join("finish"), b"release all exact children")?;
    for (mut child, joined) in children {
        if !joined {
            assert!(child.wait()?.success());
        }
    }
    Ok(())
}

#[test]
#[ignore = "owned descendant selected by the native capacity root"]
fn controlled_child() -> Check {
    let home =
        PathBuf::from(std::env::var_os("SE_TRACKED_CONTROL_ROOT").ok_or("control root absent")?);
    let index = std::env::var("SE_TRACKED_CONTROL_INDEX")?;
    fs::write(
        home.join(format!("ready-{index}")),
        std::process::id().to_string(),
    )?;
    let until = Instant::now() + Duration::from_secs(40);
    let mut restricted = false;
    while !home.join("finish").try_exists()?
        && !home.join(format!("release-{index}")).try_exists()?
        && Instant::now() < until
    {
        if !restricted && home.join(format!("restrict-{index}")).try_exists()? {
            // SAFETY: this owned fixture changes only its own group and native dumpability.
            assert!(unsafe { libc::setsid() } >= 0);
            // SAFETY: only this child changes its own executable metadata visibility.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) }, 0);
            restricted = true;
            fs::write(
                home.join(format!("restricted-{index}")),
                b"live and unreadable",
            )?;
        }
        if restricted && home.join(format!("restore-{index}")).try_exists()? {
            // SAFETY: restore this fixture's original readable executable metadata.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1) }, 0);
            fs::write(home.join(format!("restored-{index}")), b"live and readable")?;
        }
        std::thread::park_timeout(Duration::from_millis(5));
    }
    Ok(())
}
