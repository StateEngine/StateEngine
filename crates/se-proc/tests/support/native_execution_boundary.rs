//! Independent native Windows coordinator creation, refusal and cleanup.
use super::*;
const MARKER: &str = "QUALIFIED_IMAGE_ORIGINAL";
const REPLACED: &[u8] = b"QUALIFIED_IMAGE_REPLACED";

fn runtime(machine: MachineId, instance: HostInstanceId) -> Check<NativeProcessRuntime> {
    Ok(NativeProcessRuntime::open(HostConfig {
        machine,
        instance,
        helper_executable: std::env::current_exe()?,
        linux_delegation: LinuxDelegation::CurrentScope,
        limits: ResourceLimits {
            max_lifecycles: 1,
            max_diagnostic_members: 4,
            max_observation_bytes: 65536,
            max_stdio_buffer_bytes: 4096,
        },
    })
    .map_err(proc_error)?)
}
fn images(home: &Home) -> Check<(PathBuf, PathBuf)> {
    let image = home.0.join("image.exe");
    let next = home.0.join("incoming.exe");
    fs::copy(std::env::current_exe()?, &image)?;
    let mut bytes = fs::read(&image)?;
    assert_eq!(MARKER.len(), REPLACED.len());
    let mut edits = 0;
    for at in 0..=bytes.len().saturating_sub(MARKER.len()) {
        if &bytes[at..at + MARKER.len()] == MARKER.as_bytes() {
            bytes[at..at + MARKER.len()].copy_from_slice(REPLACED);
            edits += 1;
        }
    }
    assert!(edits > 0, "native fixture marker absent");
    fs::write(&next, bytes)?;
    File::options()
        .write(true)
        .open(&next)?
        .set_times(fs::FileTimes::new().set_modified(fs::metadata(&image)?.modified()?))?;
    assert_eq!(fs::metadata(&next)?.len(), fs::metadata(&image)?.len());
    assert_eq!(
        fs::metadata(&next)?.modified()?,
        fs::metadata(&image)?.modified()?
    );
    Ok((image, next))
}
fn spec(
    home: &Home,
    image: &Path,
    lifecycle: LifecycleId,
    generation: GenerationId,
    custody: NativeExecutableInvocation,
) -> Check<LaunchSpec> {
    Ok(LaunchSpec {
        executable_custody: Some(custody),
        lifecycle,
        generation,
        executable: image.to_owned(),
        arguments: [
            "--exact",
            "native_execution_boundary::coordinator_image_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]
        .map(Into::into)
        .to_vec(),
        cwd: home.0.to_path_buf(),
        environment: Environment {
            entries: vec![(
                "EXECUTION_CONTROL_ROOT".into(),
                home.0.as_os_str().to_owned(),
            )],
        },
        stdio: StandardIo {
            stdin: None,
            stdout: Some(File::create(home.0.join("stdout"))?),
            stderr: Some(File::create(home.0.join("stderr"))?),
        },
        mode: LaunchMode::Headless,
        window: None,
        policy: LaunchPolicy {
            containment: ContainmentRequirement::KernelScope,
            writes: WritePolicy::Workspace {
                roots: vec![home.0.to_path_buf()],
                scratch: home.0.to_path_buf(),
            },
            network: NetworkPolicy::Allow,
            hardening: OptionalHardening::Off,
        },
        deadline: Instant::now() + Duration::from_secs(15),
        notifications: Arc::new(Notices),
    })
}
fn run_case(changed: bool) -> Check {
    let home = Home::new()?;
    let (image, next) = images(&home)?;
    let custody = NativeExecutablePin::open(&image)?
        .ok_or("image absent")?
        .prepare()?;
    let machine = MachineId::new("execution-boundary-control")?;
    let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let host = HostInstanceId(nonce);
    let generation = GenerationId::new(1)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
    let owner = current_process_identity(machine.clone()).map_err(proc_error)?;
    let runtime = runtime(machine, host)?;
    let prepared = runtime
        .prepare_launch(
            LaunchReservation {
                format_version: 1,
                lifecycle: lifecycle.clone(),
                host,
                owner,
                generation,
                scope_nonce: nonce,
                parent: ReservationParent::Windows,
                created_at_unix_ns: 1,
            },
            spec(&home, &image, lifecycle, generation, custody)?,
        )
        .map_err(proc_error)?;
    let mut scope = Scope {
        runtime: &runtime,
        process: prepared.process,
        generation,
        released: false,
    };
    if changed {
        fs::rename(next, &image)?;
    }
    let started = runtime.begin_launch(prepared.prepared);
    if changed {
        let LaunchStart::Failed(failure) = started else {
            return Err("replaced image passed native coordinator creation".into());
        };
        assert_eq!(failure.error.code, ProcErrorCode::InvalidInput);
        assert!(failure.remaining.is_some(), "failed scope custody was lost");
        let witness = scope.wait_exit()?;
        assert!(matches!(witness.root, RootWitness::NoChildCreated));
        assert!(!home.0.join("marker.json").try_exists()?);
    } else {
        let ticket = match started {
            LaunchStart::Pending { ticket, .. } => ticket,
            LaunchStart::Failed(failure) => {
                return Err(format!("ordinary native creation failed: {:?}", failure.error).into());
            }
        };
        observe_child(&ticket, &home, &image, &mut scope)?;
    }
    assert!(
        runtime
            .arena_snapshot()
            .map_err(proc_error)?
            .entries
            .is_empty()
    );
    println!("native Windows creation changed={changed}: witnessed exit and released scope");
    Ok(())
}
#[test]
fn coordinator_keeps_image_custody_through_native_creation() -> Check {
    run_case(false)?;
    run_case(true)
}
#[test]
#[ignore = "Only the exact owned native coordinator fixture launches this child"]
fn coordinator_image_child() -> Check {
    let root =
        PathBuf::from(std::env::var_os("EXECUTION_CONTROL_ROOT").ok_or("child root absent")?);
    let argv0 = std::env::args_os().next().ok_or("argv zero absent")?;
    let marker = serde_json::to_vec(&(MARKER, argv0.to_string_lossy(), std::process::id()))?;
    fs::write(root.join("marker.pending"), marker)?;
    fs::rename(root.join("marker.pending"), root.join("marker.json"))?;
    let until = Instant::now() + Duration::from_secs(12);
    while !root.join("done").try_exists()? {
        if Instant::now() >= until {
            return Err("native coordinator did not release fixture".into());
        }
        std::thread::park_timeout(Duration::from_millis(5));
    }
    Ok(())
}

fn observe_child(ticket: &LaunchTicket, home: &Home, image: &Path, scope: &mut Scope<'_>) -> Check {
    let until = Instant::now() + Duration::from_secs(15);
    let record = loop {
        match scope.runtime.poll_launch(ticket).map_err(proc_error)? {
            LaunchProgress::Started(success) => break success.record,
            LaunchProgress::Pending if Instant::now() < until => {
                std::thread::park_timeout(Duration::from_millis(5))
            }
            LaunchProgress::Failed(failure) => {
                return Err(format!("native publication failed: {:?}", failure.error).into());
            }
            _ => return Err("native Windows creation did not publish its root".into()),
        }
    };
    assert_eq!(record.entry, EntryMethod::WindowsJobList);
    let observed: serde_json::Value = loop {
        let path = home.0.join("marker.json");
        if path.try_exists()? {
            break serde_json::from_slice(&fs::read(path)?)?;
        }
        if Instant::now() >= until {
            return Err("native child marker absent at deadline".into());
        }
        std::thread::park_timeout(Duration::from_millis(5));
    };
    fs::write(home.0.join("done"), b"done")?;
    let witness = scope.wait_exit()?;
    assert!(
        matches!(
            witness.root,
            RootWitness::Identified {
                status: ExitStatus::Code(0),
                ..
            }
        ),
        "native child did not exit cleanly: {}",
        fs::read_to_string(home.0.join("stderr"))?
    );
    assert_eq!(observed[0].as_str(), Some(MARKER));
    let argv0 = observed[1].as_str().ok_or("child argv zero absent")?;
    assert_eq!(
        canonicalize_path(Path::new(argv0))?,
        canonicalize_path(image)?
    );
    assert_eq!(observed[2].as_u64(), Some(u64::from(record.root.pid.0)));
    Ok(())
}
