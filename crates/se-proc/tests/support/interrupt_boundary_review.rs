//! Real native groups must keep interrupt separate from force and foreign custody.
use super::*;
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn interrupt_is_exact_group_sigint_and_rejects_wrong_generation() -> Check {
    let home = Home::new()?;
    let other = Home::new()?;
    let machine = MachineId::new("interrupt-boundary-review")?;
    let bytes: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let host = HostInstanceId(bytes);
    let generation = GenerationId::new(1)?;
    let runtime = open_runtime(machine.clone(), host)?;
    let until = Instant::now() + Duration::from_secs(15);
    let launch = |home: &Home, serial: u8| -> Check<Scope<'_>> {
        let mut nonce = bytes;
        nonce[0] = serial;
        let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
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
                    arguments: ["--exact", "stdio_binding_child", "--ignored", "--nocapture"]
                        .map(Into::into)
                        .into(),
                    cwd: home.0.to_path_buf(),
                    environment: Environment {
                        entries: vec![(
                            "STDIO_BINDING_JUDGE_ROOT".into(),
                            home.0.as_os_str().into(),
                        )],
                    },
                    stdio: empty(),
                    mode: LaunchMode::HeadlessConsole,
                    window: None,
                    policy: LaunchPolicy {
                        containment: ContainmentRequirement::BestAvailable,
                        writes: WritePolicy::Workspace {
                            roots: vec![home.0.to_path_buf()],
                            scratch: home.0.to_path_buf(),
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
            .bind_stdio(&prepared.prepared, home.endpoints("interrupt")?)
            .map_err(error)?;
        let scope = Scope {
            runtime: &runtime,
            process: prepared.process,
            generation,
            released: false,
        };
        let ticket = match runtime.begin_launch(prepared.prepared) {
            LaunchStart::Pending { ticket, .. } => ticket,
            LaunchStart::Failed(f) => return Err(format!("launch failed: {:?}", f.error).into()),
        };
        loop {
            match runtime.poll_launch(&ticket).map_err(error)? {
                LaunchProgress::Started(_) => break,
                LaunchProgress::AwaitingExecCommit(_) => {
                    runtime.authorize_exec(&ticket).map_err(error)?
                }
                LaunchProgress::Failed(f) => {
                    return Err(format!("exec failed: {:?}", f.error).into());
                }
                _ if Instant::now() < until => std::thread::park_timeout(Duration::from_millis(5)),
                _ => return Err("launch timed out".into()),
            }
        }
        while !home.0.join("vendor-ran").try_exists()? {
            if Instant::now() >= until {
                return Err("fixture exec not witnessed".into());
            }
            std::thread::park_timeout(Duration::from_millis(5));
        }
        Ok(scope)
    };
    let mut target = launch(&home, 1)?;
    let mut guard = launch(&other, 2)?;
    assert!(
        runtime
            .prepare_stop(&target.process, GenerationId::new(2)?, until)
            .is_err()
    );
    assert!(matches!(
        runtime.observe(&target.process).map_err(error)?.root,
        ProcessObservation::Live(_)
    ));
    let token = runtime
        .prepare_stop(&target.process, generation, until)
        .map_err(error)?;
    let attempt = runtime.request_interrupt(token).map_err(error)?;
    assert_eq!(attempt.dispatch.map_err(error)?, StopDispatch::Requested);
    let witness = loop {
        match runtime.witness_stop(&attempt.ticket).map_err(error)? {
            StopObservation::Complete(w) => break w,
            _ if Instant::now() < until => std::thread::park_timeout(Duration::from_millis(5)),
            _ => return Err("interrupt scope remained live".into()),
        }
    };
    assert!(
        matches!(
            witness.root,
            RootWitness::Identified {
                status: ExitStatus::Signal { number: 2, .. },
                ..
            }
        ),
        "interrupt must be SIGINT: {:?}",
        witness.root
    );
    assert_eq!(witness.scope_exit.remaining.population, Population::Empty);
    assert!(
        matches!(
            runtime.observe(&guard.process).map_err(error)?.root,
            ProcessObservation::Live(_)
        ),
        "foreign native scope was interrupted"
    );
    runtime.release(&target.process, &witness).map_err(error)?;
    target.released = true;
    fs::write(other.0.join("exec-observed"), b"release exact guard")?;
    guard.release()?;
    assert!(runtime.arena_snapshot().map_err(error)?.entries.is_empty());
    Ok(())
}
