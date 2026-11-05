//! Bug: 532e5c28 — entering the force path could label an empty-scope no-op forced.
use super::*;

/// Protects: G6 — the native public consumer distinguishes actual force from a stop after exact exit.
#[test]
fn native_force_and_already_exited_dispatch_are_distinct() -> Check {
    let mut failures = Vec::new();
    for case in ["exited", "live"] {
        let home = Home::new()?;
        let machine = MachineId::new("stop-dispatch-review")?;
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
                    arguments: ["--exact", "stdio_binding_child", "--ignored", "--nocapture"]
                        .map(Into::into)
                        .into(),
                    cwd: home.0.clone(),
                    environment: Environment {
                        entries: vec![(
                            "STDIO_BINDING_JUDGE_ROOT".into(),
                            home.0.as_os_str().into(),
                        )],
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
            .bind_stdio(&prepared.prepared, home.endpoints("stop")?)
            .map_err(error)?;
        let mut scope = Scope {
            runtime: &runtime,
            process: prepared.process,
            generation,
            released: false,
        };
        let ticket = match runtime.begin_launch(prepared.prepared) {
            LaunchStart::Pending { ticket, .. } => ticket,
            LaunchStart::Failed(failure) => {
                return Err(format!("start: {:?}", failure.error).into());
            }
        };
        let record = loop {
            match runtime.poll_launch(&ticket).map_err(error)? {
                LaunchProgress::Started(value) => break value.record,
                LaunchProgress::AwaitingExecCommit(_) => {
                    runtime.authorize_exec(&ticket).map_err(error)?
                }
                LaunchProgress::Failed(failure) => {
                    return Err(format!("exec: {:?}", failure.error).into());
                }
                LaunchProgress::Pending if Instant::now() < until => {
                    std::thread::park_timeout(Duration::from_millis(5))
                }
                _ => return Err("native dispatch fixture launch timed out".into()),
            }
        };
        while !home.0.join("vendor-ran").try_exists()? {
            assert!(
                Instant::now() < until,
                "actual child did not reach its wait"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
        let token = runtime
            .prepare_stop(&scope.process, generation, until)
            .map_err(error)?;
        if case == "exited" {
            fs::write(home.0.join("exec-observed"), b"release exact child")?;
            // Observe outside the runtime slot: its own witness would advance
            // the slot to Exited before the prepared stop could be consumed.
            loop {
                match read_process(record.root.machine.clone(), record.root.pid).map_err(error)? {
                    ProcessRead::Present(value)
                        if value.identity == record.root
                            && value.state == NativeState::ExitedAwaitingReap =>
                    {
                        break;
                    }
                    ProcessRead::ExitedRecord {
                        pid, boot, start, ..
                    } if pid == record.root.pid
                        && boot == record.root.boot
                        && start == record.root.start =>
                    {
                        break;
                    }
                    _ if Instant::now() < until => {
                        std::thread::park_timeout(Duration::from_millis(5))
                    }
                    other => return Err(format!("exact child exit unavailable: {other:?}").into()),
                }
            }
        }
        let attempt = runtime.request_stop(token).map_err(error)?;
        let dispatch = format!("{:?}", attempt.dispatch.map_err(error)?);
        let witness = loop {
            match runtime.witness_stop(&attempt.ticket).map_err(error)? {
                StopObservation::Complete(witness) => break witness,
                _ if Instant::now() < until => std::thread::park_timeout(Duration::from_millis(5)),
                other => return Err(format!("scope did not close: {other:?}").into()),
            }
        };
        let status = match &witness.root {
            RootWitness::Identified {
                expected, status, ..
            } if *expected == record.root => status,
            other => return Err(format!("exact root witness missing: {other:?}").into()),
        };
        assert_eq!(witness.scope_exit.remaining.population, Population::Empty);
        let expected = if case == "exited" {
            "NotNeeded"
        } else {
            "Requested"
        };
        let right_status = if case == "exited" {
            *status == ExitStatus::Code(0)
        } else {
            matches!(status, ExitStatus::Signal { number: 9, .. })
        };
        let correct = dispatch == expected && right_status;
        if !correct {
            failures.push(format!(
                "{case}: dispatch={dispatch}, expected={expected}, root={status:?}"
            ));
        }
        println!(
            "native stop {case}: pid={} birth={:?}, dispatch={dispatch}, root={status:?}, empty scope",
            record.root.pid.0, record.root.start
        );
        runtime.release(&scope.process, &witness).map_err(error)?;
        scope.released = true;
        assert!(runtime.arena_snapshot().map_err(error)?.entries.is_empty());
        drop(scope);
        drop(runtime);
        // Home removes only this test's unique, owned fixture after release.
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}
