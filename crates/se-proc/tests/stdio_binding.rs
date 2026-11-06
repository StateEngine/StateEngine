//! Protects: G6/G8 — a prepared native launch accepts its child endpoints once;
//! rejected binding fences execution and leaves an exactly releasable scope.
#![cfg(any(target_os = "linux", windows))]
use se_proc::*;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[cfg(target_os = "linux")]
#[path = "support/stop_dispatch_review.rs"]
mod stop_dispatch_review;
fn error(value: ProcError) -> String {
    format!("{value:?}")
}
struct Notices;
impl ExitSink for Notices {
    fn notify(&self, _: ExitNotice) {}
}

// A real OS readiness fixture, not a fake process runtime or private production seam.
#[cfg(unix)]
mod reactor {
    use super::*;
    use std::{
        os::fd::AsRawFd,
        sync::atomic::{AtomicBool, Ordering},
    };
    pub struct Reactor;
    struct Registration {
        stopped: Arc<AtomicBool>,
        armed: Arc<AtomicBool>,
        worker: std::thread::Thread,
    }
    impl NativeRegistration for Registration {
        fn rearm(&self) {
            self.armed.store(true, Ordering::Release);
            self.worker.unpark();
        }
        fn cancel(&mut self) {
            self.stopped.store(true, Ordering::Release);
            self.worker.unpark();
        }
    }
    impl Drop for Registration {
        fn drop(&mut self) {
            self.cancel();
        }
    }
    impl NativeReactor for Reactor {
        fn register(
            &self,
            source: File,
            interest: NativeInterest,
            sink: Arc<dyn NativeReadiness>,
        ) -> ProcResult<Box<dyn NativeRegistration>> {
            let stopped = Arc::new(AtomicBool::new(false));
            let worker_stopped = Arc::clone(&stopped);
            let armed = Arc::new(AtomicBool::new(true));
            let worker_armed = Arc::clone(&armed);
            let worker = std::thread::spawn(move || {
                let mut event = libc::pollfd {
                    fd: source.as_raw_fd(),
                    events: match interest {
                        NativeInterest::Readable => libc::POLLIN,
                        NativeInterest::Priority => libc::POLLPRI,
                    },
                    revents: 0,
                };
                while !worker_stopped.load(Ordering::Acquire) {
                    if !worker_armed.load(Ordering::Acquire) {
                        std::thread::park_timeout(Duration::from_millis(20));
                        continue;
                    }
                    // SAFETY: source owns this descriptor throughout poll; event is one writable pollfd.
                    let ready = unsafe { libc::poll(&mut event, 1, 20) };
                    if ready != 0
                        && worker_armed.swap(false, Ordering::AcqRel)
                        && !worker_stopped.load(Ordering::Acquire)
                    {
                        sink.ready();
                    }
                }
            });
            Ok(Box::new(Registration {
                stopped,
                armed,
                worker: worker.thread().clone(),
            }))
        }
    }
}
struct Home(PathBuf);
impl Home {
    fn new() -> Check<Self> {
        let suffix = se_types::hex_lower(&random_secret()?.expose()[..16]);
        let path = std::env::temp_dir().join(format!("5e-stdio-binding-{suffix}"));
        fs::create_dir(&path)?;
        Ok(Self(fs::canonicalize(path)?))
    }
    fn endpoints(&self, suffix: &str) -> Check<StandardIo> {
        fs::write(
            self.0.join(format!("input-{suffix}")),
            b"owned input marker",
        )?;
        Ok(StandardIo {
            stdin: Some(File::open(self.0.join(format!("input-{suffix}")))?),
            stdout: Some(File::create(self.0.join(format!("output-{suffix}")))?),
            stderr: Some(File::create(self.0.join(format!("error-{suffix}")))?),
        })
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("retained binding fixture {}: {error}", self.0.display());
        }
    }
}
fn empty() -> StandardIo {
    StandardIo {
        stdin: None,
        stdout: None,
        stderr: None,
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "child fixture for the explicitly selected desktop smoke"]
fn window_console_child() -> Check {
    use std::io::IsTerminal;
    assert!(std::io::stdin().is_terminal());
    assert!(std::io::stdout().is_terminal());
    assert!(std::io::stderr().is_terminal());
    let root =
        PathBuf::from(std::env::var_os("STDIO_BINDING_JUDGE_ROOT").ok_or("missing fixture home")?);
    fs::write(root.join("console-ready"), b"real controlling PTY")?;
    println!("StateEngine terminal smoke: real provider console");
    let until = Instant::now() + Duration::from_secs(15);
    while !root.join("console-done").try_exists()? {
        if Instant::now() >= until {
            return Err("desktop smoke did not finish".into());
        }
        std::thread::park_timeout(Duration::from_millis(5));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a logged-in X desktop and xterm"]
fn native_window_owns_provider_pty_and_viewer_until_exact_stop() -> Check {
    let home = Home::new()?;
    let machine = MachineId::new("window-console-smoke")?;
    let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let host = HostInstanceId(nonce);
    let generation = GenerationId::new(1)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
    let runtime = open_runtime(machine.clone(), host)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut entries: Vec<_> = std::env::vars_os()
        .filter(|(name, _)| {
            matches!(
                name.to_str(),
                Some("DISPLAY" | "XAUTHORITY" | "HOME" | "PATH")
            )
        })
        .collect();
    entries.push(("STDIO_BINDING_JUDGE_ROOT".into(), home.0.as_os_str().into()));
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
                    "window_console_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ]
                .map(Into::into)
                .into(),
                cwd: home.0.clone(),
                environment: Environment { entries },
                stdio: empty(),
                mode: LaunchMode::Window,
                window: Some(WindowSpec::UnixTerminal {
                    executable: "/usr/bin/xterm".into(),
                    adapter: TerminalAdapter::Xterm,
                }),
                policy: LaunchPolicy {
                    containment: ContainmentRequirement::BestAvailable,
                    writes: WritePolicy::Workspace {
                        roots: vec![home.0.clone()],
                        scratch: home.0.clone(),
                    },
                    network: NetworkPolicy::Allow,
                    hardening: OptionalHardening::Off,
                },
                deadline,
                notifications: Arc::new(Notices),
            },
        )
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
            return Err(format!("window start: {:?}", failure.error).into());
        }
    };
    loop {
        match runtime.poll_launch(&ticket).map_err(error)? {
            LaunchProgress::Started(_) => break,
            LaunchProgress::AwaitingExecCommit(_) => {
                runtime.authorize_exec(&ticket).map_err(error)?
            }
            LaunchProgress::Failed(failure) => {
                return Err(format!("window exec: {:?}", failure.error).into());
            }
            LaunchProgress::Pending if Instant::now() < deadline => {
                std::thread::park_timeout(Duration::from_millis(5))
            }
            _ => return Err("window launch exceeded deadline".into()),
        }
    }
    while !home.0.join("console-ready").try_exists()? {
        if Instant::now() >= deadline {
            return Err("provider console witness absent".into());
        }
        std::thread::park_timeout(Duration::from_millis(5));
    }
    let observed = runtime.observe(&scope.process).map_err(error)?;
    println!("window native witness: {observed:?}");
    fs::write(home.0.join("console-done"), b"done")?;
    scope.release()?;
    assert!(runtime.arena_snapshot().map_err(error)?.entries.is_empty());
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
#[ignore = "backend child fixture for the explicitly selected desktop smoke"]
fn window_backend_child() -> Check {
    use std::io::IsTerminal;
    assert!(!std::io::stdin().is_terminal());
    assert!(!std::io::stdout().is_terminal());
    assert!(!std::io::stderr().is_terminal());
    let root =
        PathBuf::from(std::env::var_os("STDIO_BINDING_JUDGE_ROOT").ok_or("missing fixture home")?);
    println!("backend-pipe-ready");
    fs::write(root.join("backend-ready"), b"native backend")?;
    let until = Instant::now() + Duration::from_secs(15);
    while !root.join("console-done").try_exists()? {
        if Instant::now() >= until {
            return Err("backend smoke did not finish".into());
        }
        std::thread::park_timeout(Duration::from_millis(5));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a logged-in X desktop and xterm"]
fn native_window_backend_and_console_share_custody() -> Check {
    let home = Home::new()?;
    let machine = MachineId::new("window-console-smoke")?;
    let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let host = HostInstanceId(nonce);
    let generation = GenerationId::new(1)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
    let runtime = open_runtime(machine.clone(), host)?;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut entries: Vec<_> = std::env::vars_os()
        .filter(|(name, _)| {
            matches!(
                name.to_str(),
                Some("DISPLAY" | "XAUTHORITY" | "HOME" | "PATH")
            )
        })
        .collect();
    entries.push(("STDIO_BINDING_JUDGE_ROOT".into(), home.0.as_os_str().into()));
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
                    "window_backend_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ]
                .map(Into::into)
                .into(),
                cwd: home.0.clone(),
                environment: Environment { entries },
                stdio: empty(),
                mode: LaunchMode::Window,
                window: Some(WindowSpec::UnixTerminalWithBackend {
                    executable: "/usr/bin/xterm".into(),
                    adapter: TerminalAdapter::Xterm,
                }),
                policy: LaunchPolicy {
                    containment: ContainmentRequirement::BestAvailable,
                    writes: WritePolicy::Workspace {
                        roots: vec![home.0.clone()],
                        scratch: home.0.clone(),
                    },
                    network: NetworkPolicy::Allow,
                    hardening: OptionalHardening::Off,
                },
                deadline,
                notifications: Arc::new(Notices),
            },
        )
        .map_err(error)?;
    runtime
        .bind_stdio(&prepared.prepared, home.endpoints("backend")?)
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
            return Err(format!("window start: {:?}", failure.error).into());
        }
    };
    loop {
        match runtime.poll_launch(&ticket).map_err(error)? {
            LaunchProgress::Started(_) => break,
            LaunchProgress::AwaitingExecCommit(_) => {
                runtime.authorize_exec(&ticket).map_err(error)?;
                while !home.0.join("backend-ready").try_exists()? {
                    if Instant::now() >= deadline {
                        return Err("backend did not start".into());
                    }
                    std::thread::park_timeout(Duration::from_millis(5));
                }
                assert!(!home.0.join("console-ready").try_exists()?);
                assert!(matches!(
                    runtime.poll_launch(&ticket).map_err(error)?,
                    LaunchProgress::Pending
                ));
                let (_, digest) = runtime
                    .prepare_window_exec(
                        &scope.process,
                        [
                            "--exact",
                            "window_console_child",
                            "--ignored",
                            "--nocapture",
                            "--test-threads=1",
                        ]
                        .map(Into::into)
                        .into(),
                    )
                    .map_err(error)?;
                assert_ne!(digest, prepared.argv_sha256);
                runtime
                    .authorize_window_exec(&scope.process)
                    .map_err(error)?;
            }
            LaunchProgress::Failed(failure) => {
                return Err(format!("window exec: {:?}", failure.error).into());
            }
            LaunchProgress::Pending if Instant::now() < deadline => {
                std::thread::park_timeout(Duration::from_millis(5))
            }
            _ => return Err("window launch exceeded deadline".into()),
        }
    }
    while !home.0.join("console-ready").try_exists()? {
        if Instant::now() >= deadline {
            return Err("provider console witness absent".into());
        }
        std::thread::park_timeout(Duration::from_millis(5));
    }
    let observed = runtime.observe(&scope.process).map_err(error)?;
    assert!(fs::read_to_string(home.0.join("output-backend"))?.contains("backend-pipe-ready"));
    assert!(
        observed.scope.remaining.known_live.len() >= 3,
        "{observed:?}"
    );
    println!("window native witness: {observed:?}");
    fs::write(home.0.join("console-done"), b"done")?;
    scope.release()?;
    assert!(runtime.arena_snapshot().map_err(error)?.entries.is_empty());
    Ok(())
}
fn open_runtime(machine: MachineId, instance: HostInstanceId) -> Check<NativeProcessRuntime> {
    Ok(NativeProcessRuntime::open(HostConfig {
        machine,
        instance,
        helper_executable: std::env::current_exe()?,
        linux_delegation: LinuxDelegation::CurrentScope,
        limits: ResourceLimits {
            max_lifecycles: 2,
            max_diagnostic_members: 8,
            max_observation_bytes: 65536,
            max_stdio_buffer_bytes: 4096,
        },
        #[cfg(unix)]
        reactor: Arc::new(reactor::Reactor),
    })
    .map_err(error)?)
}
struct Scope<'a> {
    runtime: &'a NativeProcessRuntime,
    process: OwnedProcess,
    generation: GenerationId,
    released: bool,
}
impl Scope<'_> {
    fn release(&mut self) -> Check {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let StopObservation::Complete(witness) =
                self.runtime.witness_exit(&self.process).map_err(error)?
            {
                self.runtime
                    .release(&self.process, &witness)
                    .map_err(error)?;
                self.released = true;
                return Ok(());
            }
            if Instant::now() >= until {
                return Err("exact binding fixture scope did not exit".into());
            }
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
}
impl Drop for Scope<'_> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let cleanup = (|| -> Check {
            if let StopObservation::Complete(witness) =
                self.runtime.witness_exit(&self.process).map_err(error)?
            {
                self.runtime
                    .release(&self.process, &witness)
                    .map_err(error)?;
                self.released = true;
                return Ok(());
            }
            let stop = self
                .runtime
                .prepare_stop(
                    &self.process,
                    self.generation,
                    Instant::now() + Duration::from_secs(5),
                )
                .map_err(error)?;
            self.runtime
                .request_stop(stop)
                .map_err(error)?
                .dispatch
                .map_err(error)?;
            self.release()
        })();
        if let Err(error) = cleanup {
            eprintln!("retained exact binding scope: {error}");
        }
    }
}

/// Protects: real child fixture — no process or stream double supplies the positive witness.
#[test]
#[ignore = "spawned only by the public native binding judge"]
fn stdio_binding_child() -> Check {
    let root = PathBuf::from(
        std::env::var_os("STDIO_BINDING_JUDGE_ROOT").ok_or("child fixture root missing")?,
    );
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    assert_eq!(input, "owned input marker");
    println!("owned stdout marker");
    eprintln!("owned stderr marker");
    let mut witness = File::create(root.join("vendor-ran"))?;
    witness.write_all(input.as_bytes())?;
    witness.sync_all()?;
    // Keep the real vendor alive until the parent has observed its exec image.
    // A tiny fixture can otherwise exit before the native image query runs.
    let until = Instant::now() + Duration::from_secs(20);
    while !root.join("exec-observed").try_exists()? {
        if Instant::now() >= until {
            return Err("parent did not observe the fixture exec image".into());
        }
        std::thread::park_timeout(Duration::from_millis(5));
    }
    Ok(())
}

/// Protects: bind_stdio once-only admission, foreign arena refusal, deadline and failed-bind execution fences.
#[test]
fn native_prepared_stream_bindings_keep_custody_through_success_and_refusal() -> Check {
    for case in [
        "roundtrip",
        "duplicate",
        "prebound",
        "expired",
        "foreign-arena",
    ] {
        let home = std::mem::ManuallyDrop::new(Home::new()?);
        println!("binding case {case}: {}", home.0.display());
        let machine = MachineId::new("independent-stdio-binding")?;
        let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
        let host = HostInstanceId(nonce);
        let generation = GenerationId::new(1)?;
        let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
        let runtime = open_runtime(machine.clone(), host)?;
        let deadline = Instant::now()
            + if case == "expired" {
                Duration::from_millis(500)
            } else {
                Duration::from_secs(15)
            };
        let prepared = runtime
            .prepare_launch(
                LaunchReservation {
                    format_version: 1,
                    lifecycle: lifecycle.clone(),
                    host,
                    owner: current_process_identity(machine.clone()).map_err(error)?,
                    generation,
                    scope_nonce: nonce,
                    #[cfg(windows)]
                    parent: ReservationParent::Windows,
                    #[cfg(target_os = "linux")]
                    parent: ReservationParent::LinuxTracked,
                    created_at_unix_ns: 1,
                },
                LaunchSpec {
                    lifecycle: lifecycle.clone(),
                    generation,
                    executable: std::env::current_exe()?,
                    arguments: vec![
                        "--exact".into(),
                        "stdio_binding_child".into(),
                        "--ignored".into(),
                        "--nocapture".into(),
                        "--test-threads=1".into(),
                    ],
                    cwd: home.0.clone(),
                    environment: Environment {
                        entries: vec![(
                            "STDIO_BINDING_JUDGE_ROOT".into(),
                            home.0.as_os_str().to_owned(),
                        )],
                    },
                    stdio: if case == "prebound" {
                        home.endpoints("original")?
                    } else {
                        empty()
                    },
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
                    deadline,
                    notifications: Arc::new(Notices),
                },
            )
            .map_err(error)?;
        let mut scope = Scope {
            runtime: &runtime,
            process: prepared.process,
            generation,
            released: false,
        };
        #[cfg(windows)]
        {
            assert!(
                runtime.describe(&scope.process).is_err(),
                "prepared scope unexpectedly has a published root"
            );
            let identity = (&runtime as &dyn ProviderStdioApi)
                .stdio_identity(&scope.process)
                .map_err(|e| format!("pre-root stream identity unavailable: {e:?}"))?;
            assert_eq!(
                identity,
                StdioIdentity {
                    lifecycle,
                    host,
                    generation
                },
                "pre-root stream identity differs from retained custody"
            );
        }
        if case == "foreign-arena" {
            let foreign = open_runtime(machine, HostInstanceId([99; 16]))?;
            #[cfg(windows)]
            assert!(
                foreign.stdio_identity(&scope.process).is_err(),
                "foreign arena read stream identity"
            );
            assert!(
                foreign
                    .bind_stdio(&prepared.prepared, home.endpoints("foreign")?)
                    .is_err()
            );
        }
        if case == "expired" {
            std::thread::park_timeout(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(5),
            );
        }
        let binding = runtime.bind_stdio(&prepared.prepared, home.endpoints("bound")?);
        let rejected = matches!(case, "prebound" | "expired" | "duplicate");
        if matches!(case, "prebound" | "expired") {
            assert!(binding.is_err(), "{case} binding was admitted");
        } else {
            binding.map_err(error)?;
        }
        if case == "duplicate" {
            assert!(
                runtime.bind_stdio(&prepared.prepared, empty()).is_err(),
                "duplicate binding was admitted"
            );
        }
        match runtime.begin_launch(prepared.prepared) {
            LaunchStart::Failed(failure) => {
                assert!(rejected, "positive launch failed: {:?}", failure.error);
            }
            LaunchStart::Pending { ticket, .. } => {
                assert!(!rejected, "rejected binding still allowed native execution");
                let until = Instant::now() + Duration::from_secs(15);
                loop {
                    match runtime.poll_launch(&ticket).map_err(error)? {
                        LaunchProgress::Started(_) => {
                            fs::write(home.0.join("exec-observed"), b"observed")?;
                            break;
                        }
                        LaunchProgress::AwaitingExecCommit(_) => {
                            runtime.authorize_exec(&ticket).map_err(error)?
                        }
                        LaunchProgress::Failed(failure) => {
                            return Err(format!(
                                "native binding launch failed: {:?}",
                                failure.error
                            )
                            .into());
                        }
                        LaunchProgress::Pending if Instant::now() < until => {
                            std::thread::park_timeout(Duration::from_millis(5))
                        }
                        _ => return Err("native binding launch timed out".into()),
                    }
                }
            }
        }
        scope.release()?;
        #[cfg(windows)]
        assert!(
            runtime.stdio_identity(&scope.process).is_err(),
            "released scope retained a stream identity"
        );
        assert_eq!(
            home.0.join("vendor-ran").try_exists()?,
            !rejected,
            "vendor execution fence differs from binding result"
        );
        if !rejected {
            assert!(
                fs::read_to_string(home.0.join("output-bound"))?.contains("owned stdout marker")
            );
            assert!(
                fs::read_to_string(home.0.join("error-bound"))?.contains("owned stderr marker")
            );
            assert_eq!(fs::read(home.0.join("vendor-ran"))?, b"owned input marker");
        }
        assert!(
            runtime.arena_snapshot().map_err(error)?.entries.is_empty(),
            "released binding still owns an arena entry"
        );
        drop(scope);
        drop(runtime);
        drop(std::mem::ManuallyDrop::into_inner(home));
    }
    Ok(())
}
