//! Direct public boundary tests for `se-native-proc` owned `ValidatedLaunch`
//! transitions (`validate_launch` -> `Driver::prepare` -> `Scope::bind_stdio` ->
//! `Driver::begin`) and Windows `NativeStdio::initialize` one-shot invariants.
#![cfg(any(target_os = "linux", target_os = "macos", windows))]

#[path = "../../test-support/directory_owner.rs"]
mod cleanup_directory;

use se_custody::ProcErrorCode;
#[cfg(not(target_os = "macos"))]
use se_native_proc::Population;
use se_native_proc::notify::Hub;
use se_native_proc::platform::{Driver, Scope};
use se_native_proc::validate::validate_launch;
use se_native_proc::{
    ContainmentRequirement, Environment, ExitNotice, ExitSink, GenerationId, HostConfig,
    HostInstanceId, LaunchMode, LaunchPolicy, LaunchReservation, LaunchSpec, LifecycleId,
    LinuxDelegation, MachineId, NativeExecutableInvocation, NativeExecutablePin, NetworkPolicy,
    OptionalHardening, ProcessIdentity, ReservationParent, ResourceLimits, StandardIo, WritePolicy,
    current_process_identity,
};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct NoopSink;
impl ExitSink for NoopSink {
    fn notify(&self, _: ExitNotice) {}
}

#[cfg(unix)]
struct NoopRegistration;
#[cfg(unix)]
impl se_native_proc::NativeRegistration for NoopRegistration {
    fn rearm(&self) {}
    fn cancel(&mut self) {}
}

#[cfg(unix)]
struct NoopReactor;
#[cfg(unix)]
impl se_native_proc::NativeReactor for NoopReactor {
    fn register(
        &self,
        _source: fs::File,
        _interest: se_native_proc::NativeInterest,
        _sink: Arc<dyn se_native_proc::NativeReadiness>,
    ) -> se_custody::ProcResult<Box<dyn se_native_proc::NativeRegistration>> {
        Ok(Box::new(NoopRegistration))
    }
}

fn private_root(label: &str) -> Check<(cleanup_directory::PrivateDirectory, PathBuf)> {
    let secret = se_proc::random_secret()?;
    let suffix = se_types::hex_lower(&secret.expose()[..8]);
    let path = std::env::temp_dir().join(format!("se-{label}-{suffix}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&path)?;
    }
    #[cfg(windows)]
    {
        fs::create_dir(&path)?;
    }
    let owner = cleanup_directory::PrivateDirectory::for_case(path.clone());
    Ok((owner, path))
}

fn write_exclusive(path: &Path, bytes: &[u8]) -> Check {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn test_limits() -> ResourceLimits {
    ResourceLimits {
        max_lifecycles: 4,
        max_diagnostic_members: 4,
        max_observation_bytes: 4096,
        max_stdio_buffer_bytes: 4096,
    }
}

fn test_config(machine: MachineId, host: HostInstanceId, exe: PathBuf) -> HostConfig {
    HostConfig {
        machine,
        instance: host,
        helper_executable: exe,
        linux_delegation: LinuxDelegation::CurrentScope,
        limits: test_limits(),
        #[cfg(unix)]
        reactor: Arc::new(NoopReactor),
    }
}

fn test_parent() -> ReservationParent {
    #[cfg(target_os = "linux")]
    {
        ReservationParent::LinuxTracked
    }
    #[cfg(target_os = "macos")]
    {
        ReservationParent::MacOs
    }
    #[cfg(windows)]
    {
        ReservationParent::Windows
    }
}

fn test_containment() -> ContainmentRequirement {
    #[cfg(windows)]
    {
        ContainmentRequirement::KernelScope
    }
    #[cfg(not(windows))]
    {
        ContainmentRequirement::TrackedTree
    }
}

fn nul_arg() -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(b"bad\0arg".to_vec())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&['b' as u16, 0, 'a' as u16])
    }
}

struct Fixture {
    owner: ProcessIdentity,
    host: HostInstanceId,
    generation: GenerationId,
    lifecycle: LifecycleId,
    exe: PathBuf,
    config: HostConfig,
    hub: Arc<Hub>,
}

impl Fixture {
    fn new(name: &str, seed: u8, helper: Option<PathBuf>) -> Check<Self> {
        let machine = MachineId::new(name)?;
        let owner = current_process_identity(machine.clone())
            .map_err(|e| format!("current_process_identity: {e:?}"))?;
        let host = HostInstanceId([seed; 16]);
        let generation = GenerationId::new(1)?;
        let lifecycle = LifecycleId::from_parts(1_700_000_000_000 + u64::from(seed), [seed; 10])?;
        let exe = std::env::current_exe()?;
        let config = test_config(machine, host, helper.unwrap_or_else(|| exe.clone()));
        let hub = Arc::new(Hub::new(lifecycle.clone(), generation, Arc::new(NoopSink)));
        Ok(Self {
            owner,
            host,
            generation,
            lifecycle,
            exe,
            config,
            hub,
        })
    }

    fn reservation(&self, nonce: u8) -> LaunchReservation {
        LaunchReservation {
            format_version: 1,
            lifecycle: self.lifecycle.clone(),
            host: self.host,
            owner: self.owner.clone(),
            generation: self.generation,
            scope_nonce: [nonce; 16],
            parent: test_parent(),
            created_at_unix_ns: 1,
        }
    }

    fn validate(
        &self,
        nonce: u8,
        spec: LaunchSpec,
    ) -> Check<se_native_proc::validate::ValidatedLaunch> {
        validate_launch(self.reservation(nonce), spec, &self.config, &self.owner)
            .map_err(|e| format!("validate_launch: {e:?}").into())
    }

    fn spec(
        &self,
        cwd: PathBuf,
        workspace: PathBuf,
        args: Vec<OsString>,
        deadline: Instant,
        custody: Option<NativeExecutableInvocation>,
    ) -> LaunchSpec {
        LaunchSpec {
            executable_custody: custody,
            lifecycle: self.lifecycle.clone(),
            generation: self.generation,
            executable: self.exe.clone(),
            arguments: args,
            cwd,
            environment: Environment { entries: vec![] },
            stdio: StandardIo {
                stdin: None,
                stdout: None,
                stderr: None,
            },
            mode: LaunchMode::Headless,
            window: None,
            policy: LaunchPolicy {
                containment: test_containment(),
                writes: WritePolicy::Workspace {
                    roots: vec![workspace.clone()],
                    scratch: workspace,
                },
                network: NetworkPolicy::Allow,
                hardening: OptionalHardening::Off,
            },
            deadline,
            notifications: Arc::new(NoopSink),
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn assert_stop_and_release(scope: &mut Scope) -> Check {
    let deadline = Instant::now() + Duration::from_secs(5);
    scope
        .stop(deadline)
        .map_err(|e| format!("scope.stop: {e:?}"))?;
    loop {
        let obs = scope
            .observe()
            .map_err(|e| format!("scope.observe: {e:?}"))?;
        if obs.remaining.population == Population::Empty {
            break;
        }
        assert!(Instant::now() < deadline, "child did not exit before bound");
        std::thread::sleep(Duration::from_millis(10));
    }
    scope
        .release(true)
        .map_err(|e| format!("scope.release: {e:?}"))?;
    Ok(())
}

#[test]
fn validate_launch_refuses_nul_bad_reservation_policy_and_cwd() -> Check {
    let (_guard, root) = private_root("val-refuse")?;
    let ws = root.join("ws");
    let outside = root.join("outside");
    fs::create_dir(&ws)?;
    fs::create_dir(&outside)?;
    let fx = Fixture::new("validate-refusal-test", 0x11, None)?;
    let dl = Instant::now() + Duration::from_secs(30);

    // Interior NUL in arguments.
    let err = validate_launch(
        fx.reservation(1),
        fx.spec(ws.clone(), ws.clone(), vec![nul_arg()], dl, None),
        &fx.config,
        &fx.owner,
    )
    .err()
    .ok_or("validate_launch accepted interior NUL")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);

    // Mismatched reservation host.
    let mut bad_res = fx.reservation(2);
    bad_res.host = HostInstanceId([0x99; 16]);
    let err = validate_launch(
        bad_res,
        fx.spec(ws.clone(), ws.clone(), vec![], dl, None),
        &fx.config,
        &fx.owner,
    )
    .err()
    .ok_or("validate_launch accepted mismatched reservation host")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);

    // Unavailable hardening profile.
    let mut bad_policy = fx.spec(ws.clone(), ws.clone(), vec![], dl, None);
    bad_policy.policy.hardening = OptionalHardening::Required {
        profile: "nonexistent".into(),
    };
    let err = validate_launch(fx.reservation(3), bad_policy, &fx.config, &fx.owner)
        .err()
        .ok_or("validate_launch accepted unavailable hardening")?;
    assert_eq!(err.code, ProcErrorCode::HardeningUnavailable);

    // Working directory outside workspace roots.
    let err = validate_launch(
        fx.reservation(4),
        fx.spec(outside, ws, vec![], dl, None),
        &fx.config,
        &fx.owner,
    )
    .err()
    .ok_or("validate_launch accepted cwd outside workspace")?;
    assert_eq!(err.code, ProcErrorCode::CwdOutsideWorkspace);
    Ok(())
}

#[test]
fn scope_bind_stdio_and_begin_enforce_one_shot_and_cleanup() -> Check {
    let (_guard, root) = private_root("oneshot")?;
    #[cfg(target_os = "macos")]
    let helper = Some(PathBuf::from("/nonexistent/se-native-boundary-helper"));
    #[cfg(not(target_os = "macos"))]
    let helper = None;

    let fx = Fixture::new("oneshot-boundary-test", 0x22, helper)?;
    let driver = Driver::new(&fx.config).map_err(|e| format!("Driver::new: {e:?}"))?;
    let dl = Instant::now() + Duration::from_secs(30);

    // Prepare a valid headless scope, bind stdio once, then refuse double bind.
    let validated = fx.validate(
        10,
        fx.spec(
            root.clone(),
            root.clone(),
            vec![OsString::from("--help")],
            dl,
            None,
        ),
    )?;
    let mut scope = driver
        .prepare(validated, test_limits(), &fx.hub)
        .map_err(|e| format!("prepare: {e:?}"))?;
    scope
        .bind_stdio(StandardIo {
            stdin: None,
            stdout: None,
            stderr: None,
        })
        .map_err(|e| format!("first bind_stdio: {e:?}"))?;
    let err = scope
        .bind_stdio(StandardIo {
            stdin: None,
            stdout: None,
            stderr: None,
        })
        .err()
        .ok_or("double bind_stdio succeeded")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);

    // First begin consumes the ValidatedLaunch; subsequent bind_stdio & begin refuse.
    #[cfg(not(target_os = "macos"))]
    {
        driver
            .begin(&mut scope, &fx.hub)
            .map_err(|e| format!("first begin: {e:?}"))?;
        let err = scope
            .bind_stdio(StandardIo {
                stdin: None,
                stdout: None,
                stderr: None,
            })
            .err()
            .ok_or("bind_stdio after begin succeeded")?;
        assert_eq!(err.code, ProcErrorCode::IllegalTransition);
        let err = driver
            .begin(&mut scope, &fx.hub)
            .err()
            .ok_or("second begin succeeded")?;
        assert_eq!(err.code, ProcErrorCode::IllegalTransition);
        assert_stop_and_release(&mut scope)?;
    }
    #[cfg(target_os = "macos")]
    {
        let err = driver
            .begin(&mut scope, &fx.hub)
            .err()
            .ok_or("nonexistent macOS helper unexpectedly spawned")?;
        assert_eq!(err.code, ProcErrorCode::LaunchFailed);
        assert!(!scope.child_created());
        let err = scope
            .bind_stdio(StandardIo {
                stdin: None,
                stdout: None,
                stderr: None,
            })
            .err()
            .ok_or("bind_stdio after begin succeeded")?;
        assert_eq!(err.code, ProcErrorCode::IllegalTransition);
        let err = driver
            .begin(&mut scope, &fx.hub)
            .err()
            .ok_or("second begin succeeded")?;
        assert_eq!(err.code, ProcErrorCode::IllegalTransition);
        scope
            .release(true)
            .map_err(|e| format!("scope.release: {e:?}"))?;
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[test]
fn scope_bind_stdio_refuses_window_mode() -> Check {
    let (_guard, root) = private_root("win-stdio")?;
    let fx = Fixture::new("window-stdio-boundary-test", 0x23, None)?;
    let driver = Driver::new(&fx.config).map_err(|e| format!("Driver::new: {e:?}"))?;
    let dl = Instant::now() + Duration::from_secs(30);
    let mut win_spec = fx.spec(root.clone(), root, vec![], dl, None);
    win_spec.mode = LaunchMode::Window;
    #[cfg(target_os = "linux")]
    {
        win_spec.window = Some(se_native_proc::WindowSpec::UnixTerminal {
            executable: PathBuf::from("/usr/bin/xterm"),
            adapter: se_native_proc::TerminalAdapter::Xterm,
        });
    }
    #[cfg(windows)]
    {
        win_spec.window = Some(se_native_proc::WindowSpec::WindowsConsole);
    }
    let validated = fx.validate(11, win_spec)?;
    let mut win_scope = driver
        .prepare(validated, test_limits(), &fx.hub)
        .map_err(|e| format!("prepare window: {e:?}"))?;
    let err = win_scope
        .bind_stdio(StandardIo {
            stdin: None,
            stdout: None,
            stderr: None,
        })
        .err()
        .ok_or("window bind_stdio succeeded")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    win_scope
        .release(true)
        .map_err(|e| format!("win_scope.release: {e:?}"))?;
    Ok(())
}

#[test]
fn driver_begin_rechecks_deadline_cwd_escape_and_custody_invalidation() -> Check {
    let (_guard, root) = private_root("recheck")?;
    let ws = root.join("ws");
    let cwd = ws.join("work");
    let outside = root.join("outside");
    fs::create_dir(&ws)?;
    fs::create_dir(&cwd)?;
    fs::create_dir(&outside)?;

    let fx = Fixture::new("recheck-boundary-test", 0x33, None)?;
    let driver = Driver::new(&fx.config).map_err(|e| format!("Driver::new: {e:?}"))?;

    // 1. Deadline expiry between prepare and begin.
    let short_dl = Instant::now() + Duration::from_millis(25);
    let validated = fx.validate(20, fx.spec(cwd.clone(), ws.clone(), vec![], short_dl, None))?;
    let mut scope = driver
        .prepare(validated, test_limits(), &fx.hub)
        .map_err(|e| format!("prepare short deadline: {e:?}"))?;
    std::thread::sleep(Duration::from_millis(45));
    let err = driver
        .begin(&mut scope, &fx.hub)
        .err()
        .ok_or("begin accepted expired deadline")?;
    assert_eq!(err.code, ProcErrorCode::LaunchTimedOut);
    assert!(!scope.child_created());
    scope
        .release(true)
        .map_err(|e| format!("scope.release deadline: {e:?}"))?;

    // 2. CWD escape (Unix symlink swap) or removal (Windows) between prepare and begin.
    let dl = Instant::now() + Duration::from_secs(30);
    let validated = fx.validate(21, fx.spec(cwd.clone(), ws.clone(), vec![], dl, None))?;
    let mut scope = driver
        .prepare(validated, test_limits(), &fx.hub)
        .map_err(|e| format!("prepare cwd escape: {e:?}"))?;
    fs::remove_dir(&cwd)?;
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, &cwd)?;
        let err = driver
            .begin(&mut scope, &fx.hub)
            .err()
            .ok_or("begin accepted cwd symlink escape")?;
        assert_eq!(err.code, ProcErrorCode::CwdOutsideWorkspace);
    }
    #[cfg(windows)]
    {
        let err = driver
            .begin(&mut scope, &fx.hub)
            .err()
            .ok_or("begin accepted removed cwd")?;
        assert_eq!(err.code, ProcErrorCode::LaunchFailed);
    }
    assert!(!scope.child_created());
    scope
        .release(true)
        .map_err(|e| format!("scope.release cwd: {e:?}"))?;

    // 3. Executable custody invalidation between prepare and begin.
    let image = root.join("pinned-image.bin");
    let replacement = root.join("replacement-image.bin");
    write_exclusive(&image, b"original-image-bytes")?;
    write_exclusive(&replacement, b"replaced-image-bytes-longer")?;
    let pin = NativeExecutablePin::open(&image)?.ok_or("pinned image missing")?;
    let mut spec = fx.spec(ws.clone(), ws, vec![], dl, Some(pin.prepare()?));
    spec.executable = image.clone();
    let validated = fx.validate(22, spec)?;
    let mut scope = driver
        .prepare(validated, test_limits(), &fx.hub)
        .map_err(|e| format!("prepare custody: {e:?}"))?;
    fs::rename(&replacement, &image)?;
    let err = driver
        .begin(&mut scope, &fx.hub)
        .err()
        .ok_or("begin accepted invalidated executable custody")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    assert!(!scope.child_created());
    scope
        .release(true)
        .map_err(|e| format!("scope.release custody: {e:?}"))?;
    Ok(())
}

#[cfg(windows)]
mod windows_stdio_boundary {
    use super::*;
    use se_native_proc::{
        StdioCloseScope, StdioCompletion, StdioConfig, StdioIdentity, StdioLimits, StdioNotice,
        StdioSink,
    };

    struct NoopStdioSink;
    impl StdioSink for NoopStdioSink {
        fn notify(&self, _: StdioNotice) {}
    }

    fn make_stdio_config(
        lifecycle: LifecycleId,
        host: HostInstanceId,
        generation: GenerationId,
    ) -> StdioConfig {
        StdioConfig {
            identity: StdioIdentity {
                lifecycle,
                host,
                generation,
            },
            limits: StdioLimits {
                max_read_bytes: 1024,
                max_write_bytes: 1024,
                max_buffer_bytes: 4096,
            },
            notifications: Arc::new(NoopStdioSink),
        }
    }

    #[test]
    fn native_stdio_refuses_double_init_and_init_after_release() -> Check {
        let machine = MachineId::new("native-stdio-boundary-test")?;
        let host = HostInstanceId([0x77; 16]);
        let generation = GenerationId::new(1)?;
        let lifecycle = LifecycleId::from_parts(1_700_000_000_002, [3; 10])?;
        let exe = std::env::current_exe()?;
        let driver = Driver::new(&test_config(machine, host, exe))
            .map_err(|e| format!("Driver::new: {e:?}"))?;

        let port = driver
            .create_stdio(&make_stdio_config(lifecycle.clone(), host, generation))
            .map_err(|e| format!("create_stdio: {e:?}"))?;
        let child = port
            .initialize()
            .map_err(|e| format!("first init: {e:?}"))?;
        let err = port
            .initialize()
            .err()
            .ok_or("second initialize succeeded")?;
        assert_eq!(err.code, ProcErrorCode::IllegalTransition);
        drop(child);

        let close_id = port
            .close(StdioCloseScope::All)
            .map_err(|e| format!("close: {e:?}"))?;
        let (_, binding, _, _, _) = port.snapshot();
        let deadline = Instant::now() + Duration::from_secs(5);
        let witness = loop {
            match port
                .take(close_id, binding)
                .map_err(|e| format!("take close: {e:?}"))?
            {
                StdioCompletion::Pending => {
                    assert!(Instant::now() < deadline, "close timed out");
                    std::thread::sleep(Duration::from_millis(10));
                }
                StdioCompletion::Close { result, .. } => {
                    break result.map_err(|e| format!("close failed: {e:?}"))?;
                }
                _ => return Err("unexpected completion kind".into()),
            }
        };
        port.release_operation(close_id)
            .map_err(|e| format!("release_operation: {e:?}"))?;
        port.release(&witness, binding)
            .map_err(|e| format!("release: {e:?}"))?;

        let err = port
            .initialize()
            .err()
            .ok_or("initialize after release succeeded")?;
        assert_eq!(err.code, ProcErrorCode::IllegalTransition);

        let port2 = driver
            .create_stdio(&make_stdio_config(lifecycle, host, generation))
            .map_err(|e| format!("create_stdio 2: {e:?}"))?;
        let close_id2 = port2
            .close(StdioCloseScope::All)
            .map_err(|e| format!("close 2: {e:?}"))?;
        let (_, binding2, _, _, _) = port2.snapshot();
        let witness2 = match port2
            .take(close_id2, binding2)
            .map_err(|e| format!("take close 2: {e:?}"))?
        {
            StdioCompletion::Close { result, .. } => {
                result.map_err(|e| format!("close 2 failed: {e:?}"))?
            }
            _ => return Err("unexpected completion kind for uninitialized close".into()),
        };
        port2
            .release_operation(close_id2)
            .map_err(|e| format!("release_operation 2: {e:?}"))?;
        port2
            .release(&witness2, binding2)
            .map_err(|e| format!("release 2: {e:?}"))?;

        let err = port2
            .initialize()
            .err()
            .ok_or("initialize after uninitialized release succeeded")?;
        assert_eq!(err.code, ProcErrorCode::IllegalTransition);
        Ok(())
    }
}
