//! Direct public boundary tests for `se-native-proc` `Driver::prepare`/`begin`
//! and Windows `NativeStdio::initialize` one-shot invariants.
#![cfg(any(target_os = "linux", target_os = "macos", windows))]

use se_custody::ProcErrorCode;
use se_native_proc::notify::Hub;
use se_native_proc::platform::{Driver, Scope};
use se_native_proc::{
    ContainmentRequirement, Environment, ExitNotice, ExitSink, GenerationId, HostConfig,
    HostInstanceId, LaunchMode, LaunchPolicy, LaunchReservation, LaunchSpec, LifecycleId,
    LinuxDelegation, MachineId, NativeExecutableInvocation, NativeExecutablePin, NetworkPolicy,
    OptionalHardening, Population, ReservationParent, ResourceLimits, StandardIo, WritePolicy,
    current_process_identity,
};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
        _source: std::fs::File,
        _interest: se_native_proc::NativeInterest,
        _sink: Arc<dyn se_native_proc::NativeReadiness>,
    ) -> se_custody::ProcResult<Box<dyn se_native_proc::NativeRegistration>> {
        Ok(Box::new(NoopRegistration))
    }
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

struct SpecTemplate {
    lifecycle: LifecycleId,
    generation: GenerationId,
    exe: PathBuf,
    cwd: PathBuf,
}

impl SpecTemplate {
    fn build(
        &self,
        args: Vec<OsString>,
        deadline: Instant,
        env: Vec<(OsString, OsString)>,
        custody: Option<NativeExecutableInvocation>,
    ) -> LaunchSpec {
        LaunchSpec {
            executable_custody: custody,
            lifecycle: self.lifecycle.clone(),
            generation: self.generation,
            executable: self.exe.clone(),
            arguments: args,
            cwd: self.cwd.clone(),
            environment: Environment { entries: env },
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
                    roots: vec![self.cwd.clone()],
                    scratch: self.cwd.clone(),
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
fn assert_stop_and_release(scope: &mut Scope) -> Result<(), Box<dyn std::error::Error>> {
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

fn assert_begin_refusals(
    driver: &Driver,
    scope: &mut Scope,
    hub: &Arc<Hub>,
    template: &SpecTemplate,
    valid_args: &[OsString],
    deadline: Instant,
    base_env: &[(OsString, OsString)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut policy_drift = template.build(valid_args.to_vec(), deadline, base_env.to_vec(), None);
    policy_drift.policy.network = NetworkPolicy::Offline;
    let bad_specs = [
        (
            "interior NUL",
            template.build(vec![nul_arg()], deadline, base_env.to_vec(), None),
        ),
        ("policy drift", policy_drift),
        (
            "argv drift",
            template.build(
                vec![OsString::from("--version")],
                deadline,
                base_env.to_vec(),
                None,
            ),
        ),
        (
            "deadline extension",
            template.build(
                valid_args.to_vec(),
                deadline + Duration::from_secs(5),
                base_env.to_vec(),
                None,
            ),
        ),
        (
            "environment drift",
            template.build(
                valid_args.to_vec(),
                deadline,
                vec![(OsString::from("SE_BOUNDARY"), OsString::from("two"))],
                None,
            ),
        ),
    ];
    for (label, bad) in bad_specs {
        let err = driver
            .begin(scope, bad, hub)
            .err()
            .ok_or_else(|| format!("begin accepted {label}"))?;
        assert_eq!(err.code, ProcErrorCode::InvalidInput, "{label}");
        assert!(!scope.child_created(), "{label}");
    }
    Ok(())
}

fn assert_one_shot_begin(
    driver: &Driver,
    scope: &mut Scope,
    hub: &Arc<Hub>,
    template: &SpecTemplate,
    valid_args: &[OsString],
    deadline: Instant,
    base_env: &[(OsString, OsString)],
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(target_os = "macos"))]
    {
        driver
            .begin(
                scope,
                template.build(valid_args.to_vec(), deadline, base_env.to_vec(), None),
                hub,
            )
            .map_err(|e| format!("first begin: {e:?}"))?;
        let err = driver
            .begin(
                scope,
                template.build(valid_args.to_vec(), deadline, base_env.to_vec(), None),
                hub,
            )
            .err()
            .ok_or("repeated begin succeeded")?;
        assert_eq!(err.code, ProcErrorCode::IllegalTransition);
        assert_stop_and_release(scope)?;
    }
    #[cfg(target_os = "macos")]
    {
        let err = driver
            .begin(
                scope,
                template.build(valid_args.to_vec(), deadline, base_env.to_vec(), None),
                hub,
            )
            .err()
            .ok_or("nonexistent macOS helper unexpectedly spawned")?;
        assert_eq!(err.code, ProcErrorCode::LaunchFailed);
        assert!(!scope.child_created());
        let err = driver
            .begin(
                scope,
                template.build(valid_args.to_vec(), deadline, base_env.to_vec(), None),
                hub,
            )
            .err()
            .ok_or("repeated begin succeeded")?;
        assert_eq!(err.code, ProcErrorCode::IllegalTransition);
        scope
            .release(true)
            .map_err(|e| format!("scope.release: {e:?}"))?;
    }
    Ok(())
}

struct TempFile(PathBuf);
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn driver_prepare_and_begin_refuse_nul_drift_and_repeat() -> Result<(), Box<dyn std::error::Error>>
{
    let machine = MachineId::new("native-boundary-test")?;
    let owner = current_process_identity(machine.clone())
        .map_err(|e| format!("current_process_identity: {e:?}"))?;
    let host = HostInstanceId([0x42; 16]);
    let generation = GenerationId::new(1)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_001, [2; 10])?;
    let exe = std::env::current_exe()?;
    let template = SpecTemplate {
        lifecycle: lifecycle.clone(),
        generation,
        exe: exe.clone(),
        cwd: std::env::temp_dir(),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let base_env = vec![(OsString::from("SE_BOUNDARY"), OsString::from("one"))];

    #[cfg(target_os = "macos")]
    let helper = PathBuf::from("/nonexistent/se-native-boundary-helper");
    #[cfg(not(target_os = "macos"))]
    let helper = exe;

    let driver = Driver::new(&test_config(machine, host, helper))
        .map_err(|e| format!("Driver::new: {e:?}"))?;
    let hub = Arc::new(Hub::new(lifecycle.clone(), generation, Arc::new(NoopSink)));
    let reservation = LaunchReservation {
        format_version: 1,
        lifecycle,
        host,
        owner,
        generation,
        scope_nonce: [0x55; 16],
        parent: test_parent(),
        created_at_unix_ns: 1,
    };

    let err = driver
        .prepare(
            &reservation,
            &template.build(vec![nul_arg()], deadline, base_env.clone(), None),
            test_limits(),
            &hub,
        )
        .err()
        .ok_or("prepare accepted interior NUL")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);

    let valid_args = vec![OsString::from("--help")];
    let mut scope = driver
        .prepare(
            &reservation,
            &template.build(valid_args.clone(), deadline, base_env.clone(), None),
            test_limits(),
            &hub,
        )
        .map_err(|e| format!("prepare: {e:?}"))?;

    assert_begin_refusals(
        &driver,
        &mut scope,
        &hub,
        &template,
        &valid_args,
        deadline,
        &base_env,
    )?;
    assert_one_shot_begin(
        &driver,
        &mut scope,
        &hub,
        &template,
        &valid_args,
        deadline,
        &base_env,
    )
}

#[test]
fn driver_begin_refuses_executable_custody_removal_or_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let machine = MachineId::new("native-custody-boundary-test")?;
    let owner = current_process_identity(machine.clone())
        .map_err(|e| format!("current_process_identity: {e:?}"))?;
    let host = HostInstanceId([0x43; 16]);
    let generation = GenerationId::new(1)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_003, [4; 10])?;
    let exe = std::env::current_exe()?;
    let cwd = std::env::temp_dir();
    let deadline = Instant::now() + Duration::from_secs(30);
    let template = SpecTemplate {
        lifecycle: lifecycle.clone(),
        generation,
        exe: exe.clone(),
        cwd: cwd.clone(),
    };

    let pin =
        NativeExecutablePin::open(&exe)?.ok_or("current_exe missing for NativeExecutablePin")?;
    let alt_path = cwd.join(format!("se-alt-custody-{}.bin", std::process::id()));
    std::fs::write(&alt_path, b"different-image-bytes")?;
    let _alt_guard = TempFile(alt_path.clone());
    let alt_pin =
        NativeExecutablePin::open(&alt_path)?.ok_or("alt image missing for NativeExecutablePin")?;

    let driver =
        Driver::new(&test_config(machine, host, exe)).map_err(|e| format!("Driver::new: {e:?}"))?;
    let hub = Arc::new(Hub::new(lifecycle.clone(), generation, Arc::new(NoopSink)));
    let reservation = LaunchReservation {
        format_version: 1,
        lifecycle,
        host,
        owner,
        generation,
        scope_nonce: [0x56; 16],
        parent: test_parent(),
        created_at_unix_ns: 1,
    };

    let args = vec![OsString::from("--help")];
    let mut scope = driver
        .prepare(
            &reservation,
            &template.build(args.clone(), deadline, vec![], Some(pin.prepare()?)),
            test_limits(),
            &hub,
        )
        .map_err(|e| format!("prepare with custody: {e:?}"))?;

    let err = driver
        .begin(
            &mut scope,
            template.build(args.clone(), deadline, vec![], None),
            &hub,
        )
        .err()
        .ok_or("begin accepted removed executable custody")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    assert!(!scope.child_created());

    let err = driver
        .begin(
            &mut scope,
            template.build(args, deadline, vec![], Some(alt_pin.prepare()?)),
            &hub,
        )
        .err()
        .ok_or("begin accepted replaced executable custody")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    assert!(!scope.child_created());

    scope
        .release(true)
        .map_err(|e| format!("scope.release: {e:?}"))?;
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
    fn native_stdio_refuses_double_init_and_init_after_release()
    -> Result<(), Box<dyn std::error::Error>> {
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
