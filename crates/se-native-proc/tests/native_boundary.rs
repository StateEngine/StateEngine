//! Direct public boundary tests for `se-native-proc` `Driver::prepare`/`begin`
//! and Windows `NativeStdio::initialize` one-shot invariants.
#![cfg(any(target_os = "linux", target_os = "macos", windows))]

use se_custody::ProcErrorCode;
use se_native_proc::notify::Hub;
use se_native_proc::platform::Driver;
use se_native_proc::{
    ContainmentRequirement, Environment, ExitNotice, ExitSink, GenerationId, HostConfig,
    HostInstanceId, LaunchMode, LaunchPolicy, LaunchReservation, LaunchSpec, LifecycleId,
    LinuxDelegation, MachineId, NetworkPolicy, OptionalHardening, ReservationParent,
    ResourceLimits, StandardIo, WritePolicy, current_process_identity,
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

fn make_spec(
    lifecycle: LifecycleId,
    generation: GenerationId,
    exe: PathBuf,
    cwd: PathBuf,
    args: Vec<OsString>,
) -> LaunchSpec {
    LaunchSpec {
        executable_custody: None,
        lifecycle,
        generation,
        executable: exe,
        arguments: args,
        cwd: cwd.clone(),
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
                roots: vec![cwd.clone()],
                scratch: cwd,
            },
            network: NetworkPolicy::Allow,
            hardening: OptionalHardening::Off,
        },
        deadline: Instant::now() + Duration::from_secs(30),
        notifications: Arc::new(NoopSink),
    }
}

#[test]
fn driver_prepare_and_begin_refuse_interior_nul_mismatch_and_repeat()
-> Result<(), Box<dyn std::error::Error>> {
    let machine = MachineId::new("native-boundary-test")?;
    let owner = current_process_identity(machine.clone())
        .map_err(|e| format!("current_process_identity: {e:?}"))?;
    let host = HostInstanceId([0x42; 16]);
    let generation = GenerationId::new(1)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_001, [2; 10])?;
    let exe = std::env::current_exe()?;
    let cwd = std::env::temp_dir();
    let spec = |args: Vec<OsString>| {
        make_spec(
            lifecycle.clone(),
            generation,
            exe.clone(),
            cwd.clone(),
            args,
        )
    };

    let driver = Driver::new(&test_config(machine, host, exe.clone()))
        .map_err(|e| format!("Driver::new: {e:?}"))?;
    let hub = Arc::new(Hub::new(lifecycle.clone(), generation, Arc::new(NoopSink)));
    let reservation = LaunchReservation {
        format_version: 1,
        lifecycle: lifecycle.clone(),
        host,
        owner,
        generation,
        scope_nonce: [0x55; 16],
        parent: test_parent(),
        created_at_unix_ns: 1,
    };

    // 1. Interior NUL in prepare is refused before any OS scope is created.
    let err = driver
        .prepare(&reservation, &spec(vec![nul_arg()]), test_limits(), &hub)
        .err()
        .ok_or("prepare accepted interior NUL")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);

    // 2. Prepare a valid scope.
    let valid_args = vec![OsString::from("--help")];
    let mut scope = driver
        .prepare(&reservation, &spec(valid_args.clone()), test_limits(), &hub)
        .map_err(|e| format!("prepare: {e:?}"))?;

    // 3. Direct begin with interior NUL is refused.
    let err = driver
        .begin(&mut scope, spec(vec![nul_arg()]), &hub)
        .err()
        .ok_or("begin accepted interior NUL")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    assert!(!scope.child_created());

    // 4. Direct begin with a mismatched policy is refused.
    let mut mismatched = spec(valid_args.clone());
    mismatched.policy.network = NetworkPolicy::Offline;
    let err = driver
        .begin(&mut scope, mismatched, &hub)
        .err()
        .ok_or("begin accepted mismatched policy")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    assert!(!scope.child_created());

    // 5. Direct begin with mismatched argv is refused.
    let err = driver
        .begin(&mut scope, spec(vec![OsString::from("--version")]), &hub)
        .err()
        .ok_or("begin accepted mismatched argv")?;
    assert_eq!(err.code, ProcErrorCode::InvalidInput);
    assert!(!scope.child_created());

    // 6. First valid begin consumes the one-shot binding; second begin is refused.
    #[cfg(not(target_os = "macos"))]
    driver
        .begin(&mut scope, spec(valid_args.clone()), &hub)
        .map_err(|e| format!("first begin: {e:?}"))?;
    #[cfg(target_os = "macos")]
    let _ = driver.begin(&mut scope, spec(valid_args.clone()), &hub);

    let err = driver
        .begin(&mut scope, spec(valid_args), &hub)
        .err()
        .ok_or("repeated begin succeeded")?;
    assert_eq!(err.code, ProcErrorCode::IllegalTransition);

    let _ = scope.stop(Instant::now() + Duration::from_secs(5));
    let _ = scope.release(true);
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

        // 1. Double initialize is refused without overwriting server handles.
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

        // Close and release port cleanly, then verify init-after-release refuses.
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

        // 2. Fresh port closed+released before any initialize also refuses initialize.
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
