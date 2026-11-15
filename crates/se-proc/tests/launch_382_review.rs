//! Independent native owned-scope controls, including a real same-birth exec.
#![cfg(target_os = "macos")]
#[path = "support/macos_runtime/mod.rs"]
mod fixture;
use fixture::{Check, Home, error, json, lifecycle, native, wait};
use se_proc::*;
use std::{
    fs,
    os::fd::AsRawFd,
    path::PathBuf,
    time::{Duration, Instant},
};
fn control() -> Check<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("SE382_CONTROL_DIR").ok_or("control directory absent")?,
    ))
}
struct Fault;
impl Drop for Fault {
    fn drop(&mut self) {
        if let Ok(root) = control() {
            let _ = fs::remove_file(root.join("fault"));
        }
    }
}
fn arm(mode: &str, pid: ProcessId) -> Check<Fault> {
    fs::write(control()?.join("fault"), format!("{mode} {}", pid.0))?;
    Ok(Fault)
}
fn calls() -> Check<usize> {
    Ok(fs::read_to_string(control()?.join("calls"))?
        .lines()
        .count())
}
fn setup() -> Check<(Home, NativeProcessRuntime, LaunchSuccess)> {
    let home = Home::new()?;
    fs::write(
        control()?.join("native-home"),
        home.0.as_os_str().as_encoded_bytes(),
    )?;
    fs::write(home.0.join("make-child"), b"owned descendant")?;
    let sentinel = lifecycle::sentinel(&home.0)?;
    fs::write(home.0.join("sentinel"), sentinel.as_raw_fd().to_string())?;
    let runtime = lifecycle::open(&home.0)?;
    let launched = lifecycle::launch(&runtime, &home.0)?;
    wait(|| Ok(home.0.join("pin-child.json").exists()))?;
    let observed = runtime
        .observe_until(&launched.process, fixture::until())
        .map_err(error)?;
    let child = native::read_pin(&home.0, "child")?;
    assert!(
        observed
            .scope
            .remaining
            .known_live
            .contains(&child.identity)
    );
    Ok((home, runtime, launched))
}
fn close(home: &Home, runtime: &NativeProcessRuntime, launched: &LaunchSuccess) -> Check {
    lifecycle::close(runtime, &launched.process, launched.record.generation)?;
    native::wait_exit(&native::read_pin(&home.0, "child")?, fixture::until())?;
    native::wait_exit(&native::read_pin(&home.0, "provider")?, fixture::until())
}
#[test]
fn same_birth_descendant_exec_settles_without_duplicate_obligations() -> Check {
    let (home, runtime, launched) = setup()?;
    let before = native::read_pin(&home.0, "child")?;
    fs::copy(std::env::current_exe()?, home.0.join("next-child"))?;
    let fault = arm("exec-once", before.identity.pid)?;
    let result = runtime.observe_until(&launched.process, fixture::until());
    drop(fault);
    let observed = result.map_err(error)?;
    let after = native::read_pin(&home.0, "child")?;
    assert_eq!(before.identity.pid, after.identity.pid);
    assert_eq!(before.identity.boot, after.identity.boot);
    assert_eq!(before.identity.start, after.identity.start);
    assert_ne!(before.identity.image, after.identity.image);
    assert!(native::live(&after)?);
    assert_eq!(calls()?, 1);
    assert_eq!(
        observed
            .scope
            .remaining
            .known_live
            .iter()
            .filter(|p| p.pid == after.identity.pid)
            .count(),
        1
    );
    assert_eq!(observed.scope.remaining.extent, EnumerationExtent::Complete);
    json(
        control()?.join("transition.json"),
        &serde_json::json!({"before":before.identity,"after":after.identity}),
    )?;
    close(&home, &runtime, &launched)
}
#[test]
fn persistent_descendant_esrch_stays_unknown_and_keeps_original_bound() -> Check {
    let (home, runtime, launched) = setup()?;
    let child = native::read_pin(&home.0, "child")?;
    let fault = arm("esrch", child.identity.pid)?;
    let start = Instant::now();
    let result = runtime.observe_until(&launched.process, start + Duration::from_millis(150));
    let elapsed = start.elapsed();
    drop(fault);
    let cause = result
        .err()
        .ok_or("unreadable descendant became successful scope proof")?;
    assert_eq!(cause.code, ProcErrorCode::IdentityUnreadable);
    assert_eq!(
        cause.native.as_ref().and_then(|n| n.code),
        Some(i64::from(libc::ESRCH))
    );
    assert!(
        calls()? >= 2,
        "same-birth descendant was not freshly reobserved"
    );
    assert!(elapsed >= Duration::from_millis(100) && elapsed < Duration::from_secs(2));
    assert!(native::live(&child)?);
    json(
        control()?.join("bounded-error.json"),
        &serde_json::json!({"elapsed_ms":elapsed.as_millis(),"cause":format!("{cause:?}")}),
    )?;
    close(&home, &runtime, &launched)
}
#[test]
fn root_image_unreadability_never_gets_descendant_retry() -> Check {
    let (home, runtime, launched) = setup()?;
    let fault = arm("esrch", launched.record.root.pid)?;
    let result = runtime.observe_until(&launched.process, fixture::until());
    drop(fault);
    let cause = result
        .err()
        .ok_or("root unreadability became scope proof")?;
    assert_eq!(cause.code, ProcErrorCode::IdentityUnreadable);
    assert_eq!(calls()?, 1);
    assert_eq!(
        native::identity(launched.record.root.pid)?,
        launched.record.root
    );
    close(&home, &runtime, &launched)
}
#[test]
fn malformed_image_keeps_its_reason_without_retry() -> Check {
    let (home, runtime, launched) = setup()?;
    let child = native::read_pin(&home.0, "child")?;
    let fault = arm("zero", child.identity.pid)?;
    let result = runtime.observe_until(&launched.process, fixture::until());
    drop(fault);
    let cause = result.err().ok_or("malformed image became scope proof")?;
    assert_eq!(calls()?, 1);
    assert!(
        matches!(cause.detail.as_ref(), ProcErrorDetail::Input { reason,.. } if reason.contains("empty executable path"))
    );
    assert!(native::live(&child)?);
    close(&home, &runtime, &launched)
}
#[test]
fn descendant_access_denial_is_not_a_settling_exec() -> Check {
    let (home, runtime, launched) = setup()?;
    let child = native::read_pin(&home.0, "child")?;
    let fault = arm("denied", child.identity.pid)?;
    let result = runtime.observe_until(&launched.process, fixture::until());
    drop(fault);
    let cause = result.err().ok_or("access denial became scope proof")?;
    assert_eq!(
        cause.native.as_ref().and_then(|n| n.code),
        Some(i64::from(libc::EACCES))
    );
    assert_eq!(calls()?, 1);
    assert!(native::live(&child)?);
    close(&home, &runtime, &launched)
}
#[test]
fn different_root_birth_never_becomes_live_original() -> Check {
    let (home, runtime, launched) = setup()?;
    let fault = arm("birth", launched.record.root.pid)?;
    let result = runtime.observe_until(&launched.process, fixture::until());
    drop(fault);
    let observed = result.map_err(error)?;
    assert!(matches!(
        observed.root,
        ProcessObservation::Exited {
            evidence: ExitEvidence::Replaced { .. },
            ..
        }
    ));
    assert_eq!(
        native::identity(launched.record.root.pid)?,
        launched.record.root
    );
    close(&home, &runtime, &launched)
}
#[test]
#[ignore = "exec target selected only by the owned descendant"]
fn review_exec_child() -> Check {
    let root = fixture::root()?;
    json(
        root.join("pin-child.json"),
        &native::pin(ProcessId(std::process::id()))?,
    )?;
    fs::write(root.join("exec-complete"), b"same-birth exec witnessed")?;
    loop {
        std::thread::sleep(Duration::from_millis(20));
    }
}
