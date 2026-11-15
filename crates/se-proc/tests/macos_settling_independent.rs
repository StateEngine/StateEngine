//! Native descendant exec and refusal controls through the public runtime.
#![cfg(target_os = "macos")]
#[path = "support/macos_runtime/mod.rs"]
mod fixture;
use fixture::{Check, Home, error, lifecycle, native};
use se_proc::*;
use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

fn control() -> Check<PathBuf> {
    Ok(std::env::var_os("SE_SETTLING_CONTROL")
        .ok_or("control path required")?
        .into())
}
fn disarm() -> Check {
    match fs::remove_file(control()?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn arm(home: &Home, pid: ProcessId, mode: u32, trigger: u32) -> Check {
    let nonce = u32::from_ne_bytes(random_secret()?.expose()[..4].try_into()?);
    fs::write(
        control()?,
        format!("{nonce} {} {mode} {trigger}\n{}\n", pid.0, home.0.display()),
    )?;
    Ok(())
}
struct Case {
    home: Home,
    runtime: NativeProcessRuntime,
    process: OwnedProcess,
    generation: GenerationId,
    before: ProcessIdentity,
}
impl Case {
    fn new() -> Check<Self> {
        disarm()?;
        let home = Home::new()?;
        fs::write(home.0.join("sentinel"), b"100")?;
        fs::write(home.0.join("make-child"), b"owned child")?;
        fs::copy(std::env::current_exe()?, home.0.join("next-image"))?;
        let runtime = lifecycle::open(&home.0)?;
        let launched = lifecycle::launch(&runtime, &home.0)?;
        fixture::wait(|| Ok(home.0.join("pin-child.json").exists()))?;
        let before = native::read_pin(&home.0, "child")?.identity;
        fixture::wait(|| {
            Ok(runtime
                .observe(&launched.process)
                .map_err(error)?
                .scope
                .remaining
                .known_live
                .iter()
                .any(|p| p.pid == before.pid && p.start == before.start))
        })?;
        Ok(Self {
            home,
            runtime,
            process: launched.process,
            generation: launched.record.generation,
            before,
        })
    }
    fn close(&self) -> Check {
        disarm()?;
        lifecycle::close(&self.runtime, &self.process, self.generation)?;
        for who in ["provider", "child"] {
            native::wait_exit(&native::read_pin(&self.home.0, who)?, fixture::until())?;
        }
        println!("INDEPENDENT_CLOSURE public_complete=true outside_original_births_gone=true");
        Ok(())
    }
    fn observe(&self, mode: u32, trigger: u32) -> Check<OwnedObservation> {
        arm(&self.home, self.before.pid, mode, trigger)?;
        let result = self
            .runtime
            .observe_until(&self.process, Instant::now() + Duration::from_millis(250));
        disarm()?;
        Ok(result.map_err(error)?)
    }
}
impl Drop for Case {
    fn drop(&mut self) {
        if let Err(e) = disarm() {
            eprintln!("control cleanup failed: {e}");
        }
        match self.runtime.arena_snapshot() {
            Ok(arena) if !arena.entries.is_empty() => {
                if let Err(e) = self.close() {
                    eprintln!("public cleanup unproved: {e}");
                }
            }
            Err(e) => eprintln!("cleanup census unreadable: {e:?}"),
            _ => (),
        }
    }
}
fn assert_one(observed: &OwnedObservation, before: &ProcessIdentity) {
    assert!(matches!(observed.root, ProcessObservation::Live(_)));
    let instances: Vec<_> = observed
        .scope
        .remaining
        .known_live
        .iter()
        .filter(|p| p.pid == before.pid && p.boot == before.boot && p.start == before.start)
        .collect();
    assert_eq!(
        instances.len(),
        1,
        "one native birth must be one retained obligation"
    );
    assert_eq!(observed.scope.remaining.extent, EnumerationExtent::Complete);
}
#[test]
fn independent_same_birth_exec_between_image_reads_settles() -> Check {
    let case = Case::new()?;
    let outcome = case.observe(2, 1);
    let after = native::identity(case.before.pid)?;
    assert_eq!(after.start, case.before.start);
    assert_eq!(after.boot, case.before.boot);
    assert_ne!(after.image, case.before.image);
    println!("INDEPENDENT_EXEC before={:?} after={after:?}", case.before);
    let observed = outcome?;
    assert_one(&observed, &case.before);
    assert!(observed.scope.remaining.known_live.contains(&after));
    case.close()
}
#[test]
fn independent_exec_after_group_enumeration_has_no_duplicate_birth() -> Check {
    let case = Case::new()?;
    // Enumeration reads two paths, membership two, then watcher rechecks four.
    // The ninth descendant path after enumeration is the retained tail read.
    let observed = case.observe(6, 10)?;
    let after = native::identity(case.before.pid)?;
    assert_eq!(after.start, case.before.start);
    assert_ne!(
        after.image, case.before.image,
        "native transition must actually occur"
    );
    assert_one(&observed, &case.before);
    case.close()
}
#[test]
fn independent_transient_descendant_esrch_settles() -> Check {
    let case = Case::new()?;
    let observed = case.observe(1, 1)?;
    assert_one(&observed, &case.before);
    case.close()
}
#[test]
fn independent_stateless_image_error_is_not_absence() -> Check {
    let case = Case::new()?;
    arm(&case.home, case.before.pid, 1, 1)?;
    let result = read_process(case.before.machine.clone(), case.before.pid);
    disarm()?;
    let e = result
        .err()
        .ok_or("stateless unreadability manufactured identity or absence")?;
    assert_eq!(e.code, ProcErrorCode::IdentityUnreadable);
    assert_eq!(
        e.native.as_ref().and_then(|n| n.code),
        Some(i64::from(libc::ESRCH))
    );
    assert_eq!(native::identity(case.before.pid)?, case.before);
    case.close()
}
#[test]
fn independent_root_image_error_and_access_denial_refuse_promptly() -> Check {
    let case = Case::new()?;
    let root = case.runtime.describe(&case.process).map_err(error)?.root;
    for (pid, mode, code) in [
        (root.pid, 4, libc::ESRCH),
        (case.before.pid, 3, libc::EACCES),
    ] {
        arm(&case.home, pid, mode, 1)?;
        let start = Instant::now();
        let result = case
            .runtime
            .observe_until(&case.process, start + Duration::from_secs(2));
        disarm()?;
        let e = result
            .err()
            .ok_or("root unreadability or denied access was accepted")?;
        assert_eq!(
            e.native.as_ref().and_then(|n| n.code),
            Some(i64::from(code))
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }
    case.close()
}
#[test]
fn independent_persistent_descendant_esrch_keeps_original_bound() -> Check {
    let case = Case::new()?;
    arm(&case.home, case.before.pid, 5, 1)?;
    let start = Instant::now();
    let result = case
        .runtime
        .observe_until(&case.process, start + Duration::from_millis(120));
    disarm()?;
    let elapsed = start.elapsed();
    let e = result
        .err()
        .ok_or("persistent image unavailability was accepted")?;
    assert_eq!(e.code, ProcErrorCode::IdentityUnreadable);
    assert!(
        elapsed >= Duration::from_millis(100),
        "must exercise bounded reobservation"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "must preserve original bound"
    );
    assert_eq!(native::identity(case.before.pid)?, case.before);
    case.close()
}
