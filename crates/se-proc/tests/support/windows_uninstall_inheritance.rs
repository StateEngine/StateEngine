use super::*;
use crate::windows_policy_fixture::*;
#[test]
fn uninstall_spawn_inherits_only_explicit_handles_and_stdio() -> Check {
    let home = Home::new()?;
    let allowed = event()?;
    let excluded = event()?;
    // The real helper's stdin is an explicitly inherited channel. An event is a
    // valid startup handle and keeps this fixture finite without a blocking read.
    let input = event()?;
    let plan = ChildPlan {
        report: home.0.join("child.report"),
        excluded: excluded.as_raw_handle() as usize,
        allowed: Some(allowed.as_raw_handle() as usize),
        input: Some(input.as_raw_handle() as usize),
        claim: None,
    };
    let args = child_args(&plan)?;
    let process = command(
        &wide(std::env::current_exe()?.as_os_str()),
        &mut child_line(&args)?,
        &input,
        &[allowed.as_raw_handle()],
        0,
        None,
    )?;
    // Exact handle ownership is retained; timeout cleanup terminates only this
    // created process handle, never a reused PID or an executable-name match.
    // SAFETY: live retained process handle and finite native wait.
    if unsafe { WaitForSingleObject(process.as_raw_handle(), 10000) } != WAIT_OBJECT_0 {
        // SAFETY: this handle came from our successful private spawn, not a PID lookup.
        unsafe {
            TerminateProcess(process.as_raw_handle(), 97);
            WaitForSingleObject(process.as_raw_handle(), 10000);
        }
        return Err("owned uninstall fixture child did not exit".into());
    }
    let mut code = 0;
    assert_ne!(
        // SAFETY: retained exited process and writable status output.
        unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) },
        0
    );
    assert_eq!(code, 0, "native child test failed");
    assert!(signaled(&allowed)?, "explicit event was not inherited");
    assert!(signaled(&input)?, "explicit stdin event was not usable");
    assert_eq!(
        flags(input.as_raw_handle())? & HANDLE_FLAG_INHERIT,
        0,
        "stdin parent flag survived spawn"
    );
    assert_eq!(
        flags(allowed.as_raw_handle())? & HANDLE_FLAG_INHERIT,
        0,
        "extra parent flag survived spawn"
    );
    report(&plan, &excluded)
}
