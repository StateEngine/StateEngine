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
        None,
    )?;
    wait_for_fixture(&process, 10000)?;
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

fn wait_for_fixture(process: &impl AsRawHandle, timeout_ms: u32) -> Check {
    // Exact handle ownership is retained; timeout cleanup terminates only this
    // created process handle, never a reused PID or an executable-name match.
    // SAFETY: live retained process handle and finite native wait.
    if unsafe { WaitForSingleObject(process.as_raw_handle(), timeout_ms) } != WAIT_OBJECT_0 {
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
    Ok(())
}

fn output_fixture_args(name: &str, report: &Path) -> Check<Vec<std::ffi::OsString>> {
    Ok(vec![
        "--exact".into(),
        format!("uninstall::spawn::judges::{name}").into(),
        "--ignored".into(),
        "--nocapture".into(),
        "--test-threads=1".into(),
        "--skip".into(),
        serde_json::to_string(report)?.into(),
    ])
}

fn output_fixture_report() -> Check<PathBuf> {
    let encoded = std::env::args()
        .skip_while(|arg| arg != "--skip")
        .nth(1)
        .ok_or("missing output fixture report path")?;
    Ok(serde_json::from_str(&encoded)?)
}

#[test]
fn uninstall_helpers_do_not_retain_redirected_caller_output() -> Check {
    let home = Home::new()?;
    let mut parent = std::process::Command::new(std::env::current_exe()?)
        .args(output_fixture_args("redirected_output_parent", &home.0)?)
        .stdin(std::process::Stdio::null())
        .stdout(File::create(home.0.join("caller.stdout"))?)
        .stderr(File::create(home.0.join("caller.stderr"))?)
        .spawn()?;
    wait_for_fixture(&parent, 30000)?;
    parent.wait()?;
    // Read independently after the spawned parent has closed its copies.
    for name in ["helper.report", "carrier.report", "diagnostic.report"] {
        let actual: [u32; 2] = serde_json::from_slice(&std::fs::read(home.0.join(name))?)?;
        let expected = if name == "diagnostic.report" {
            [FILE_TYPE_CHAR, FILE_TYPE_DISK]
        } else {
            [FILE_TYPE_CHAR; 2]
        };
        assert_eq!(actual, expected, "{name} retained caller output");
    }
    assert_eq!(
        std::fs::read_to_string(home.0.join("private.stderr"))?,
        "owned diagnostic\n"
    );
    Ok(())
}

#[test]
#[ignore = "owned redirected-output parent fixture"]
fn redirected_output_parent() -> Check {
    let root = output_fixture_report()?;
    for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: observes only this isolated fixture's own standard handle.
        assert_eq!(unsafe { GetFileType(GetStdHandle(which)) }, FILE_TYPE_DISK);
    }
    // Both real consumers use the same native builder: helper has no extra
    // creation flag, and PowerShell's last-close carrier uses CREATE_NO_WINDOW.
    for (name, creation_flags) in [
        ("helper.report", 0),
        ("carrier.report", CREATE_NO_WINDOW),
        ("diagnostic.report", CREATE_NO_WINDOW),
    ] {
        let diagnostic = if name == "diagnostic.report" {
            Some(File::create(root.join("private.stderr"))?)
        } else {
            None
        };
        let input = event()?;
        let args = output_fixture_args("observe_private_output", &root.join(name))?;
        let process = command(
            &wide(std::env::current_exe()?.as_os_str()),
            &mut child_line(&args)?,
            &input,
            &[],
            creation_flags,
            None,
            diagnostic.as_ref(),
        )?;
        wait_for_fixture(&process, 10000)?;
        assert!(signaled(&input)?, "private stdin channel was not usable");
    }
    Ok(())
}

#[test]
#[ignore = "owned child-table observer"]
fn observe_private_output() -> Check {
    // SAFETY: observes only this child process's own startup handles.
    let types = unsafe {
        [
            GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)),
            GetFileType(GetStdHandle(STD_ERROR_HANDLE)),
        ]
    };
    eprintln!("owned diagnostic");
    std::fs::write(output_fixture_report()?, serde_json::to_vec(&types)?)?;
    // SAFETY: the parent explicitly passed its live event as this child's stdin.
    assert_ne!(unsafe { SetEvent(GetStdHandle(STD_INPUT_HANDLE)) }, 0);
    Ok(())
}
