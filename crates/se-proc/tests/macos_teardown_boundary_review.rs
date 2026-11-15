//! Independent native boundary controls; no product source is replaced.
//! BSD records and successful image observations remain real Darwin queries.
#[cfg(target_os = "macos")]
#[path = "../../test-support/directory_owner.rs"]
mod cleanup_directory;

#[cfg(target_os = "macos")]
mod macos {
    use se_proc::{
        MachineId, ProcErrorCode, ProcessId, ProcessIdentity, ProcessRead, StartIdentity,
        observe_process_birth, read_process, read_process_until,
    };
    use std::{
        io::Write,
        process::Command,
        time::{Duration, Instant},
    };
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn arm() -> Result {
        // SAFETY: the isolated child loads this fixture's known exported ABI.
        let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"se_boundary_arm".as_ptr()) };
        if symbol.is_null() {
            return Err("native fixture arm symbol is absent".into());
        }
        // SAFETY: the non-null symbol is the void(void) function defined in the fixture.
        let call: unsafe extern "C" fn() = unsafe { std::mem::transmute(symbol) };
        // SAFETY: this only arms the current isolated fixture process.
        unsafe { call() };
        Ok(())
    }

    fn calls() -> Result<i32> {
        // SAFETY: the isolated child loads this fixture's known exported ABI.
        let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"se_boundary_calls".as_ptr()) };
        if symbol.is_null() {
            return Err("native fixture counter symbol is absent".into());
        }
        // SAFETY: the non-null symbol is the int(void) function defined in the fixture.
        let call: unsafe extern "C" fn() -> i32 = unsafe { std::mem::transmute(symbol) };
        // SAFETY: this only reads the fixture's atomic call count.
        Ok(unsafe { call() })
    }

    fn expected() -> Result<ProcessIdentity> {
        let value = read_process(
            MachineId::new("native-teardown-boundary")?,
            ProcessId(std::process::id()),
        )
        .map_err(|error| format!("{error:?}"))?;
        match value {
            ProcessRead::Present(live) => Ok(live.identity),
            other => Err(format!("fixture is not live before arming: {other:?}").into()),
        }
    }

    #[test]
    #[ignore = "isolated native boundary child; requires the fixture dylib"]
    fn fault_child() -> Result {
        let mode = std::env::var("SE_TEARDOWN_REVIEW_MODE")?;
        let identity = expected()?;
        arm()?;
        let start = Instant::now();
        if mode == "authority" {
            let error = observe_process_birth(&identity, start + Duration::from_millis(250))
                .err()
                .ok_or("exact authority accepted an unreadable native image")?;
            assert_eq!(error.code, ProcErrorCode::IdentityUnreadable);
            assert_eq!(calls()?, 1, "exact authority retried instead of refusing");
        } else if mode == "identity" {
            let mut wrong_birth = identity.clone();
            let StartIdentity::MacOs {
                seconds,
                microseconds,
            } = identity.start.clone()
            else {
                return Err("expected a native Darwin birth".into());
            };
            wrong_birth.start = StartIdentity::MacOs {
                seconds: seconds + 1,
                microseconds,
            };
            let mut wrong_image = identity.clone();
            wrong_image.image.set_file_name("different-native-image");
            for wrong in [wrong_birth, wrong_image] {
                assert_eq!(
                    observe_process_birth(&wrong, start + Duration::from_millis(250))
                        .err()
                        .map(|e| e.code),
                    Some(ProcErrorCode::IdentityChanged),
                );
            }
        } else {
            let reply = if mode == "immediate" {
                read_process(identity.machine.clone(), identity.pid)
            } else {
                let budget = if mode == "deadline" { 50 } else { 250 };
                let deadline = if mode == "expired" {
                    start
                } else {
                    start + Duration::from_millis(budget)
                };
                read_process_until(identity.machine.clone(), identity.pid, deadline)
            };
            let elapsed = start.elapsed();
            let count = calls()?;
            println!(
                "NATIVE_OBSERVATION {}",
                serde_json::json!({
                    "mode": mode, "calls": count, "elapsed_us": elapsed.as_micros(),
                    "reply": format!("{reply:?}"),
                })
            );
            if mode == "recover" || mode == "recover-later" {
                let ProcessRead::Present(observed) = reply.map_err(|error| format!("{error:?}"))?
                else {
                    return Err("transient image failure fabricated a non-live observation".into());
                };
                assert_eq!(observed.identity, identity);
                assert!(count >= if mode == "recover" { 3 } else { 5 });
            } else if mode == "expired" {
                assert!(reply.is_err(), "the original expired deadline was renewed");
                assert_eq!(count, 0, "expired input reached the image API");
            } else {
                let error = reply.err().ok_or("native failure became a process fact")?;
                assert_eq!(error.code, ProcErrorCode::IdentityUnreadable);
                if mode == "denied" {
                    assert_eq!(
                        error.native.and_then(|n| n.code),
                        Some(i64::from(libc::EACCES))
                    );
                }
                if mode == "deadline" {
                    assert!(
                        count >= 2,
                        "bounded observation never waited for another native read"
                    );
                    assert!(elapsed >= Duration::from_millis(30));
                    assert!(
                        elapsed < Duration::from_millis(1500),
                        "original deadline was renewed"
                    );
                } else {
                    assert_eq!(count, 1, "a strict native failure was retried");
                }
            }
        }
        Ok(())
    }

    #[test]
    fn native_boundary_controls() -> Result {
        let scratch = std::env::temp_dir().join(format!(
            "se-native-teardown-boundary-{}",
            std::process::id()
        ));
        std::fs::create_dir(&scratch)?;
        let owner = super::cleanup_directory::PrivateDirectory::for_case(scratch.clone());
        let source = scratch.join("boundary.c");
        let library = scratch.join("boundary.dylib");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&source)?;
        file.write_all(include_bytes!("support/macos_teardown_boundary_fault.c"))?;
        drop(file);
        let compiled = Command::new("/usr/bin/cc")
            .args(["-dynamiclib", "-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&library)
            .arg("-lproc")
            .output()?;
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        let mut failures = Vec::new();
        for mode in [
            "recover",
            "recover-later",
            "deadline",
            "immediate",
            "authority",
            "denied",
            "zero",
            "identity",
            "expired",
        ] {
            let child = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "macos::fault_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("DYLD_INSERT_LIBRARIES", &library)
                .env("SE_TEARDOWN_REVIEW_MODE", mode)
                .output()?;
            let stdout = String::from_utf8_lossy(&child.stdout);
            let stderr = String::from_utf8_lossy(&child.stderr);
            let passed = child.status.success() && stdout.contains("1 passed");
            println!(
                "NATIVE_CASE {}",
                serde_json::json!({
                    "case": mode, "passed": passed, "exit": child.status.code(),
                    "stdout": stdout, "stderr": stderr,
                })
            );
            if !passed {
                failures.push(mode);
            }
        }
        std::fs::remove_file(source)?;
        std::fs::remove_file(library)?;
        owner.finish(Ok::<(), std::io::Error>(()))?;
        drop(owner);
        assert!(
            !scratch.exists(),
            "native fixture root remained after cleanup"
        );
        assert!(
            failures.is_empty(),
            "native boundary failures: {failures:?}"
        );
        Ok(())
    }
}
