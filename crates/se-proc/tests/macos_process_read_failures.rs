//! Isolated native error returns must never become fabricated process facts.
#[cfg(target_os = "macos")]
#[path = "../../test-support/directory_owner.rs"]
mod cleanup_directory;
#[cfg(target_os = "macos")]
mod macos {
    use se_proc::{MachineId, ProcErrorCode, ProcessId, read_process, read_process_until};
    use std::{
        io::Write,
        process::Command,
        time::{Duration, Instant},
    };
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[test]
    #[ignore = "private native-boundary child, invoked only with the fixture dylib"]
    fn native_fault_child() -> Result {
        let mode = std::env::var("SE_READER_NATIVE_FAULT")?;
        let machine = MachineId::new("darwin-reader-failure-fixture")?;
        let pid = ProcessId(std::process::id());
        let replies = [
            read_process(machine.clone(), pid),
            read_process_until(machine, pid, Instant::now() + Duration::from_millis(50)),
        ];
        for reply in replies {
            let error = reply
                .err()
                .ok_or("native unreadability became a process observation")?;
            assert_eq!(
                error.code,
                ProcErrorCode::IdentityUnreadable,
                "{mode}: {error:?}"
            );
            if mode == "denied" {
                assert_eq!(
                    error.native.and_then(|n| n.code),
                    Some(i64::from(libc::EACCES))
                );
            }
        }
        Ok(())
    }
    #[test]
    fn denied_short_zero_and_missing_image_reads_remain_unreadable() -> Result {
        let scratch =
            std::env::temp_dir().join(format!("se-darwin-reader-fault-{}", std::process::id()));
        std::fs::create_dir(&scratch)?;
        let _root_owner = super::cleanup_directory::PrivateDirectory::for_case(scratch.clone());
        let source = scratch.join("fault.c");
        let library = scratch.join("fault.dylib");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&source)?;
        file.write_all(include_bytes!("support/macos_process_read_fault.c"))?;
        drop(file);
        let compile = Command::new("/usr/bin/cc")
            .args(["-dynamiclib", "-Wall", "-Wextra", "-Werror"])
            .arg(&source)
            .arg("-o")
            .arg(&library)
            .arg("-lproc")
            .output()?;
        assert!(
            compile.status.success(),
            "{}",
            String::from_utf8_lossy(&compile.stderr)
        );
        for mode in ["denied", "short", "zero", "path-missing", "path-zero"] {
            let child = Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "macos::native_fault_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("DYLD_INSERT_LIBRARIES", &library)
                .env("SE_READER_NATIVE_FAULT", mode)
                .output()?;
            assert!(
                child.status.success(),
                "{mode}: {}\n{}",
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr)
            );
            assert!(
                String::from_utf8_lossy(&child.stdout).contains("1 passed"),
                "fault child did not execute its assertion"
            );
        }
        std::fs::remove_file(source)?;
        std::fs::remove_file(library)?;

        _root_owner.finish(Ok(()))
    }
}
