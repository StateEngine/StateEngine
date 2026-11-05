//! Real native reader across an executable/exit race. Only the observer is interposed.
#![cfg(target_os = "linux")]
use se_proc::{
    MachineId, ProcErrorCode, ProcessIdentity, ProcessRead, read_process, read_process_until,
};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command},
    time::{Duration, Instant},
};
type Check = Result<(), Box<dyn std::error::Error>>;

struct OwnedChild {
    child: Child,
    release: PathBuf,
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Err(error) = std::fs::write(&self.release, b"release") {
            eprintln!("release exact owned exit fixture: {error}");
        }
        if let Err(error) = self.child.wait() {
            eprintln!("wait exact owned exit fixture: {error}");
        }
    }
}
fn fixture_command(name: &str) -> Result<Command, Box<dyn std::error::Error>> {
    let mut command = Command::new(std::env::current_exe()?);
    command.args(["--ignored", "--exact", name, "--nocapture"]);
    Ok(command)
}
fn wait_ready(path: &Path, child: &mut Child) -> Check {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(child.try_wait()?.is_none(), "owned fixture exited early");
        assert!(Instant::now() < deadline, "owned fixture not ready");
        std::thread::park_timeout(Duration::from_millis(5));
    }
    Ok(())
}

#[test]
fn native_executable_exit_requires_fresh_facts_and_keeps_the_original_bound() -> Check {
    let root = std::env::temp_dir().join(format!("se-exit-read-{}", std::process::id()));
    std::fs::create_dir(&root)?;
    let library = root.join("readlink-fault.so");
    let compiled = Command::new("cc")
        .args([
            "-std=c11", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC",
        ])
        .arg("-o")
        .arg(&library)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/executable_exit_fault.c"
        ))
        .arg("-ldl")
        .output()?;
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    for mode in ["exit", "recover", "persistent", "permission"] {
        let ready = root.join(format!("{mode}.ready"));
        let release = root.join(format!("{mode}.release"));
        let mut owned = OwnedChild {
            child: fixture_command("owned_exit_child")?
                .env("SE_EXIT_READY", &ready)
                .env("SE_EXIT_RELEASE", &release)
                .spawn()?,
            release: release.clone(),
        };
        wait_ready(&ready, &mut owned.child)?;
        let ProcessRead::Present(before) = read_process(
            MachineId::new("exit-observer")?,
            se_proc::ProcessId(owned.child.id()),
        )
        .map_err(|error| format!("{error:?}"))?
        else {
            return Err("owned fixture not natively live before observer".into());
        };
        let observed = fixture_command("bounded_exit_observer")?
            .env("LD_PRELOAD", &library)
            .env("SE_EXIT_IDENTITY", serde_json::to_string(&before.identity)?)
            .env(
                "SE_EXIT_READ_PATH",
                format!("/proc/{}/exe", owned.child.id()),
            )
            .env("SE_EXIT_RELEASE", &release)
            .env("SE_EXIT_READ_MODE", mode)
            .output()?;
        assert!(
            observed.status.success(),
            "{mode}: {}{}",
            String::from_utf8_lossy(&observed.stdout),
            String::from_utf8_lossy(&observed.stderr)
        );
        if mode != "exit" {
            assert!(
                owned.child.try_wait()?.is_none(),
                "unreadability falsely ended a live child"
            );
        }
        std::fs::write(&release, b"release")?;
        assert!(
            owned.child.wait()?.success(),
            "owned fixture failed during exit"
        );
        assert!(
            !PathBuf::from(format!("/proc/{}", owned.child.id())).exists(),
            "owned fixture remains after reaping"
        );
        drop(owned);
        println!("native executable observation: {mode} passed; exact child waited");
    }
    std::fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
#[ignore = "standalone child owned and reaped by the native reader test"]
fn owned_exit_child() -> Check {
    let ready = PathBuf::from(std::env::var_os("SE_EXIT_READY").ok_or("ready path absent")?);
    let release = PathBuf::from(std::env::var_os("SE_EXIT_RELEASE").ok_or("release path absent")?);
    std::fs::write(ready, b"ready")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !release.exists() {
        assert!(
            Instant::now() < deadline,
            "parent did not release owned fixture"
        );
        std::thread::park_timeout(Duration::from_millis(5));
    }
    Ok(())
}

#[test]
#[ignore = "standalone production observer with process-local native fault injection"]
fn bounded_exit_observer() -> Check {
    let expected: ProcessIdentity = serde_json::from_str(&std::env::var("SE_EXIT_IDENTITY")?)?;
    let mode = std::env::var("SE_EXIT_READ_MODE")?;
    let started = Instant::now();
    let observed = read_process_until(
        expected.machine.clone(),
        expected.pid,
        started + Duration::from_millis(250),
    );
    match mode.as_str() {
        "exit" => match observed {
            Ok(ProcessRead::Absent { pid, .. }) => assert_eq!(pid, expected.pid),
            Ok(ProcessRead::ExitedRecord {
                pid, boot, start, ..
            }) => {
                assert_eq!(pid, expected.pid);
                assert_eq!(boot, expected.boot);
                assert_eq!(start, expected.start);
            }
            other => return Err(format!("exact child exit remains unproved: {other:?}").into()),
        },
        "recover" => match observed {
            Ok(ProcessRead::Present(live)) => assert_eq!(live.identity, expected),
            other => return Err(format!("recovered exact child is not live: {other:?}").into()),
        },
        "persistent" | "permission" => {
            let error = match observed {
                Err(error) => error,
                Ok(value) => return Err(format!("unreadable live process became {value:?}").into()),
            };
            assert_eq!(error.code, ProcErrorCode::IdentityUnreadable);
            let native = error.native.ok_or("native error lost")?;
            assert_eq!(native.api, "read proc executable");
            if mode == "permission" {
                assert_eq!(native.code, Some(i64::from(libc::EACCES)));
            } else {
                assert_eq!(native.code, Some(i64::from(libc::ENOENT)));
                assert!(
                    started.elapsed() >= Duration::from_millis(250),
                    "original bound bypassed"
                );
            }
        }
        _ => return Err("unknown native fixture mode".into()),
    }
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "observation renewed its original bound"
    );
    Ok(())
}
