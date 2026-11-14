//! Real preparation consumer with a controlled, process-owned SSH fault boundary.
#![cfg(all(windows, feature = "remote"))]
use se_host::remote::ssh::{ImageStage, prepare_image};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
#[path = "../../test-support/directory.rs"]
mod directory;
type Check = Result<(), Box<dyn std::error::Error>>;

fn exercise(case: &str) -> Check {
    let root = directory::private_directory()?;
    let source = root.join("ssh-fixture.rs");
    std::fs::write(&source, include_str!("support/windows_ssh_transport.rs"))?;
    let compiled = Command::new("rustc")
        .args(["--edition=2024", "-C", "debuginfo=0"])
        .arg(&source)
        .arg("-o")
        .arg(root.join("ssh.exe"))
        .output()?;
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let path = std::env::join_paths(std::iter::once(root.to_path_buf()).chain(
        std::env::split_paths(&std::env::var_os("PATH").ok_or("PATH absent")?),
    ))?;
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "isolated_transfer_consumer",
            "--nocapture",
        ])
        .env("PATH", path)
        .env("SE_STAGING_ROOT", root.as_os_str())
        .env("SE_STAGING_CASE", case)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let until = Instant::now() + Duration::from_secs(75);
    while child.try_wait()?.is_none() {
        if Instant::now() >= until {
            child.kill()?;
            child.wait()?;
            return Err("isolated consumer exceeded its bound".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn cancelling_an_inflight_upload_removes_only_its_nonce_and_preserves_an_incumbent() -> Check {
    exercise("cancel")
}
#[test]
fn a_missing_companion_is_reported_as_absent_before_any_remote_write() -> Check {
    exercise("missing")
}
#[test]
fn an_unreadable_companion_is_distinct_from_an_absent_companion() -> Check {
    exercise("unreadable")
}

#[test]
#[ignore = "invoked only by the three isolated controls with their owned transport"]
fn isolated_transfer_consumer() -> Check {
    let root =
        std::path::PathBuf::from(std::env::var_os("SE_STAGING_ROOT").ok_or("fixture root absent")?);
    let case = std::env::var("SE_STAGING_CASE")?;
    let distribution = root.join("se.exe");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let cancelled = AtomicBool::new(false);
    if case != "cancel" {
        std::fs::write(&distribution, b"synthetic source distribution")?;
        if case == "unreadable" {
            std::fs::create_dir_all(root.join("remote-images/x86_64-unknown-linux-gnu/se"))?;
        }
        let error = runtime
            .block_on(prepare_image(
                "synthetic-destination",
                &distribution,
                &cancelled,
                &mut |_| Ok(()),
            ))
            .err()
            .ok_or("missing/unreadable companion admitted")?;
        assert_eq!(error.code(), se_types::Code::ListenerUnavailable);
        let expected = if case == "missing" {
            "absent from this distribution"
        } else {
            "image is unreadable"
        };
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(
            std::fs::read_to_string(root.join("commands.log"))?,
            "uname -sm\n"
        );
        return Ok(());
    }
    let mut bytes = vec![31; 4 * 1024 * 1024];
    bytes[..root.as_os_str().len().min(100)].fill(43);
    std::fs::write(&distribution, &bytes)?;
    let digest = se_types::hex_lower(&Sha256::digest(&bytes));
    let profile =
        std::path::PathBuf::from(std::env::var_os("USERPROFILE").ok_or("native profile absent")?);
    let directory = profile.join(".stateengine-runtime").join(digest);
    assert!(
        !directory.try_exists()?,
        "fixture cache unexpectedly exists"
    );
    std::fs::create_dir_all(&directory)?;
    std::fs::write(directory.join("se.exe"), b"synthetic incumbent")?;
    std::fs::write(directory.join("other.upload"), b"another invocation")?;
    let result = (|| -> Check {
        let error = runtime
            .block_on(prepare_image(
                "synthetic-destination",
                &distribution,
                &cancelled,
                &mut |progress| {
                    if matches!(progress.stage, ImageStage::Uploading)
                        && progress.bytes_streamed > 0
                    {
                        cancelled.store(true, Ordering::Release);
                    }
                    Ok(())
                },
            ))
            .err()
            .ok_or("cancelled transfer was published")?;
        assert!(error.to_string().contains("cancelled"), "{error}");
        let upload =
            std::path::PathBuf::from(std::fs::read_to_string(root.join("upload-path.txt"))?);
        assert_eq!(upload.parent(), Some(directory.as_path()));
        assert!(!upload.try_exists()?, "owned cancelled upload remained");
        assert_eq!(
            std::fs::read(directory.join("se.exe"))?,
            b"synthetic incumbent"
        );
        assert_eq!(
            std::fs::read(directory.join("other.upload"))?,
            b"another invocation"
        );
        let calls = std::fs::read_to_string(root.join("commands.log"))?;
        assert!(
            calls.lines().count() >= 6,
            "cleanup command was not observed"
        );
        Ok(())
    })();
    cleanup(&directory)?;
    result
}

fn cleanup(directory: &Path) -> Check {
    if directory.try_exists()? {
        std::fs::remove_dir_all(directory)?;
    }
    assert!(!directory.try_exists()?);
    Ok(())
}
