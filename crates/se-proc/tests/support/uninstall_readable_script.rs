use super::*;
use crate::windows_policy_fixture::{Check, Home};
use std::process::{Command, Stdio};

/// Protects: J5 — let the native interpreter read the pinned carrier while refusing script mutation.
#[test]
fn script_custody_allows_the_native_reader_and_blocks_mutation() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::open(&home.0)?;
    let script = Script::create(&files, false)?;
    let path = script.path().to_owned();
    let write = File::options()
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(&path);
    assert_eq!(write.err().and_then(|error| error.raw_os_error()), Some(32));
    assert_eq!(
        std::fs::remove_file(&path)
            .err()
            .and_then(|error| error.raw_os_error()),
        Some(32)
    );
    // This is the actual interpreter's -File reader. No private frame means the
    // fixed script exits 78 after loading and compiling, without authorizing work.
    // Bypass applies only to this reader test, independent of machine policy.
    let mut child = Command::new(cleanup::system_powershell()?)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while child.try_wait()?.is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("exact interpreter fixture exceeded its deadline".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output()?;
    assert_eq!(
        output.status.code(),
        Some(78),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    script.remove()?;
    assert_eq!(
        std::fs::symlink_metadata(&path)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    Ok(())
}

/// Protects: J5 — refuse cleanup of a replacement script even when its bytes match the original.
#[test]
fn script_cleanup_preserves_a_same_byte_replacement() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::open(&home.0)?;
    let mut script = Script::create(&files, false)?;
    let path = script.path().to_owned();
    let original = home.0.join("original-readable.ps1");
    drop(script.reader.take());
    std::fs::rename(&path, &original)?;
    std::fs::copy(&original, &path)?;
    let before = std::fs::read(&path)?;
    let failure = script
        .remove()
        .err()
        .ok_or("replacement was adopted for cleanup")?;
    assert!(failure.to_string().contains("replacement preserved"));
    assert_eq!(std::fs::read(&path)?, before);
    assert_eq!(std::fs::read(&original)?, before);
    Ok(())
}
