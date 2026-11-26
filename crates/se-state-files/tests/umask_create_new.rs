#![cfg(unix)]

use se_state_files::{NativeDirectoryCreation, OwnedFile};
use std::{
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
};

static UMASK_LOCK: Mutex<()> = Mutex::new(());

struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    fn set(mask: libc::mode_t) -> Self {
        // SAFETY: process-wide umask change serialized by UMASK_LOCK in this test binary.
        Self(unsafe { libc::umask(mask) })
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: restores the previous process umask recorded in `set`.
        unsafe { libc::umask(self.0) };
    }
}

fn scratch_dir(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "se-state-files-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
    Ok(dir)
}

fn assert_no_stage_residue(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(dir)? {
        let name = entry?.file_name();
        let text = name.to_string_lossy();
        assert!(
            !text.starts_with(".se-"),
            "unexpected staging residue left in {}: {text}",
            dir.display()
        );
    }
    Ok(())
}

#[test]
fn create_new_and_private_dir_succeed_under_umask_0177() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = UMASK_LOCK.lock().map_err(|_| "umask lock poisoned")?;
    let root = scratch_dir("umask-0177")?;
    let _mask = UmaskGuard::set(0o177);

    let file_path = root.join("settings.json");
    OwnedFile::create_new(&file_path, b"{\"ok\":true}\n")?;
    let mode = std::fs::metadata(&file_path)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let mut opened = OwnedFile::open(&file_path)?.ok_or("created file missing on readback")?;
    assert_eq!(opened.read(4096)?, b"{\"ok\":true}\n");

    let private_home = root.join("private-home");
    let mut creation = NativeDirectoryCreation::begin();
    creation.prepare(&private_home)?;
    let dir_mode = std::fs::metadata(&private_home)?.permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_no_stage_residue(&root)?;

    drop(_mask);
    std::fs::remove_dir_all(&root)?;
    Ok(())
}

#[test]
fn umask_0777_create_new_and_private_dir_leave_zero_residue()
-> Result<(), Box<dyn std::error::Error>> {
    let _lock = UMASK_LOCK.lock().map_err(|_| "umask lock poisoned")?;
    let root = scratch_dir("umask-0777")?;
    let _mask = UmaskGuard::set(0o777);

    let file_path = root.join("settings.json");
    OwnedFile::create_new(&file_path, b"{\"ok\":true}\n")?;
    let mode = std::fs::metadata(&file_path)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let mut opened = OwnedFile::open(&file_path)?.ok_or("created file missing on readback")?;
    assert_eq!(opened.read(4096)?, b"{\"ok\":true}\n");

    let private_home = root.join("private-home");
    let mut creation = NativeDirectoryCreation::begin();
    #[cfg(target_os = "linux")]
    {
        let err = creation
            .prepare(&private_home)
            .err()
            .ok_or("expected Linux private dir creation to refuse under umask 0777")?;
        assert!(
            err.to_string().contains("umask"),
            "expected actionable umask refusal, got: {err}"
        );
    }
    #[cfg(target_os = "macos")]
    {
        creation.prepare(&private_home)?;
        let dir_mode = std::fs::metadata(&private_home)?.permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
    }
    assert_no_stage_residue(&root)?;

    drop(_mask);
    std::fs::remove_dir_all(&root)?;
    Ok(())
}
