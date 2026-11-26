#![cfg(unix)]

use se_state_files::{NativeDirectoryCreation, OwnedFile, StateFileErrorCode};
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

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "se-state-files-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
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

#[cfg(target_os = "linux")]
fn supports_anonymous_tmpfile_publish(dir: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let dir_file = std::fs::File::open(dir)?;
    let dot = c".";
    // SAFETY: held open directory fd and literal "." probing O_TMPFILE support.
    let raw = unsafe {
        libc::openat(
            dir_file.as_raw_fd(),
            dot.as_ptr(),
            libc::O_WRONLY | libc::O_TMPFILE | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        let err = std::io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(libc::EOPNOTSUPP | libc::EISDIR | libc::EINVAL | libc::ENOSYS | libc::EACCES)
        ) {
            return Ok(false);
        }
        return Err(err.into());
    }
    // SAFETY: successful openat transferred sole ownership of `raw`.
    let tmp = unsafe { OwnedFd::from_raw_fd(raw) };
    let proc_fd = std::ffi::CString::new(format!("/proc/self/fd/{}", tmp.as_raw_fd()))?;
    let probe_name = c"probe-o-tmpfile";
    // SAFETY: held directory fd and /proc/self/fd path probing exact linkat publication.
    let linked = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            proc_fd.as_ptr(),
            dir_file.as_raw_fd(),
            probe_name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    drop(tmp);
    if linked < 0 {
        let err = std::io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(libc::ENOENT | libc::EXDEV | libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL)
        ) {
            return Ok(false);
        }
        return Err(err.into());
    }
    std::fs::remove_file(dir.join("probe-o-tmpfile"))?;
    Ok(true)
}

#[test]
fn create_new_and_private_dir_succeed_under_umask_0177() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = UMASK_LOCK.lock().map_err(|_| "umask lock poisoned")?;
    let root = ScratchDir::new("umask-0177")?;
    let _mask = UmaskGuard::set(0o177);

    let file_path = root.path().join("settings.json");
    OwnedFile::create_new(&file_path, b"{\"ok\":true}\n")?;
    let mode = std::fs::metadata(&file_path)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let mut opened = OwnedFile::open(&file_path)?.ok_or("created file missing on readback")?;
    assert_eq!(opened.read(4096)?, b"{\"ok\":true}\n");

    let private_home = root.path().join("private-home");
    let mut creation = NativeDirectoryCreation::begin();
    creation.prepare(&private_home)?;
    let dir_mode = std::fs::metadata(&private_home)?.permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    assert_no_stage_residue(root.path())?;
    Ok(())
}

#[test]
fn private_dir_under_umask_0777_leaves_zero_residue() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = UMASK_LOCK.lock().map_err(|_| "umask lock poisoned")?;
    let root = ScratchDir::new("umask-0777-dir")?;
    let _mask = UmaskGuard::set(0o777);

    let private_home = root.path().join("private-home");
    let mut creation = NativeDirectoryCreation::begin();
    #[cfg(target_os = "linux")]
    {
        let err = creation
            .prepare(&private_home)
            .err()
            .ok_or("expected Linux private dir creation to refuse under umask 0777")?;
        assert_eq!(err.code, StateFileErrorCode::LocationUnsafe);
        assert!(
            err.to_string().contains("umask"),
            "expected actionable umask refusal, got: {err}"
        );
        assert!(!private_home.exists());
    }
    #[cfg(target_os = "macos")]
    {
        creation.prepare(&private_home)?;
        let dir_mode = std::fs::metadata(&private_home)?.permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
    }
    assert_no_stage_residue(root.path())?;
    Ok(())
}

#[test]
fn create_new_under_umask_0777_matches_fs_support() -> Result<(), Box<dyn std::error::Error>> {
    let _lock = UMASK_LOCK.lock().map_err(|_| "umask lock poisoned")?;
    let root = ScratchDir::new("umask-0777-file")?;
    #[cfg(target_os = "linux")]
    let expect_success = supports_anonymous_tmpfile_publish(root.path())?;
    #[cfg(not(target_os = "linux"))]
    let expect_success = true;
    let _mask = UmaskGuard::set(0o777);

    let file_path = root.path().join("settings.json");
    if expect_success {
        OwnedFile::create_new(&file_path, b"{\"ok\":true}\n")?;
        let mode = std::fs::metadata(&file_path)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let mut opened = OwnedFile::open(&file_path)?.ok_or("created file missing on readback")?;
        assert_eq!(opened.read(4096)?, b"{\"ok\":true}\n");
    } else {
        let err = OwnedFile::create_new(&file_path, b"{\"ok\":true}\n")
            .err()
            .ok_or("expected non-O_TMPFILE Linux fallback to refuse under umask 0777")?;
        assert_eq!(err.code, StateFileErrorCode::LocationUnsafe);
        assert!(!file_path.exists());
    }
    assert_no_stage_residue(root.path())?;
    Ok(())
}
