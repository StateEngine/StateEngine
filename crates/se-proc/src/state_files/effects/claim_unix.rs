//! Permanent per-account claim creation and retained installation-record locking.
use super::*;
#[cfg(target_os = "macos")]
#[path = "claim_macos.rs"]
mod macos;

impl Pin {
    pub(in crate::state_files) fn create_claim(path: &Path) -> Result<Self> {
        if let Some(pin) = Self::open(path).map_err(claim_error)? {
            if pin
                .file
                .metadata()
                .map_err(|error| io_error("inspect permanent claim mode", path, error))?
                .mode()
                & 0o077
                != 0
            {
                return Err(unsafe_path(
                    "permanent installation claim must be owner-only",
                    path,
                ));
            }
            #[cfg(target_os = "macos")]
            super::super::metadata(&pin.file, path, false)?;
            return Ok(pin);
        }
        #[cfg(target_os = "macos")]
        macos::create(path)?;
        #[cfg(not(target_os = "macos"))]
        {
            let (directory, leaf_name) = parent(path)?;
            // SAFETY: held trusted parent, exclusive no-follow private creation;
            // the existing permanent claim inode is never truncated or replaced.
            let raw = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    leaf_name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if raw < 0 {
                if io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                    return Err(io_error(
                        "create shared installation claim",
                        path,
                        io::Error::last_os_error(),
                    ));
                }
            } else {
                let file = owned(raw, "create shared installation claim", path)?;
                file.sync_all()
                    .map_err(|error| io_error("sync installation claim", path, error))?;
                directory
                    .sync_all()
                    .map_err(|error| io_error("sync installation claim parent", path, error))?;
            }
        }
        let pin = Self::open(path)
            .map_err(claim_error)?
            .ok_or_else(|| changed("new installation claim disappeared", path))?;
        #[cfg(target_os = "macos")]
        super::super::metadata(&pin.file, path, false)?;
        Ok(pin)
    }
    pub(in crate::state_files) fn claim_record(&mut self) -> Result<()> {
        self.check()?;
        let security = self.file.metadata().map_err(|error| {
            io_error("inspect installation claim protection", &self.path, error)
        })?;
        if security.mode() & 0o022 != 0 {
            return Err(unsafe_path(
                "installation record permits another native writer",
                &self.path,
            ));
        }
        #[cfg(target_os = "macos")]
        metadata::check_directory_acl(&self.file, &self.path)?;
        // The file claim remains held while unrelated children use the parent
        // mutation lock. Rename/digest checks still guard every later effect.
        // Release the parent explicitly through the guard, so a duplicate a
        // child inherited between fork and exec cannot keep it locked.
        if let Some(mut parent) = self.parent_lock.take() {
            parent.release().map_err(|error| {
                io_error("release installer claim parent lock", &self.path, error)
            })?;
        }
        // The pin's own description already holds this record's lock, and
        // `Pin::open` keeps it through the guard for the pin's lifetime, so the
        // claim is that lock. A second description of the same inode would be
        // refused by flock, not granted.
        self.check()
    }
}
