//! Held-file removal, recovery and atomic replacement preserve exact identities.
use super::*;
use sha2::{Digest, Sha256};
use std::io::{Seek, SeekFrom, Write};

impl Pin {
    pub(in crate::state_files) fn remove(self, expected: [u8; 32]) -> Result<()> {
        self.check()?;
        verify(&self.file, &self.path, expected)?;
        self.check()?;
        let (recovery_path, recovery_name) = recovery_name(&self.path)?;
        move_no_replace(&self.parent, &self.name, &recovery_name, &self.path)?;
        self.parent
            .sync_all()
            .map_err(|e| io_error("sync staged removal", &recovery_path, e))?;
        let displaced = leaf(&self.parent, &recovery_name, &recovery_path, false)?;
        if id(&displaced, &recovery_path, false, true)? != self.identity
            || digest(&displaced, &recovery_path)? != expected
        {
            move_no_replace(&self.parent, &recovery_name, &self.name, &recovery_path)?;
            self.parent
                .sync_all()
                .map_err(|e| io_error("sync restored raced removal", &self.path, e))?;
            return Err(changed(
                "file changed during removal; displaced file restored",
                &self.path,
            ));
        }
        self.check_parent()?;
        // SAFETY: only the uniquely named, held and reverified original is unlinked.
        // A new file created at the original pathname is never touched.
        if unsafe { libc::unlinkat(self.parent.as_raw_fd(), recovery_name.as_ptr(), 0) } < 0 {
            return Err(io_error(
                "unlink exact held original",
                &recovery_path,
                io::Error::last_os_error(),
            ));
        }
        let after = self
            .file
            .metadata()
            .map_err(|e| io_error("read unlinked original identity", &self.path, e))?;
        if after.nlink() != 0 {
            return Err(changed(
                "unlink did not retire the held original object",
                &recovery_path,
            ));
        }
        if !matches!(digest(&self.file, &self.path), Ok(value) if value == expected) {
            self.retain_raced_bytes(&recovery_path, &recovery_name)?;
            return Err(changed(
                "file changed through an open handle during unlink; recovery copy retained",
                &recovery_path,
            ));
        }
        self.parent
            .sync_all()
            .map_err(|e| io_error("sync installation unlink", &self.path, e))?;
        self.check_parent()?;
        match leaf(&self.parent, &self.name, &self.path, false) {
            Err(e) if absent(&e) => Ok(()),
            Err(e) => Err(e),
            Ok(_) => Err(changed(
                "a new file appeared at the removed pathname; it was preserved",
                &self.path,
            )),
        }
    }
    fn retain_raced_bytes(&self, path: &Path, _name: &CString) -> Result<()> {
        // SAFETY: exclusive no-follow creation of a recovery sibling; no user name
        // is overwritten. Preserve any bytes that raced through the old open FD.
        #[cfg(not(target_os = "macos"))]
        let mut recovery = owned(
            unsafe {
                libc::openat(
                    self.parent.as_raw_fd(),
                    _name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            },
            "retain raced original bytes",
            path,
        )?;
        let mut original = &self.file;
        original
            .seek(SeekFrom::Start(0))
            .map_err(|e| io_error("seek raced original", path, e))?;
        #[cfg(target_os = "macos")]
        let recovery = private_stage::create_profile(path, &self.file, |file| {
            io::copy(&mut original, file)
                .map_err(|e| io_error("copy raced original to recovery sibling", path, e))?;
            Ok(())
        })?;
        #[cfg(not(target_os = "macos"))]
        {
            io::copy(&mut original, &mut recovery)
                .map_err(|e| io_error("copy raced original to recovery sibling", path, e))?;
            metadata::copy(&self.file, &recovery, path)?;
        }
        recovery
            .sync_all()
            .map_err(|e| io_error("sync raced original recovery", path, e))?;
        self.parent
            .sync_all()
            .map_err(|e| io_error("sync raced original recovery parent", path, e))
    }
    pub(in crate::state_files) fn restore_to(
        self,
        destination: &Path,
        expected: [u8; 32],
    ) -> Result<()> {
        components(destination)?;
        if destination.parent() != self.path.parent() || destination == self.path {
            return Err(unsafe_path(
                "recovery target must be a distinct exact name in the held parent",
                destination,
            ));
        }
        let target = name(
            destination
                .file_name()
                .ok_or_else(|| unsafe_path("recovery target leaf missing", destination))?,
            destination,
        )?;
        self.check()?;
        verify(&self.file, &self.path, expected)?;
        self.check()?;
        move_no_replace(&self.parent, &self.name, &target, destination)?;
        self.parent
            .sync_all()
            .map_err(|e| io_error("sync recovery restoration", destination, e))?;
        self.check_parent()?;
        let outside = leaf(&self.parent, &target, destination, false)?;
        if id(&outside, destination, false, true)? != self.identity
            || digest(&outside, destination)? != expected
        {
            return Err(changed(
                "restored recovery object changed on outside readback",
                destination,
            ));
        }
        match leaf(&self.parent, &self.name, &self.path, false) {
            Err(error) if absent(&error) => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(changed(
                "recovery source pathname reappeared after restoration; preserved",
                &self.path,
            )),
        }
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(in crate::state_files) fn replace(self, expected: [u8; 32], bytes: &[u8]) -> Result<()> {
        self.check()?;
        verify(&self.file, &self.path, expected)?;
        let random = super::super::random(&self.path)?;
        let suffix: String = se_types::hex_lower(&random);
        let stage_path = self
            .path
            .with_file_name(format!(".se-edit-backup-{suffix}"));
        let stage_name = name(
            stage_path
                .file_name()
                .ok_or_else(|| unsafe_path("staging leaf missing", &stage_path))?,
            &stage_path,
        )?;
        // SAFETY: same held parent and exclusive no-follow creation; no existing
        // entry is overwritten; inherited staging ACLs are cleared before writing.
        #[cfg(not(target_os = "macos"))]
        let mut stage = owned(
            unsafe {
                libc::openat(
                    self.parent.as_raw_fd(),
                    stage_name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            },
            "create owned profile staging",
            &stage_path,
        )?;
        #[cfg(target_os = "macos")]
        let stage = private_stage::create_profile(&stage_path, &self.file, |file| {
            file.write_all(bytes)
                .map_err(|e| io_error("write staged profile", &stage_path, e))
        })?;
        let stage_identity = id(&stage, &stage_path, false, true)?;
        let wanted: [u8; 32] = Sha256::digest(bytes).into();
        let mut swapped = false;
        let result = (|| {
            #[cfg(not(target_os = "macos"))]
            stage
                .write_all(bytes)
                .map_err(|e| io_error("write staged profile", &stage_path, e))?;
            let security = self
                .file
                .metadata()
                .map_err(|e| io_error("read original profile security", &self.path, e))?;
            metadata::copy(&self.file, &stage, &self.path)?;
            if self.private {
                super::super::metadata(&stage, &stage_path, false)?;
            }
            stage
                .sync_all()
                .map_err(|e| io_error("sync staged profile", &stage_path, e))?;
            self.check()?;
            verify(&self.file, &self.path, expected)?;
            self.check()?;
            let current_security = self
                .file
                .metadata()
                .map_err(|e| io_error("recheck profile security", &self.path, e))?;
            if metadata::stamp(&security) != metadata::stamp(&current_security) {
                return Err(changed(
                    "profile security changed before publication",
                    &self.path,
                ));
            }
            exchange(&self.parent, &stage_name, &self.name, &self.path)?;
            swapped = true;
            let displaced = leaf(&self.parent, &stage_name, &stage_path, false)?;
            let intact = id(&displaced, &stage_path, false, true)? == self.identity
                && digest(&displaced, &stage_path)? == expected;
            if !intact {
                let current = leaf(&self.parent, &self.name, &self.path, false)?;
                if id(&current, &self.path, false, true)? != stage_identity
                    || digest(&current, &self.path)? != wanted
                {
                    return Err(changed(
                        "profile raced with exchange; both versions retained",
                        &stage_path,
                    ));
                }
                exchange(&self.parent, &stage_name, &self.name, &self.path)?;
                swapped = false;
                self.parent
                    .sync_all()
                    .map_err(|e| io_error("sync rolled-back profile exchange", &self.path, e))?;
                return Err(changed(
                    "profile changed during atomic exchange; original restored",
                    &self.path,
                ));
            }
            self.parent
                .sync_all()
                .map_err(|e| io_error("sync profile replacement", &self.path, e))?;
            self.check_parent()?;
            let observed = leaf(&self.parent, &self.name, &self.path, false)?;
            if id(&observed, &self.path, false, true)? != id(&stage, &stage_path, false, true)?
                || digest(&observed, &self.path)? != <[u8; 32]>::from(Sha256::digest(bytes))
            {
                return Err(changed("profile replacement readback differs", &self.path));
            }
            if self.private {
                super::super::metadata(&observed, &self.path, false)?;
            }
            // SAFETY: the displaced entry's exact identity and digest were checked
            // after atomic exchange; unlink only that held original name.
            if unsafe { libc::unlinkat(self.parent.as_raw_fd(), stage_name.as_ptr(), 0) } < 0 {
                return Err(io_error(
                    "remove displaced original profile",
                    &stage_path,
                    io::Error::last_os_error(),
                ));
            }
            let retired = self
                .file
                .metadata()
                .map_err(|e| io_error("read displaced original link count", &stage_path, e))?;
            if retired.nlink() != 0 {
                return Err(changed(
                    "profile exchange did not retire the held original",
                    &stage_path,
                ));
            }
            if !matches!(digest(&self.file, &self.path), Ok(value) if value == expected) {
                let (retained_path, retained_name) = recovery_name(&self.path)?;
                self.retain_raced_bytes(&retained_path, &retained_name)?;
                return Err(changed(
                    "profile changed through an open displaced handle; recovery copy retained",
                    &retained_path,
                ));
            }
            self.parent
                .sync_all()
                .map_err(|e| io_error("sync retired profile sibling", &self.path, e))?;
            Ok(())
        })();
        // An uncertain exchange retains both versions. After a successful rollback,
        // only our original staging object is eligible for cleanup.
        // SAFETY: this random O_EXCL-created literal name belongs to this operation.
        if result.is_err() && !swapped {
            let cleanup = leaf(&self.parent, &stage_name, &stage_path, false)?;
            if id(&cleanup, &stage_path, false, true)? != stage_identity {
                return Err(changed(
                    "profile staging changed before cleanup",
                    &stage_path,
                ));
            }
        }
        // SAFETY: only the checked uniquely-created staging entry is removed.
        if result.is_err()
            && !swapped
            // SAFETY: retained parent descriptor and NUL-terminated staging leaf;
            // this removes only the validated staging name within that parent.
            && unsafe { libc::unlinkat(self.parent.as_raw_fd(), stage_name.as_ptr(), 0) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::NotFound
        {
            return Err(io_error(
                "cleanup owned profile staging failed",
                &stage_path,
                io::Error::last_os_error(),
            ));
        }
        result
    }
}
