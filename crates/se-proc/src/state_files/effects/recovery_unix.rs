//! Finite inventory only: a recovery filename never grants mutation authority.
use super::*;
use std::{
    ffi::CStr,
    os::{fd::FromRawFd, unix::ffi::OsStringExt},
};

pub(in crate::state_files) fn scan_recovery(path: &Path) -> Result<Vec<PathBuf>> {
    let parent = super::super::walk_effect_parent(path)?;
    let before = parent
        .metadata()
        .map_err(|e| io_error("inspect recovery directory", path, e))?;
    // SAFETY: duplicate a retained directory with close-on-exec; fdopendir owns
    // the duplicate alone and cannot close the original custody descriptor.
    let raw = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io_error(
            "duplicate recovery directory",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: uniquely owned duplicated descriptor and native directory output.
    let stream = unsafe { libc::fdopendir(raw) };
    if stream.is_null() {
        // SAFETY: failed fdopendir did not consume this uniquely owned FD.
        drop(unsafe { File::from_raw_fd(raw) });
        return Err(io_error(
            "open recovery inventory",
            path,
            io::Error::last_os_error(),
        ));
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            // SAFETY: exclusively owned native directory stream.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let stream = Stream(stream);
    let mut found = Vec::new();
    let mut count = 0;
    loop {
        // SAFETY: native thread-local errno, cleared to distinguish EOF/error.
        unsafe {
            #[cfg(target_os = "linux")]
            {
                *libc::__errno_location() = 0;
            }
            #[cfg(target_os = "macos")]
            {
                *libc::__error() = 0;
            }
        }
        // SAFETY: live exclusively owned stream; returned record copied before next call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(0) {
                return Err(io_error("read recovery directory", path, error));
            }
            break;
        }
        count += 1;
        if count > 4096 {
            return Err(unsafe_path(
                "recovery scan exceeds 4096 directory entries",
                path,
            ));
        }
        // SAFETY: readdir supplies a terminated d_name valid until next call.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name.starts_with(b".se-edit-backup-") {
            if found.len() == 256 {
                return Err(unsafe_path("recovery inventory exceeds 256 siblings", path));
            }
            found.push(path.join(std::ffi::OsString::from_vec(name.to_vec())));
        }
    }
    let outside = super::super::walk_effect_parent(path)?;
    let after = outside
        .metadata()
        .map_err(|e| io_error("recheck recovery directory", path, e))?;
    if (
        before.dev(),
        before.ino(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err(changed("recovery directory changed while scanning", path));
    }
    found.sort();
    Ok(found)
}
