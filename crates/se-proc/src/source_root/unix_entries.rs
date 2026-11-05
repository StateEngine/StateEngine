//! One retained native DIR stream, not a pathname walk or a collected listing.
use super::*;
use std::{
    ffi::CStr,
    os::{fd::IntoRawFd, unix::ffi::OsStringExt},
    ptr::NonNull,
};
pub(super) struct Cursor(NonNull<libc::DIR>);
// SAFETY: this exclusively owned DIR is accessed only through &mut self and is
// never shared. POSIX directory streams have no creating-thread affinity.
unsafe impl Send for Cursor {}
impl Cursor {
    pub(super) fn new(file: &File) -> io::Result<Self> {
        let descriptor = file.try_clone()?.into_raw_fd();
        // SAFETY: descriptor is uniquely owned here; fdopendir consumes it only
        // on success. Cursor::drop then closes the stream and its descriptor.
        let raw = unsafe { libc::fdopendir(descriptor) };
        if let Some(pointer) = NonNull::new(raw) {
            Ok(Self(pointer))
        } else {
            let error = io::Error::last_os_error();
            // SAFETY: fdopendir failed and left our original descriptor open.
            unsafe { libc::close(descriptor) };
            Err(error)
        }
    }
    pub(super) fn next(&mut self) -> io::Result<Option<NativeSourceEntry>> {
        loop {
            // readdir distinguishes EOF from error through errno. errno is
            // thread-local, and this exact call has exclusive stream access.
            #[cfg(target_os = "linux")]
            // SAFETY: libc returns this thread's live errno location.
            unsafe {
                *libc::__errno_location() = 0;
            }
            #[cfg(target_os = "macos")]
            // SAFETY: libc returns this thread's live errno location.
            unsafe {
                *libc::__error() = 0;
            }
            // SAFETY: live exclusively owned DIR; returned bytes are copied
            // before another readdir call can invalidate the native storage.
            let entry = unsafe { libc::readdir(self.0.as_ptr()) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                return if error.raw_os_error() == Some(0) {
                    Ok(None)
                } else {
                    Err(error)
                };
            }
            // SAFETY: the OS supplies a NUL-terminated d_name in this live row.
            let row = unsafe { &*entry };
            // SAFETY: the kernel's d_name is NUL-terminated in this live row.
            let native_name = unsafe { CStr::from_ptr(row.d_name.as_ptr()) };
            let name = native_name.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let kind = match row.d_type {
                libc::DT_REG => NativeSourceKind::File,
                libc::DT_DIR => NativeSourceKind::Directory,
                libc::DT_LNK => NativeSourceKind::Link,
                libc::DT_UNKNOWN => {
                    // SAFETY: one native entry relative to this held directory,
                    // with link following disabled and initialized stat output.
                    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                    // SAFETY: live exclusively owned directory stream.
                    let descriptor = unsafe { libc::dirfd(self.0.as_ptr()) };
                    // SAFETY: valid output and a NUL-terminated single name;
                    // AT_SYMLINK_NOFOLLOW preserves link/device classification.
                    if unsafe {
                        libc::fstatat(
                            descriptor,
                            native_name.as_ptr(),
                            &mut stat,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    } < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    match stat.st_mode & libc::S_IFMT {
                        libc::S_IFREG => NativeSourceKind::File,
                        libc::S_IFDIR => NativeSourceKind::Directory,
                        libc::S_IFLNK => NativeSourceKind::Link,
                        _ => NativeSourceKind::Other,
                    }
                }
                _ => NativeSourceKind::Other,
            };
            return Ok(Some(NativeSourceEntry {
                name: std::ffi::OsString::from_vec(name.to_vec()),
                kind,
            }));
        }
    }
}
impl Drop for Cursor {
    fn drop(&mut self) {
        // SAFETY: this is the sole close of the stream owned since fdopendir.
        unsafe { libc::closedir(self.0.as_ptr()) };
    }
}
