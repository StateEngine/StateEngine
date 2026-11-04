use super::*;
use std::{
    ffi::CString,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
};

pub(super) fn open_root(path: &Path) -> io::Result<File> {
    let path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| invalid("NUL in source root"))?;
    // SAFETY: terminated path, read-only directory flags; ownership transfers
    // only on a nonnegative descriptor. O_NOFOLLOW protects the registered leaf.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned(fd)
}
pub(super) fn open_relative(root: &File, path: &str) -> io::Result<File> {
    let mut directory = root.try_clone()?;
    let mut components = path.split('/').peekable();
    while let Some(part) = components.next() {
        let name = CString::new(part).map_err(|_| invalid("NUL in source component"))?;
        let is_directory = components.peek().is_some();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if is_directory {
                libc::O_DIRECTORY
            } else {
                libc::O_NONBLOCK
            };
        // SAFETY: live retained directory and one validated relative component;
        // no link traversal, creation, writes or inherited descriptors.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        let child = owned(fd)?;
        revision(&child, is_directory)?;
        directory = child;
    }
    Ok(directory)
}
fn owned(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful native open transferred this uniquely owned fd.
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(super) fn revision(file: &File, directory: bool) -> io::Result<NativeFileRevision> {
    let m = file.metadata()?;
    if (directory && !m.is_dir()) || (!directory && !m.is_file()) {
        return Err(invalid(
            "regular source file or directory required; links and devices refused",
        ));
    }
    let mut volume = [0; 16];
    let mut id = [0; 16];
    volume[..8].copy_from_slice(&m.dev().to_be_bytes());
    id[..8].copy_from_slice(&m.ino().to_be_bytes());
    Ok(NativeFileRevision {
        volume,
        file: id,
        size: m.len(),
        mtime_unix_nanos: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
        ctime_unix_nanos: Some(i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec())),
    })
}
