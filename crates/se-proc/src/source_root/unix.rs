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
    open_components(root, path, false)
}
pub(super) fn open_directory(root: &File, path: &str) -> io::Result<File> {
    open_components(root, if path.is_empty() { "." } else { path }, true)
}
pub(super) fn open_component(parent: &File, part: &str, is_directory: bool) -> io::Result<File> {
    let name = CString::new(part).map_err(|_| invalid("NUL in source component"))?;
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
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    let child = owned(fd)?;
    let m = child.metadata()?;
    if (is_directory && !m.is_dir()) || (!is_directory && !m.is_file()) {
        return Err(invalid(
            "regular source file or directory required; links and devices refused",
        ));
    }
    Ok(child)
}
fn open_components(root: &File, path: &str, last_directory: bool) -> io::Result<File> {
    let mut held: Option<File> = None;
    let mut components = path.split('/').peekable();
    while let Some(part) = components.next() {
        let is_directory = components.peek().is_some() || last_directory;
        let parent = held.as_ref().unwrap_or(root);
        held = Some(open_component(parent, part, is_directory)?);
    }
    held.ok_or_else(|| invalid("bounded slash-separated root-relative source path required"))
}
fn owned(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful native open transferred this uniquely owned fd.
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(super) fn same_object(a: &File, b: &File) -> io::Result<bool> {
    let ma = a.metadata()?;
    let mb = b.metadata()?;
    Ok(ma.dev() == mb.dev() && ma.ino() == mb.ino())
}
pub(super) fn revision(file: &File, directory: bool) -> io::Result<NativeFileRevision> {
    se_state_files::observe_file_revision_for(file, directory)
}
