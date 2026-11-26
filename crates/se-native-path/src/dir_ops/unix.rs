//! Unix `openat`/`fdopendir`/`statx`/`unlinkat` handle-anchored directory ops.
use super::{ChildInfo, ChildKind, DeleteChildError, DirOpError, NodeId};
use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fs::File,
    io::{self, Read, Write},
    mem::zeroed,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::Path,
};

pub(super) struct DirHandle {
    fd: OwnedFd,
}

fn c_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))
}

fn c_literal_name(name: &OsStr) -> io::Result<CString> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "child entry must be a single literal name",
        ));
    }
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL byte"))
}

fn map_open_err(err: io::Error) -> DirOpError {
    match err.raw_os_error() {
        Some(libc::ENOENT) => DirOpError::NotFound,
        Some(libc::ELOOP) => DirOpError::Link("symlink"),
        Some(libc::ENOTDIR) => DirOpError::NotDir,
        _ => DirOpError::Io(err),
    }
}

#[cfg(target_os = "linux")]
fn statx_query(
    dirfd: libc::c_int,
    name: &CStr,
    flags: libc::c_int,
) -> io::Result<Option<ChildInfo>> {
    // SAFETY: zeroed `libc::statx` is valid POD for the kernel to populate.
    let mut stx: libc::statx = unsafe { zeroed() };
    let mask = libc::STATX_BASIC_STATS | libc::STATX_MNT_ID;
    // SAFETY: `dirfd` is a valid open directory fd, `name` is NUL-terminated,
    // and `&mut stx` is a valid writable `libc::statx` buffer.
    let rc = unsafe { libc::statx(dirfd, name.as_ptr(), flags, mask, &mut stx) };
    if rc < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOSYS) {
            return Ok(None);
        }
        return Err(err);
    }
    let dev = libc::makedev(stx.stx_dev_major, stx.stx_dev_minor) as u64;
    let mount_id = if stx.stx_mask & libc::STATX_MNT_ID != 0 {
        Some(stx.stx_mnt_id)
    } else {
        None
    };
    let is_mount_root = (stx.stx_attributes_mask & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0)
        && (stx.stx_attributes & libc::STATX_ATTR_MOUNT_ROOT as u64 != 0);
    let kind = mode_to_kind(libc::mode_t::from(stx.stx_mode));
    Ok(Some(ChildInfo {
        kind,
        id: NodeId {
            dev,
            ino: stx.stx_ino,
            mount_id,
        },
        is_mount_root,
    }))
}

fn mode_to_kind(mode: libc::mode_t) -> ChildKind {
    match mode & libc::S_IFMT {
        libc::S_IFREG => ChildKind::File,
        libc::S_IFDIR => ChildKind::Dir,
        libc::S_IFLNK => ChildKind::Link("symlink"),
        _ => ChildKind::Other,
    }
}

fn fstat_fd(fd: libc::c_int) -> io::Result<ChildInfo> {
    #[cfg(target_os = "linux")]
    if let Some(info) = statx_query(fd, c"", libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW)? {
        return Ok(info);
    }
    // SAFETY: zeroed `libc::stat` is valid POD for `fstat`.
    let mut st: libc::stat = unsafe { zeroed() };
    // SAFETY: `fd` is a valid open file descriptor and `&mut st` is writable.
    if unsafe { libc::fstat(fd, &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ChildInfo {
        kind: mode_to_kind(st.st_mode),
        id: NodeId {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            mount_id: None,
        },
        is_mount_root: false,
    })
}

fn fstatat_child(dirfd: libc::c_int, name: &CStr) -> Result<ChildInfo, DirOpError> {
    #[cfg(target_os = "linux")]
    match statx_query(dirfd, name, libc::AT_SYMLINK_NOFOLLOW) {
        Ok(Some(info)) => return Ok(info),
        Ok(None) => {}
        Err(err) => return Err(map_open_err(err)),
    }
    // SAFETY: zeroed `libc::stat` is valid POD for `fstatat`.
    let mut st: libc::stat = unsafe { zeroed() };
    // SAFETY: `dirfd` is a live directory fd, `name` is NUL-terminated.
    if unsafe { libc::fstatat(dirfd, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } < 0 {
        return Err(map_open_err(io::Error::last_os_error()));
    }
    Ok(ChildInfo {
        kind: mode_to_kind(st.st_mode),
        id: NodeId {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            mount_id: None,
        },
        is_mount_root: false,
    })
}

impl DirHandle {
    pub(super) fn open_root(path: &Path) -> Result<Self, DirOpError> {
        let cpath = c_path(path).map_err(DirOpError::Io)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: `cpath` is NUL-terminated and flags open an existing directory read-only.
        let raw = unsafe { libc::open(cpath.as_ptr(), flags) };
        if raw < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOTDIR)
                && let Ok(info) = fstatat_child(libc::AT_FDCWD, &cpath)
                && let ChildKind::Link(kind) = info.kind
            {
                return Err(DirOpError::Link(kind));
            }
            return Err(map_open_err(err));
        }
        // SAFETY: `open` succeeded and returned a uniquely owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self { fd })
    }

    pub(super) fn open_child_dir(&self, name: &OsStr) -> Result<Self, DirOpError> {
        let cname = c_literal_name(name).map_err(DirOpError::Io)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: `self.fd` is a valid directory fd and `cname` is a single literal name.
        let raw = unsafe { libc::openat(self.fd.as_raw_fd(), cname.as_ptr(), flags) };
        if raw < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOTDIR)
                && let Ok(info) = fstatat_child(self.fd.as_raw_fd(), &cname)
                && let ChildKind::Link(kind) = info.kind
            {
                return Err(DirOpError::Link(kind));
            }
            return Err(map_open_err(err));
        }
        // SAFETY: `openat` succeeded and returned a uniquely owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self { fd })
    }

    pub(super) fn stat_self(&self) -> io::Result<(NodeId, bool)> {
        let info = fstat_fd(self.fd.as_raw_fd())?;
        Ok((info.id, info.is_mount_root))
    }

    pub(super) fn read_entries(&self) -> io::Result<Vec<OsString>> {
        // Duplicate the fd so `closedir` does not close `self.fd`, and rewind
        // the duplicated stream to offset 0 before iterating.
        // SAFETY: `self.fd` is a valid open directory fd.
        let dup_raw = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if dup_raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `dup_raw` is an owned directory fd; `fdopendir` takes ownership on success.
        let dirp = unsafe { libc::fdopendir(dup_raw) };
        if dirp.is_null() {
            let err = io::Error::last_os_error();
            // SAFETY: `fdopendir` failed so we still own `dup_raw`.
            unsafe {
                libc::close(dup_raw);
            }
            return Err(err);
        }
        // SAFETY: `dirp` is a valid `DIR*` stream.
        unsafe {
            libc::rewinddir(dirp);
        }
        let mut names = Vec::new();
        let read_res = loop {
            // Clear errno before each `readdir` call to distinguish EOF from error.
            set_errno(0);
            // SAFETY: `dirp` is a valid open `DIR*`.
            let entry = unsafe { libc::readdir(dirp) };
            if entry.is_null() {
                let err = io::Error::last_os_error();
                if err.raw_os_error().unwrap_or(0) != 0 {
                    break Err(err);
                }
                break Ok(());
            }
            // SAFETY: `entry` is non-null and `d_name` is a NUL-terminated C string.
            let cstr = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let bytes = cstr.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            names.push(OsString::from_vec(bytes.to_vec()));
        };
        // SAFETY: `dirp` is owned and closed exactly once.
        unsafe {
            libc::closedir(dirp);
        }
        read_res?;
        Ok(names)
    }

    pub(super) fn inspect_child(&self, name: &OsStr) -> Result<ChildInfo, DirOpError> {
        let cname = c_literal_name(name).map_err(DirOpError::Io)?;
        fstatat_child(self.fd.as_raw_fd(), &cname)
    }

    pub(super) fn read_child_file(
        &self,
        name: &OsStr,
        max_bytes: usize,
    ) -> Result<Vec<u8>, DirOpError> {
        let cname = c_literal_name(name).map_err(DirOpError::Io)?;
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: `self.fd` is a valid directory fd and `cname` is a single literal name.
        let raw = unsafe { libc::openat(self.fd.as_raw_fd(), cname.as_ptr(), flags) };
        if raw < 0 {
            return Err(map_open_err(io::Error::last_os_error()));
        }
        // SAFETY: `openat` succeeded and transferred one unique fd.
        let mut file = unsafe { File::from_raw_fd(raw) };
        let info = fstat_fd(file.as_raw_fd()).map_err(DirOpError::Io)?;
        if info.kind != ChildKind::File {
            return Err(DirOpError::Io(io::Error::other("not a regular file")));
        }
        let mut buf = Vec::new();
        Read::take(&mut file, (max_bytes as u64).saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(DirOpError::Io)?;
        if buf.len() > max_bytes {
            return Err(DirOpError::Io(io::Error::other(
                "file exceeds maximum read limit",
            )));
        }
        Ok(buf)
    }

    pub(super) fn create_child_file_exclusive(&self, name: &OsStr, bytes: &[u8]) -> io::Result<()> {
        let cname = c_literal_name(name)?;
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: `self.fd` is a valid directory fd and `cname` is a single literal name.
        let raw = unsafe { libc::openat(self.fd.as_raw_fd(), cname.as_ptr(), flags, 0o600) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` succeeded and transferred one unique fd.
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(bytes)?;
        file.sync_data()?;
        Ok(())
    }

    pub(super) fn unlink_child_file(
        &self,
        name: &OsStr,
        expected_id: Option<NodeId>,
    ) -> Result<(), DeleteChildError> {
        let cname = c_literal_name(name).map_err(DeleteChildError::Io)?;
        let info = fstatat_child(self.fd.as_raw_fd(), &cname).map_err(|err| match err {
            DirOpError::Link(k) => DeleteChildError::Link(k),
            DirOpError::Io(e) => DeleteChildError::Io(e),
            DirOpError::NotFound => {
                DeleteChildError::Io(io::Error::from_raw_os_error(libc::ENOENT))
            }
            DirOpError::NotDir => DeleteChildError::Io(io::Error::from_raw_os_error(libc::ENOTDIR)),
        })?;
        if let ChildKind::Link(kind) = info.kind {
            return Err(DeleteChildError::Link(kind));
        }
        if let Some(expected) = expected_id
            && info.id != expected
        {
            return Err(DeleteChildError::IdentityMismatch);
        }
        // SAFETY: `self.fd` is a valid directory fd and `cname` is a single literal name.
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), cname.as_ptr(), 0) } < 0 {
            return Err(DeleteChildError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    pub(super) fn remove_child_dir(
        &self,
        name: &OsStr,
        expected_id: Option<NodeId>,
    ) -> Result<(), DeleteChildError> {
        let cname = c_literal_name(name).map_err(DeleteChildError::Io)?;
        let info = fstatat_child(self.fd.as_raw_fd(), &cname).map_err(|err| match err {
            DirOpError::Link(k) => DeleteChildError::Link(k),
            DirOpError::Io(e) => DeleteChildError::Io(e),
            DirOpError::NotFound => {
                DeleteChildError::Io(io::Error::from_raw_os_error(libc::ENOENT))
            }
            DirOpError::NotDir => DeleteChildError::Io(io::Error::from_raw_os_error(libc::ENOTDIR)),
        })?;
        if let ChildKind::Link(kind) = info.kind {
            return Err(DeleteChildError::Link(kind));
        }
        if info.is_mount_root {
            return Err(DeleteChildError::Link("mount point / bind mount"));
        }
        if let Some(expected) = expected_id
            && info.id != expected
        {
            return Err(DeleteChildError::IdentityMismatch);
        }
        // SAFETY: `self.fd` is a valid directory fd and `cname` is a single literal name.
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), cname.as_ptr(), libc::AT_REMOVEDIR) } < 0 {
            return Err(DeleteChildError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    pub(super) fn can_modify_entries(&self) -> io::Result<bool> {
        // SAFETY: `self.fd` is a valid open directory fd and "." is NUL-terminated.
        let rc = unsafe {
            libc::faccessat(
                self.fd.as_raw_fd(),
                c".".as_ptr(),
                libc::W_OK | libc::X_OK,
                0,
            )
        };
        if rc == 0 {
            return Ok(true);
        }
        let err = io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(libc::EACCES | libc::EROFS | libc::EPERM)
        ) {
            return Ok(false);
        }
        Err(err)
    }
}

fn set_errno(value: libc::c_int) {
    #[cfg(target_os = "linux")]
    // SAFETY: `__errno_location` returns the thread-local errno pointer.
    unsafe {
        *libc::__errno_location() = value;
    }
    #[cfg(target_os = "macos")]
    // SAFETY: `__error` returns the thread-local errno pointer.
    unsafe {
        *libc::__error() = value;
    }
}
