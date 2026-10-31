use super::*;
use std::{
    ffi::{CString, OsStr},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Component,
};

pub(super) struct Directory {
    file: File,
    identity: (u64, u64),
}
fn name(value: &OsStr, path: &Path) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| unsafe_path("NUL in native path", path))
}
fn owned(raw: i32, operation: &'static str, path: &Path) -> Result<File> {
    if raw < 0 {
        return Err(io_error(operation, path, io::Error::last_os_error()));
    }
    // SAFETY: native allocation succeeded and supplies one uniquely owned FD.
    Ok(unsafe { File::from_raw_fd(raw) })
}
fn metadata(file: &File, path: &Path, directory: bool) -> Result<std::fs::Metadata> {
    let meta = file
        .metadata()
        .map_err(|e| io_error("read pinned metadata", path, e))?;
    // SAFETY: geteuid has no pointers or process-wide mutation.
    if meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || (!directory && meta.nlink() != 1)
        || if directory {
            !meta.is_dir()
        } else {
            !meta.is_file()
        }
    {
        return Err(unsafe_path(
            "require owner-only native regular file/directory",
            path,
        ));
    }
    Ok(meta)
}
fn components(path: &Path) -> Result<Vec<&OsStr>> {
    if !path.is_absolute() {
        return Err(unsafe_path("absolute state path required", path));
    }
    path.components()
        .filter(|c| !matches!(c, Component::RootDir))
        .map(|c| match c {
            Component::Normal(n) => Ok(n),
            _ => Err(unsafe_path("normalized state path required", path)),
        })
        .collect()
}
fn walk(path: &Path, create: bool) -> Result<File> {
    let root = CString::new("/").map_err(|_| unsafe_path("native root", path))?;
    // SAFETY: constant path, successful open supplies an independently owned FD.
    let mut parent = owned(
        unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        },
        "open filesystem root",
        path,
    )?;
    let parts = components(path)?;
    let mut private = false;
    for (index, value) in parts.iter().enumerate() {
        let component = name(value, path)?;
        let mut created = false;
        if create {
            // SAFETY: single literal component relative to the held parent FD.
            let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) };
            created = rc == 0;
            if !created && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io_error(
                    "create private directory",
                    path,
                    io::Error::last_os_error(),
                ));
            }
        }
        private |= created || index + 1 == parts.len();
        // SAFETY: initialized writable stat output and held parent/component.
        let mut link: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: no-follow stat inspects the actual named directory entry.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                component.as_ptr(),
                &mut link,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } < 0
        {
            return Err(io_error(
                "inspect directory entry",
                path,
                io::Error::last_os_error(),
            ));
        }
        let symlink = link.st_mode & libc::S_IFMT == libc::S_IFLNK;
        // SAFETY: geteuid reads the current native user without side effects.
        let user = unsafe { libc::geteuid() };
        if symlink && (private || (link.st_uid != 0 && link.st_uid != user)) {
            return Err(unsafe_path("untrusted or private-directory symlink", path));
        }
        // SAFETY: held parent and one component; only an inspected trusted system
        // ancestor may be followed. Final and newly owned components never are.
        let next = owned(
            unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_DIRECTORY
                        | libc::O_CLOEXEC
                        | if symlink { 0 } else { libc::O_NOFOLLOW },
                )
            },
            "open native directory",
            path,
        )?;
        if created {
            // SAFETY: chmod the just-opened owned directory, never its pathname.
            if unsafe { libc::fchmod(next.as_raw_fd(), 0o700) } < 0 {
                return Err(io_error(
                    "protect newly created directory",
                    path,
                    io::Error::last_os_error(),
                ));
            }
            parent
                .sync_all()
                .map_err(|e| io_error("sync newly created directory parent", path, e))?;
        }
        if private {
            metadata(&next, path, true)?;
        } else if symlink {
            let meta = next
                .metadata()
                .map_err(|e| io_error("inspect system ancestor", path, e))?;
            if meta.uid() != 0 && meta.uid() != user {
                return Err(unsafe_path(
                    "system ancestor owner is not root or current user",
                    path,
                ));
            }
        }
        parent = next;
    }
    Ok(parent)
}

pub(super) fn random(path: &Path) -> Result<[u8; 16]> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| io_error("native staging entropy", path, e))?;
    Ok(bytes)
}
pub(super) fn identity(file: &File, path: &Path) -> Result<(u64, u64)> {
    let meta = metadata(file, path, false)?;
    Ok((meta.dev(), meta.ino()))
}
pub(super) fn create_directories(path: &Path) -> Result<()> {
    let file = walk(path, true)?;
    metadata(&file, path, true)?;
    file.sync_all()
        .map_err(|e| io_error("sync private directory", path, e))
}
impl Directory {
    pub fn open(path: &Path) -> Result<Self> {
        let file = walk(path, false)?;
        let meta = metadata(&file, path, true)?;
        Ok(Self {
            file,
            identity: (meta.dev(), meta.ino()),
        })
    }
    pub fn check_name(&self, path: &Path) -> Result<()> {
        let observed = Self::open(path)?;
        if observed.identity != self.identity {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "held state root was replaced",
                path,
            ));
        }
        metadata(&self.file, path, true)?;
        Ok(())
    }
    fn directory(&self, path: &Path, root: &Path) -> Result<File> {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| unsafe_path("directory outside root", path))?;
        let mut file = self
            .file
            .try_clone()
            .map_err(|e| io_error("duplicate directory pin", path, e))?;
        for component in relative.components() {
            let Component::Normal(component) = component else {
                return Err(unsafe_path("normalized relative directory required", path));
            };
            let component = name(component, path)?;
            // SAFETY: single normal component relative to a pinned private FD; links refused.
            file = owned(
                unsafe {
                    libc::openat(
                        file.as_raw_fd(),
                        component.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                },
                "open protected subdirectory",
                path,
            )?;
            metadata(&file, path, true)?;
        }
        Ok(file)
    }
    fn parent(&self, path: &Path, root: &Path) -> Result<(File, CString)> {
        let parent = path
            .parent()
            .ok_or_else(|| unsafe_path("file parent missing", path))?;
        let name = name(
            path.file_name()
                .ok_or_else(|| unsafe_path("file name missing", path))?,
            path,
        )?;
        Ok((self.directory(parent, root)?, name))
    }
    pub fn create_staging_at(&self, path: &Path, root: &Path) -> Result<File> {
        let (parent, name) = self.parent(path, root)?;
        // SAFETY: private held parent, one native name, atomic exclusive creation.
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        let file = owned(raw, "create protected staging file", path)?;
        // SAFETY: newly created unique regular-file descriptor, no path mutation.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } < 0 {
            return Err(io_error(
                "protect staging mode",
                path,
                io::Error::last_os_error(),
            ));
        }
        metadata(&file, path, false)?;
        parent
            .sync_all()
            .map_err(|e| io_error("sync staging parent", path, e))?;
        Ok(file)
    }
    pub fn open_for_publication(&self, path: &Path, root: &Path) -> Result<File> {
        self.readback(path, root)?
            .ok_or_else(|| io_error("staging file absent", path, io::ErrorKind::NotFound.into()))
    }
    pub fn readback(&self, path: &Path, root: &Path) -> Result<Option<File>> {
        let (parent, name) = match self.parent(path, root) {
            Ok(v) => v,
            Err(e)
                if e.source
                    .as_ref()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        // SAFETY: pinned parent and native component; no-follow and nonblocking
        // flags reject links and prevent substituted FIFOs from blocking.
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        let file = owned(raw, "open published file without following links", path)?;
        metadata(&file, path, false)?;
        Ok(Some(file))
    }
    pub fn publish(
        &self,
        staged: &Path,
        destination: &Path,
        root: &Path,
        _source: &File,
    ) -> Result<()> {
        let (from, from_name) = self.parent(staged, root)?;
        let (to, to_name) = self.parent(destination, root)?;
        #[cfg(target_os = "linux")]
        // SAFETY: held parent FDs and NUL-terminated single names; no replacement.
        let renamed = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                from.as_raw_fd(),
                from_name.as_ptr(),
                to.as_raw_fd(),
                to_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        // SAFETY: descriptor-relative native rename, RENAME_EXCL is atomic no-replace.
        let renamed = unsafe {
            libc::renameatx_np(
                from.as_raw_fd(),
                from_name.as_ptr(),
                to.as_raw_fd(),
                to_name.as_ptr(),
                libc::RENAME_EXCL,
            )
        } as i64;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(failure(
            StateFileErrorCode::Unsupported,
            "atomic native no-replace rename unavailable",
            destination,
        ));
        if renamed < 0 {
            return Err(io_error(
                "native no-replace publication",
                destination,
                io::Error::last_os_error(),
            ));
        }
        to.sync_all()
            .map_err(|e| io_error("sync publication parent", destination, e))?;
        from.sync_all()
            .map_err(|e| io_error("sync staging parent after rename", staged, e))?;
        Ok(())
    }
}
