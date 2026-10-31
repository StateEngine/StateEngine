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
    // SAFETY: constant pathname, no inherited descriptor; flags reject links.
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
    for component in components(path)? {
        let component = name(component, path)?;
        if create {
            // SAFETY: native relative component below the held directory; an
            // existing name is only read later, never chmodded or replaced.
            let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o700) };
            if rc == 0 {
                // Explicit mode on the just-created directory removes ambient
                // umask from the contract. Its parent is held throughout.
                if unsafe { libc::fchmodat(parent.as_raw_fd(), component.as_ptr(), 0o700, 0) } < 0 {
                    return Err(io_error(
                        "protect newly created directory",
                        path,
                        io::Error::last_os_error(),
                    ));
                }
                parent
                    .sync_all()
                    .map_err(|e| io_error("sync newly created directory parent", path, e))?;
            } else if io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io_error(
                    "create private directory",
                    path,
                    io::Error::last_os_error(),
                ));
            }
        }
        // SAFETY: held parent, single literal component, O_NOFOLLOW for every
        // component rather than only the final absolute pathname.
        parent = owned(
            unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            },
            "open directory without following links",
            path,
        )?;
    }
    Ok(parent)
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
    pub fn create_staging(&self, directory: &Path, root: &Path) -> Result<ProtectedStateStaging> {
        let parent = self.directory(directory, root)?;
        for _ in 0..8 {
            let mut random = [0; 16];
            File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut random))
                .map_err(|e| io_error("native staging entropy", directory, e))?;
            let file_name = format!(
                ".se-stage-{}",
                random
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            let path = directory.join(&file_name);
            let c_name = name(OsStr::new(&file_name), &path)?;
            let raw = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if raw < 0 && io::Error::last_os_error().kind() == io::ErrorKind::AlreadyExists {
                continue;
            }
            let file = owned(raw, "create protected staging file", &path)?;
            // SAFETY: uniquely created file FD, no path-based permission change.
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } < 0 {
                return Err(io_error(
                    "protect staging mode",
                    &path,
                    io::Error::last_os_error(),
                ));
            }
            metadata(&file, &path, false)?;
            parent
                .sync_all()
                .map_err(|e| io_error("sync staging parent", directory, e))?;
            return Ok(ProtectedStateStaging { path, file });
        }
        Err(failure(
            StateFileErrorCode::AlreadyExists,
            "native staging name collisions",
            directory,
        ))
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
        // Nonblocking open prevents a substituted FIFO/device from hanging a
        // host worker before fstat rejects the non-regular object.
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
    pub fn publish(&self, staged: &Path, destination: &Path, root: &Path) -> Result<()> {
        let source = self.readback(staged, root)?.ok_or_else(|| {
            io_error(
                "staging file absent",
                staged,
                io::Error::from(io::ErrorKind::NotFound),
            )
        })?;
        source
            .sync_all()
            .map_err(|e| io_error("sync staged data", staged, e))?;
        let before = metadata(&source, staged, false)?;
        let (from, from_name) = self.parent(staged, root)?;
        let (to, to_name) = self.parent(destination, root)?;
        #[cfg(target_os = "linux")]
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
        #[cfg(target_os = "linux")]
        let fallback =
            renamed < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS);
        #[cfg(not(target_os = "linux"))]
        let fallback = true;
        if fallback {
            // linkat without AT_SYMLINK_FOLLOW is atomic no-replace. The caller
            // owns a closed SQLite file in the same filesystem/private root.
            if unsafe {
                libc::linkat(
                    from.as_raw_fd(),
                    from_name.as_ptr(),
                    to.as_raw_fd(),
                    to_name.as_ptr(),
                    0,
                )
            } < 0
            {
                return Err(io_error(
                    "publish without replacement",
                    destination,
                    io::Error::last_os_error(),
                ));
            }
            if unsafe { libc::unlinkat(from.as_raw_fd(), from_name.as_ptr(), 0) } < 0 {
                return Err(io_error(
                    "retire staging name after publication",
                    staged,
                    io::Error::last_os_error(),
                ));
            }
        }
        #[cfg(target_os = "linux")]
        if !fallback && renamed < 0 {
            return Err(io_error(
                "renameat2 no-replace publication",
                destination,
                io::Error::last_os_error(),
            ));
        }
        to.sync_all()
            .map_err(|e| io_error("sync publication parent", destination, e))?;
        from.sync_all()
            .map_err(|e| io_error("sync staging parent after rename", staged, e))?;
        let published = self.readback(destination, root)?.ok_or_else(|| {
            failure(
                StateFileErrorCode::SourceChanged,
                "published file absent on readback",
                destination,
            )
        })?;
        let after = metadata(&published, destination, false)?;
        if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "publication identity changed",
                destination,
            ));
        }
        if self.readback(staged, root)?.is_some() {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "staging name remained after publication",
                staged,
            ));
        }
        Ok(())
    }
}
