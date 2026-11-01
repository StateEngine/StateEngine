//! Explicit platform paths; no ambient environment or authority lives here.
use super::*;
use sha2::{Digest, Sha256};
use std::{ffi::CString, os::fd::AsRawFd};

/// The executable collects these platform inputs. Embedded callers supply
/// their own; absence selects the state home's protected `run` directory.
#[derive(Clone, Debug, Default)]
pub struct UnixSocketPaths {
    /// Linux XDG_RUNTIME_DIR; its existing root must be current-owner 0700.
    pub runtime_directory: Option<PathBuf>,
    /// macOS TMPDIR, used only when the state-home socket exceeds sun_path.
    pub temporary_directory: Option<PathBuf>,
}
struct SocketLocation {
    parent: PathBuf,
    child: String,
    path: PathBuf,
    temporary: bool,
}
impl UnixSocketPaths {
    /// Pure address comparison for a caller that cannot take the runtime lease.
    /// This observes no files and creates no directories. It grants no custody:
    /// binding still requires `prepare` under the retained exclusive home lease.
    pub fn expected_path(&self, state: &Path) -> IpcNativeResult<PathBuf> {
        Ok(self.location(state)?.path)
    }
    /// Call only while retaining the exclusive runtime lease, through stale
    /// socket inspection and listener publication. Existing directories are
    /// checked without permission repair, following the socket custody rules.
    pub fn prepare(&self, state: &Path, bound: &IpcIoBound) -> IpcNativeResult<PathBuf> {
        bound
            .remaining()
            .map_err(|e| error("runtime socket path deadline", e))?;
        let SocketLocation {
            parent,
            child,
            path,
            temporary,
        } = self.location(state)?;
        let state_pin = private_directory(state)?;
        let pin = parent_pin(&parent, temporary)?;
        prepare_child(&parent, &pin, &child)?;
        if stamp(&parent_pin(&parent, temporary)?)? != stamp(&pin)?
            || stamp(&private_directory(state)?)? != stamp(&state_pin)?
        {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "runtime socket parent or state home changed",
            ));
        }
        bound
            .remaining()
            .map_err(|e| error("runtime socket path deadline", e))?;
        Ok(path)
    }
    fn location(&self, state: &Path) -> IpcNativeResult<SocketLocation> {
        fn normalized(path: &Path) -> bool {
            path.is_absolute()
                && !path.as_os_str().as_bytes().contains(&0)
                && path.components().all(|c| {
                    matches!(
                        c,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                })
        }
        if !normalized(state) {
            return Err(refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "runtime socket state home must be a normalized absolute native path",
            ));
        }
        let digest = Sha256::digest(state.as_os_str().as_bytes());
        let key: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
        let (parent, child, name, temporary) = self.selection(state, &key)?;
        if !normalized(&parent) {
            return Err(refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "runtime socket root must be a normalized absolute native path",
            ));
        }
        let path = parent.join(&child).join(name);
        // Check before creating any directory, using the native platform's
        // actual byte capacity including the required trailing NUL.
        // SAFETY: zeroed sockaddr_un is valid storage for inspecting capacity.
        let address: libc::sockaddr_un = unsafe { zeroed() };
        if path.as_os_str().as_bytes().len() >= address.sun_path.len()
            || path.as_os_str().as_bytes().contains(&0)
        {
            return Err(refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "runtime socket path is too long; select a shorter protected runtime directory or temporary directory",
            ));
        }
        Ok(SocketLocation {
            parent,
            child,
            path,
            temporary,
        })
    }
    fn selection(
        &self,
        state: &Path,
        key: &str,
    ) -> IpcNativeResult<(PathBuf, String, String, bool)> {
        #[cfg(target_os = "linux")]
        if let Some(root) = &self.runtime_directory {
            return Ok((
                root.clone(),
                "stateengine".into(),
                format!("{key}.sock"),
                false,
            ));
        }
        #[cfg(target_os = "macos")]
        if state.join("run/runtime.sock").as_os_str().as_bytes().len() >= 104 {
            let root = self.temporary_directory.clone().ok_or_else(|| refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "long macOS state home requires an explicit protected temporary directory (TMPDIR in the CLI)",
            ))?;
            return Ok((
                root,
                format!("se-{}", current_uid()),
                format!("{key}.sock"),
                true,
            ));
        }
        let _ = key;
        Ok((state.to_owned(), "run".into(), "runtime.sock".into(), false))
    }
}

fn parent_pin(path: &Path, temporary: bool) -> IpcNativeResult<File> {
    if !temporary {
        return private_directory(path);
    }
    let file = crate::state_files::pin_runtime_temporary_parent(path)
        .map_err(|e| error("pin runtime temporary parent", io::Error::other(e)))?;
    let m = file
        .metadata()
        .map_err(|e| error("inspect runtime temporary parent", e))?;
    if !((m.uid() == current_uid() && m.mode() & 0o7777 == 0o700)
        || (m.uid() == 0 && m.mode() & 0o7777 == 0o1777))
    {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "temporary parent must be current-owner mode 0700 or a root-owned sticky mode 1777 directory",
        ));
    }
    Ok(file)
}

fn prepare_child(parent: &Path, pin: &File, child: &str) -> IpcNativeResult<()> {
    let name = CString::new(child).map_err(|_| {
        refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "runtime directory name contains NUL",
        )
    })?;
    // SAFETY: one literal component relative to a retained verified directory;
    // protection applies at creation, without changing the process umask.
    if unsafe { libc::mkdirat(pin.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
        let cause = io::Error::last_os_error();
        if cause.kind() != io::ErrorKind::AlreadyExists {
            return Err(error("create protected runtime directory", cause));
        }
    }
    // SAFETY: the retained parent and literal leaf are valid; final symlinks
    // refuse, and a successful descriptor transfers unique ownership below.
    let raw = unsafe {
        libc::openat(
            pin.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(last("pin runtime directory"));
    }
    // SAFETY: successful openat transferred one uniquely owned descriptor.
    let file = unsafe { File::from_raw_fd(raw) };
    let path = parent.join(child);
    if stamp(&file)? != stamp(&private_directory(&path)?)? {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "runtime directory changed during preparation",
        ));
    }
    Ok(())
}
