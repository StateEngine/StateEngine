//! Compare-and-remove custody for a crashed owner's Unix socket pathname.
use super::*;
use std::{ffi::CString, os::fd::AsRawFd};

#[derive(Eq, PartialEq)]
struct SocketIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
    changed: (libc::time_t, libc::c_long),
}

fn socket_at(directory: &File, name: &CString) -> IpcNativeResult<Option<SocketIdentity>> {
    // SAFETY: zeroed stat is writable native output storage.
    let mut metadata: libc::stat = unsafe { zeroed() };
    // SAFETY: a held directory, one nul-terminated name and initialized output;
    // no-follow inspection never traverses a replacement symlink.
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            &mut metadata,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        let cause = io::Error::last_os_error();
        return if cause.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error("observe stale IPC socket", cause))
        };
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFSOCK
        || metadata.st_mode & 0o7777 != 0o600
        || metadata.st_uid != current_uid()
        || metadata.st_nlink != 1
    {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "stale IPC socket must be a single-link current-owner socket with mode 0600",
        ));
    }
    Ok(Some(SocketIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        changed: (metadata.st_ctime, metadata.st_ctime_nsec),
    }))
}

fn check(bound: &IpcIoBound) -> IpcNativeResult<()> {
    bound
        .remaining()
        .map(|_| ())
        .map_err(|e| error("stale IPC socket cleanup deadline", e))
}

/// Never inferred from an IPC request. The caller must retain the exclusive
/// runtime lease from before observation through removal, preventing another
/// cooperating host from publishing. The old endpoint is never adopted.
pub struct NativeUnixSocketCleanup {
    path: PathBuf,
    directory: File,
    name: CString,
    socket: SocketIdentity,
}
impl NativeUnixSocketCleanup {
    /// Absence is distinct from unreadable or unsafe. A bounded connection
    /// probe sends no bytes: only ECONNREFUSED proves the socket is not listening.
    pub fn observe(path: &Path, bound: &IpcIoBound) -> IpcNativeResult<Option<Self>> {
        check(bound)?;
        let parent = path.parent().ok_or_else(|| {
            refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "IPC socket parent required",
            )
        })?;
        let directory = private_directory(parent)?;
        let name = CString::new(
            path.file_name()
                .ok_or_else(|| {
                    refuse(
                        IpcNativeErrorCode::UnsafeEndpoint,
                        "IPC socket name required",
                    )
                })?
                .as_bytes(),
        )
        .map_err(|_| {
            refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "IPC socket name contains NUL",
            )
        })?;
        let socket = socket_at(&directory, &name)?;
        if stamp(&private_directory(parent)?)? != stamp(&directory)? {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "IPC parent changed during observation",
            ));
        }
        check(bound)?;
        let Some(socket) = socket else {
            return Ok(None);
        };
        let observed = Self {
            path: path.to_owned(),
            directory,
            name,
            socket,
        };
        observed.not_listening(bound)?;
        observed.verify(bound)?;
        Ok(Some(observed))
    }
    fn verify(&self, bound: &IpcIoBound) -> IpcNativeResult<()> {
        check(bound)?;
        let parent = self.path.parent().ok_or_else(|| {
            refuse(
                IpcNativeErrorCode::UnsafeEndpoint,
                "IPC socket parent required",
            )
        })?;
        if stamp(&private_directory(parent)?)? != stamp(&self.directory)?
            || socket_at(&self.directory, &self.name)?.as_ref() != Some(&self.socket)
        {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "stale IPC socket or parent changed",
            ));
        }
        check(bound)
    }
    /// Rechecks protection, parent/socket identity and liveness before removing
    /// just the observed entry relative to the held parent. Never repairs a
    /// collision, removes a live listener, or extends the caller's deadline.
    pub fn compare_remove(self, bound: &IpcIoBound) -> IpcNativeResult<()> {
        self.verify(bound)?;
        self.not_listening(bound)?;
        self.verify(bound)?;
        // SAFETY: the private directory is held, the one-component name and
        // socket identity were rechecked, and the caller still holds its lease.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) } < 0 {
            return Err(last("remove observed stale IPC socket"));
        }
        Ok(())
    }
    fn not_listening(&self, bound: &IpcIoBound) -> IpcNativeResult<()> {
        check(bound)?;
        // Reuse the bounded native connector without sending any bytes or
        // retaining the connection. A live or unreadable peer is never removed.
        let result = NativeUnixStream::connect(&self.path, bound.clone());
        check(bound)?;
        match result {
            Ok(_) => Err(refuse(
                IpcNativeErrorCode::AlreadyExists,
                "IPC socket has a live listener",
            )),
            Err(error)
                if matches!(
                    error.operation,
                    "connect native IPC" | "complete IPC connect"
                ) && error.source.raw_os_error() == Some(libc::ECONNREFUSED) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}
