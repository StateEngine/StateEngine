use super::*;
use crate::linux_native::{self, ProcStat};
use std::{
    fs::{self, File},
    io::Read,
    mem::{size_of, zeroed},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::MetadataExt,
    },
};
pub(super) fn credentials(channel: BorrowedIpc<'_>) -> IpcNativeResult<(u32, u32)> {
    // SAFETY: zero initializes this native POD output before getsockopt fills it.
    let mut info: libc::ucred = unsafe { zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a borrowed live socket, aligned ucred output and exact size.
    if unsafe {
        libc::getsockopt(
            channel.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut info as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(last("read SO_PEERCRED"));
    }
    if length as usize != size_of::<libc::ucred>() || info.pid <= 0 {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid native IPC peer credentials",
        ));
    }
    Ok((info.uid, info.pid as u32))
}
fn start(pid: u32) -> IpcNativeResult<u64> {
    let mut bytes = Vec::new();
    File::open(format!("/proc/{pid}/stat"))
        .and_then(|f| {
            f.take(linux_native::STAT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|e| error("read IPC process birth", e))?;
    if bytes.len() > linux_native::STAT_BYTES {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "oversized native process stat",
        ));
    }
    let facts = ProcStat::parse(&bytes).map_err(|_| {
        refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid native process stat",
        )
    })?;
    facts.start_ticks().map_err(|_| {
        refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid process start ticks",
        )
    })
}

pub(super) fn observe(pid: u32, uid: u32, bound: &IpcIoBound) -> IpcNativeResult<NativeIpcPeer> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid peer process ID",
        ));
    }
    let before = start(pid)?;
    let path = Path::new("/proc").join(pid.to_string());
    let owner = fs::metadata(&path).map_err(|e| error("read peer native owner", e))?;
    if owner.uid() != uid {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "peer process owner differs from connection credential",
        ));
    }
    let executable = path.join("exe");
    let image = fs::read_link(&executable).map_err(|e| error("read peer executable path", e))?;
    // Opening /proc/PID/exe pins the actual executable, not a later file which
    // happens to occupy the same display path.
    let image_sha256 = hash_image(
        File::open(&executable).map_err(|e| error("pin peer executable", e))?,
        bound,
    )?;
    if start(pid)? != before
        || fs::read_link(&executable).map_err(|e| error("reobserve peer executable", e))? != image
        || fs::metadata(&path)
            .map_err(|e| error("reobserve peer owner", e))?
            .uid()
            != uid
    {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "peer changed during native identity readback",
        ));
    }
    Ok(NativeIpcPeer {
        principal: IpcPrincipal::Unix { uid },
        pid,
        started: StartIdentity::Linux {
            start_ticks: before,
        },
        image: native_path(&image)?,
        image_sha256,
        _peer_pidfd: None,
    })
}

pub(super) fn observe_connected(
    channel: BorrowedIpc<'_>,
    pid: u32,
    uid: u32,
    bound: &IpcIoBound,
) -> IpcNativeResult<NativeIpcPeer> {
    let pin = peer_pidfd(channel)?;
    pin_live(pin.as_ref())?;
    let mut peer = observe(pid, uid, bound)?;
    pin_live(pin.as_ref())?;
    peer._peer_pidfd = pin;
    Ok(peer)
}

fn peer_pidfd(channel: BorrowedIpc<'_>) -> IpcNativeResult<Option<OwnedFd>> {
    let mut raw: libc::c_int = -1;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: connected borrowed socket and an aligned, exact-size descriptor
    // output. Success transfers a fresh kernel-owned peer pidfd to this caller.
    if unsafe {
        libc::getsockopt(
            channel.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut raw as *mut libc::c_int).cast(),
            &mut length,
        )
    } != 0
    {
        let mut cause = last("pin connection peer with SO_PEERPIDFD");
        if cause.source.raw_os_error() == Some(libc::ENOPROTOOPT) {
            // Linux before 6.5: retain the original SO_PEERCRED + birth/image
            // rechecks. Access/resource failures are never downgraded to this.
            return Ok(None);
        }
        if cause.source.raw_os_error() == Some(libc::ESRCH) {
            cause.code = IpcNativeErrorCode::PeerChanged;
        }
        return Err(cause);
    }
    if raw < 0 {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid socket peer pidfd",
        ));
    }
    // SAFETY: successful SO_PEERPIDFD returned one newly owned descriptor;
    // the kernel installs it close-on-exec, including on the fallback-free path.
    let pin = unsafe { OwnedFd::from_raw_fd(raw) };
    if length as usize != size_of::<libc::c_int>() {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid socket peer pidfd size",
        ));
    }
    Ok(Some(pin))
}

fn pin_live(pin: Option<&OwnedFd>) -> IpcNativeResult<()> {
    let Some(pin) = pin else {
        return Ok(());
    };
    let mut wait = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: retained pidfd and a writable single pollfd; zero timeout only
    // observes the original process and neither waits nor signals it.
    let result = unsafe { libc::poll(&mut wait, 1, 0) };
    if result < 0 {
        return Err(last("observe pinned IPC peer liveness"));
    }
    if wait.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "unreadable socket peer pidfd",
        ));
    }
    if wait.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "connection peer exited during identity readback",
        ));
    }
    Ok(())
}

pub(super) fn verify_stop_start(
    pid: u32,
    uid: u32,
    expected: &StartIdentity,
) -> IpcNativeResult<()> {
    let before = start(pid)?;
    let path = Path::new("/proc").join(pid.to_string());
    let owner = fs::metadata(&path).map_err(|e| error("read stop target owner", e))?;
    if expected
        != &(StartIdentity::Linux {
            start_ticks: before,
        })
        || owner.uid() != uid
        || start(pid)? != before
    {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "recorded stop target birth or owner changed; rediscover the live host and retry the original stop key",
        ));
    }
    Ok(())
}
