use super::*;
use std::{
    fs::{self, File},
    io::Read,
    mem::{size_of, zeroed},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
};
pub(super) fn credentials(channel: BorrowedIpc<'_>) -> IpcNativeResult<(u32, u32)> {
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
        .and_then(|f| f.take(4097).read_to_end(&mut bytes))
        .map_err(|e| error("read IPC process birth", e))?;
    if bytes.len() > 4096 {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "oversized native process stat",
        ));
    }
    let end = bytes.windows(2).rposition(|p| p == b") ").ok_or_else(|| {
        refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid native process stat",
        )
    })?;
    bytes[end + 2..]
        .split(u8::is_ascii_whitespace)
        .filter(|v| !v.is_empty())
        .nth(19)
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| {
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
    })
}
