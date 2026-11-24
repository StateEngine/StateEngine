use super::*;
use std::{
    ffi::OsString,
    fs::File,
    mem::{size_of, zeroed},
    os::{fd::AsRawFd, unix::ffi::OsStringExt},
};
pub(super) fn credentials(channel: BorrowedIpc<'_>) -> IpcNativeResult<(u32, u32)> {
    // SAFETY: zero initializes the native POD buffer before getsockopt fills it.
    let mut credentials: libc::xucred = unsafe { zeroed() };
    let mut size = size_of::<libc::xucred>() as libc::socklen_t;
    // SAFETY: borrowed local socket and exact aligned native credential buffer.
    // SAFETY: retained local socket and exact aligned PID/credential output with its writable size.
    if unsafe {
        libc::getsockopt(
            channel.as_raw_fd(),
            0,
            libc::LOCAL_PEERCRED,
            (&mut credentials as *mut libc::xucred).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(last("read LOCAL_PEERCRED"));
    }
    if size as usize != size_of::<libc::xucred>() || credentials.cr_version != libc::XUCRED_VERSION
    {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid local peer credential version",
        ));
    }
    let mut pid: libc::pid_t = 0;
    size = size_of::<libc::pid_t>() as _;
    // SAFETY: retained local socket and exact aligned PID/credential output with its writable size.
    if unsafe {
        libc::getsockopt(
            channel.as_raw_fd(),
            0,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut size,
        )
    } != 0
    {
        return Err(last("read LOCAL_PEERPID"));
    }
    if size as usize != size_of::<libc::pid_t>() || pid <= 0 {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid native peer PID",
        ));
    }
    Ok((credentials.cr_uid, pid as u32))
}
fn process(pid: u32) -> IpcNativeResult<libc::proc_bsdinfo> {
    // SAFETY: zero initializes this fixed-size native POD output before proc_pidinfo fills it.
    let mut info: libc::proc_bsdinfo = unsafe { zeroed() };
    let wanted = size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: initialized aligned fixed-size native output for one validated PID.
    if unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            wanted,
        )
    } != wanted
    {
        return Err(last("read IPC process identity"));
    }
    Ok(info)
}
fn image_path(pid: u32) -> IpcNativeResult<std::path::PathBuf> {
    let mut bytes = vec![0; 4096];
    // SAFETY: writable bounded byte storage and explicit capacity for the selected native PID.
    let count =
        unsafe { libc::proc_pidpath(pid as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    if count <= 0 || count as usize >= bytes.len() {
        return Err(last("read IPC process image"));
    }
    let end = bytes.iter().position(|b| *b == 0).ok_or_else(|| {
        refuse(
            IpcNativeErrorCode::Unreadable,
            "unterminated native process image",
        )
    })?;
    bytes.truncate(end);
    Ok(OsString::from_vec(bytes).into())
}
pub(super) fn observe(pid: u32, uid: u32, bound: &IpcIoBound) -> IpcNativeResult<NativeIpcPeer> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid peer process ID",
        ));
    }
    let before = process(pid)?;
    let image = image_path(pid)?;
    let image_sha256 = hash_image(
        File::open(&image).map_err(|e| error("pin peer executable", e))?,
        bound,
    )?;
    let after = process(pid)?;
    if before.pbi_uid != uid
        || after.pbi_uid != uid
        || before.pbi_start_tvsec != after.pbi_start_tvsec
        || before.pbi_start_tvusec != after.pbi_start_tvusec
        || image_path(pid)? != image
    {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "peer changed during native identity readback",
        ));
    }
    let start_micros = u32::try_from(before.pbi_start_tvusec).map_err(|_| {
        refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid native process birth",
        )
    })?;
    Ok(NativeIpcPeer {
        principal: IpcPrincipal::Unix { uid },
        pid,
        started: StartIdentity::Macos {
            start_seconds: before.pbi_start_tvsec,
            start_micros,
        },
        image: native_path(&image)?,
        image_sha256,
    })
}

pub(super) fn verify_stop_start(
    pid: u32,
    uid: u32,
    expected: &StartIdentity,
) -> IpcNativeResult<()> {
    let before = process(pid)?;
    let after = process(pid)?;
    let micros = u32::try_from(before.pbi_start_tvusec).map_err(|_| {
        refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid stop target birth; restore native observation access",
        )
    })?;
    if before.pbi_uid != uid
        || after.pbi_uid != uid
        || before.pbi_start_tvsec != after.pbi_start_tvsec
        || before.pbi_start_tvusec != after.pbi_start_tvusec
        || expected
            != &(StartIdentity::Macos {
                start_seconds: before.pbi_start_tvsec,
                start_micros: micros,
            })
    {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "recorded stop target birth or owner changed; rediscover the live host and retry the original stop key",
        ));
    }
    Ok(())
}
