//! Native Windows peer process observations and upgrade-safe stop identity.
use super::{windows::owned, windows_security as security, *};
use std::{
    fs::{File, OpenOptions},
    num::NonZeroU64,
    os::windows::{
        ffi::OsStringExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, OwnedHandle},
    },
    path::PathBuf,
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::{FILE_EXECUTE, FILE_SHARE_DELETE, FILE_SHARE_READ, SYNCHRONIZE},
    System::{Pipes::*, Threading::*},
};
pub(super) fn peer(
    channel: BorrowedIpc<'_>,
    side: IpcPeerSide,
    bound: &IpcIoBound,
) -> IpcNativeResult<NativeIpcPeer> {
    let mut pid = 0;
    let ok = match side {
        // SAFETY: borrowed connected server pipe handle and writable process-ID output.
        IpcPeerSide::Client => unsafe {
            GetNamedPipeClientProcessId(channel.as_raw_handle(), &mut pid)
        },
        // SAFETY: borrowed connected client pipe handle and writable process-ID output.
        IpcPeerSide::Server => unsafe {
            GetNamedPipeServerProcessId(channel.as_raw_handle(), &mut pid)
        },
    };
    if ok == 0 {
        return Err(last("read native pipe peer process ID"));
    }
    observe(pid, bound)
}
pub(super) fn self_peer(bound: &IpcIoBound) -> IpcNativeResult<NativeIpcPeer> {
    observe(std::process::id(), bound)
}

/// Keep a writer-excluding pin only when both live processes map this exact
/// file object. Any missing native fact leaves the ordinary full proof in use.
pub(super) fn shared_mapped_image(expected: &ProcessInstance) -> Option<File> {
    let fields = expected.fields();
    let StartIdentity::Windows { creation_filetime } = fields.started else {
        return None;
    };
    // SAFETY: read-only native process query and lifetime witness rights.
    let process =
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, 0, fields.pid.get()) };
    let process = owned(process, "pin expected IPC image process").ok()?;
    let raw = process.as_raw_handle();
    if crate::windows_native::process_start(raw).ok()? != creation_filetime.get()
        || security::process_sid(raw).ok()? != security::current_sid().ok()?
    {
        return None;
    }
    let file = OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ | FILE_EXECUTE | SYNCHRONIZE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(std::env::current_exe().ok()?)
        .ok()?;
    // SAFETY: this pseudo-handle refers to the current process throughout the query.
    let current = unsafe { GetCurrentProcess() };
    let matching = crate::windows_native::maps_executable(current, &file)
        && crate::windows_native::maps_executable(raw, &file);
    // SAFETY: the original process handle remains pinned and the wait is nonblocking.
    let live = unsafe { WaitForSingleObject(raw, 0) } == WAIT_TIMEOUT;
    (matching && live).then_some(file)
}

pub(super) fn observe(pid: u32, bound: &IpcIoBound) -> IpcNativeResult<NativeIpcPeer> {
    let (process, sid, creation_filetime) = process_identity(pid)?;
    let mut image = vec![0; 32768];
    let mut length = image.len() as u32;
    // SAFETY: retained bounded UTF-16 output buffer and native process pin.
    if unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), 0, image.as_mut_ptr(), &mut length)
    } == 0
    {
        return Err(process_error(&process, last("read IPC peer executable")));
    }
    image.truncate(length as usize);
    let image = PathBuf::from(std::ffi::OsString::from_wide(&image));
    let image_sha256 = hash_image(
        File::open(&image).map_err(|e| error("pin IPC peer executable", e))?,
        bound,
    )?;
    // SAFETY: the query/synchronize process handle is retained above. Native
    // signalled state distinguishes exit code 259 from a live process.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_TIMEOUT => (),
        WAIT_OBJECT_0 => {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "IPC peer exited during identity readback",
            ));
        }
        _ => return Err(last("reobserve IPC peer liveness")),
    }
    Ok(NativeIpcPeer {
        principal: IpcPrincipal::Windows { sid },
        pid,
        started: StartIdentity::Windows { creation_filetime },
        image: native_path(&image)?,
        image_sha256,
        _process: process,
    })
}

fn process_identity(pid: u32) -> IpcNativeResult<(OwnedHandle, String, NonZeroU64)> {
    // SAFETY: query-only process pin, no inherited handle or native mutation.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    if raw.is_null() {
        let mut cause = last("pin IPC peer process");
        // A positive PID supplied by the connected pipe can cease to be
        // pinnable before this call. This invalid selector is a stale peer,
        // not proof that its process exited or that a PID is absent.
        if pid != 0 && cause.source.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            cause.code = IpcNativeErrorCode::PeerChanged;
        }
        return Err(cause);
    }
    let process = owned(raw, "pin IPC peer process")?;
    let sid = security::process_sid(process.as_raw_handle())
        .map_err(|cause| process_error(&process, cause))?;
    if sid != security::current_sid()? {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "IPC peer process SID differs from current user",
        ));
    }
    let creation_filetime = NonZeroU64::new(
        crate::windows_native::process_start(process.as_raw_handle())
            .map_err(|e| process_error(&process, error(e.operation, e.source)))?,
    )
    .ok_or_else(|| {
        refuse(
            IpcNativeErrorCode::Unreadable,
            "native process creation clock is zero",
        )
    })?;
    Ok((process, sid, creation_filetime))
}
// An image/token read error alone never proves death. Only the original
// retained kernel object becoming signalled turns it into a changed peer;
// keep the actual failing operation and OS error for both outcomes.
fn process_error(process: &OwnedHandle, mut cause: IpcNativeError) -> IpcNativeError {
    // SAFETY: retained SYNCHRONIZE process handle, zero-time observation only.
    if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } == WAIT_OBJECT_0 {
        cause.code = IpcNativeErrorCode::PeerChanged;
    }
    cause
}
pub(super) fn stop_server(
    channel: BorrowedIpc<'_>,
    expected: &ProcessInstance,
) -> IpcNativeResult<()> {
    let mut pid = 0;
    // SAFETY: retained connected pipe handle and writable PID output; no impersonation occurs.
    if unsafe { GetNamedPipeServerProcessId(channel.as_raw_handle(), &mut pid) } == 0 {
        return Err(last("read stop target server PID"));
    }
    let (process, _sid, creation) = process_identity(pid)?;
    // SAFETY: retained query/synchronize process handle; zero timeout observes liveness without blocking.
    let live = unsafe { WaitForSingleObject(process.as_raw_handle(), 0) };
    if live != WAIT_TIMEOUT && live != WAIT_OBJECT_0 {
        return Err(last("reobserve stop target liveness"));
    }
    if pid != expected.fields().pid.get()
        || expected.fields().started
            != (StartIdentity::Windows {
                creation_filetime: creation,
            })
        || live != WAIT_TIMEOUT
    {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "recorded stop target PID, birth or liveness changed; rediscover the live host and retry the original stop key",
        ));
    }
    Ok(())
}
