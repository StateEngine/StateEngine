//! Native Windows peer process observations and upgrade-safe stop identity.
use super::{windows::owned, windows_security as security, *};
use std::{
    fs::File,
    num::NonZeroU64,
    os::windows::io::{AsRawHandle, OwnedHandle},
    path::PathBuf,
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::SYNCHRONIZE,
    System::{Pipes::*, Threading::*},
};
pub(super) fn peer(
    channel: BorrowedIpc<'_>,
    side: IpcPeerSide,
    bound: &IpcIoBound,
) -> IpcNativeResult<NativeIpcPeer> {
    let mut pid = 0;
    // SAFETY: borrowed connected pipe handle and writable process-ID output.
    let ok = unsafe {
        match side {
            IpcPeerSide::Client => GetNamedPipeClientProcessId(channel.as_raw_handle(), &mut pid),
            IpcPeerSide::Server => GetNamedPipeServerProcessId(channel.as_raw_handle(), &mut pid),
        }
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
    // SAFETY: the OpenProcess result is a newly opened handle or null, which `owned` rejects.
    let process = unsafe { owned(process, "pin expected IPC image process") }.ok()?;
    let raw = process.as_raw_handle();
    // SAFETY: `raw` is a retained query-capable process handle pinned above.
    let start = unsafe { crate::windows_process::process_start(raw) }.ok()?;
    // SAFETY: `raw` is a retained query-capable process handle pinned above.
    let sid = unsafe { security::process_sid(raw) }.ok()?;
    if start != creation_filetime.get() || sid != security::current_sid().ok()? {
        return None;
    }
    let file = crate::windows_process::open_executable(&std::env::current_exe().ok()?).ok()?;
    // SAFETY: this pseudo-handle refers to the current process throughout the query.
    let current = unsafe { GetCurrentProcess() };
    // SAFETY: `current` is the current-process pseudo handle and `raw` is the retained process handle.
    let matching = unsafe {
        crate::windows_process::maps_executable(current, &file)
            && crate::windows_process::maps_executable(raw, &file)
    };
    // SAFETY: the original process handle remains pinned and the wait is nonblocking.
    let live = unsafe { WaitForSingleObject(raw, 0) } == WAIT_TIMEOUT;
    (matching && live).then_some(file)
}

pub(super) fn observe(pid: u32, bound: &IpcIoBound) -> IpcNativeResult<NativeIpcPeer> {
    let (process, sid, creation_filetime) = process_identity(pid)?;
    // SAFETY: `process` is a retained PROCESS_QUERY_INFORMATION handle pinned above.
    let image = unsafe { crate::windows_process::process_image_path(process.as_raw_handle()) }
        .map_err(|e| process_error(&process, error(e.operation, e.source)))?;
    // SAFETY: `process` is a retained PROCESS_QUERY_INFORMATION handle pinned above.
    let file =
        unsafe { crate::windows_process::open_mapped_executable(process.as_raw_handle(), &image) }
            .map_err(|e| process_error(&process, error(e.operation, e.source)))?
            .ok_or_else(|| {
                process_error(
                    &process,
                    refuse(
                        IpcNativeErrorCode::PeerChanged,
                        "IPC peer executable path does not match the live process image mapping; reconnect from an unmodified executable",
                    ),
                )
            })?;
    let image_sha256 = hash_image(file, bound)?;
    check_live(&process)?;
    Ok(NativeIpcPeer {
        principal: IpcPrincipal::Windows { sid },
        pid,
        started: StartIdentity::Windows { creation_filetime },
        image: native_path(&image)?,
        image_sha256,
        _process: process,
    })
}
pub(super) fn observe_birth(
    pid: u32,
    with_path: bool,
) -> IpcNativeResult<(IpcPrincipal, StartIdentity, Option<PathBuf>)> {
    let (process, sid, creation_filetime) = process_identity(pid)?;
    let image = with_path
        .then(|| {
            // SAFETY: `process` is a retained PROCESS_QUERY_INFORMATION handle pinned above.
            unsafe { crate::windows_process::process_image_path(process.as_raw_handle()) }
                .map_err(|e| process_error(&process, error(e.operation, e.source)))
        })
        .transpose()?;
    check_live(&process)?;
    Ok((
        IpcPrincipal::Windows { sid },
        StartIdentity::Windows { creation_filetime },
        image,
    ))
}
fn check_live(process: &OwnedHandle) -> IpcNativeResult<()> {
    // SAFETY: retained SYNCHRONIZE process handle; zero-time observation only.
    if !unsafe { crate::windows_process::process_is_live(process.as_raw_handle()) }
        .map_err(|e| error(e.operation, e.source))?
    {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "IPC peer exited during identity readback",
        ));
    }
    Ok(())
}

fn process_identity(pid: u32) -> IpcNativeResult<(OwnedHandle, String, NonZeroU64)> {
    // SAFETY: query-only process pin (PROCESS_QUERY_INFORMATION is required for
    // ProcessImageFileMapping), no inherited handle or native mutation.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, 0, pid) };
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
    // SAFETY: the successful OpenProcess above transferred unique ownership to `raw`.
    let process = unsafe { owned(raw, "pin IPC peer process") }?;
    // SAFETY: `process` retains a valid query-capable process handle for this call.
    let sid = unsafe { security::process_sid(process.as_raw_handle()) }
        .map_err(|cause| process_error(&process, cause))?;
    if sid != security::current_sid()? {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "IPC peer process SID differs from current user",
        ));
    }
    // SAFETY: `process` is a retained query-capable process handle pinned above.
    let creation_filetime = NonZeroU64::new(
        unsafe { crate::windows_process::process_start(process.as_raw_handle()) }
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
    let live = unsafe { crate::windows_process::process_is_live(process.as_raw_handle()) }
        .map_err(|e| error(e.operation, e.source))?;
    let expected_started = StartIdentity::Windows {
        creation_filetime: creation,
    };
    if pid != expected.fields().pid.get() || expected.fields().started != expected_started || !live
    {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "recorded stop target PID, birth or liveness changed; rediscover the live host and retry the original stop key",
        ));
    }
    Ok(())
}
