use crate::support::*;
use crate::*;
use std::{
    io,
    os::windows::ffi::{OsStrExt, OsStringExt},
};
use windows_sys::Win32::{Foundation::*, System::Threading::*};

pub(super) struct Handle(pub HANDLE);
// SAFETY: owns one process/kernel reference. Native operations use immutable
// handles; resource mutation is serialized by its slot or kernel IOCP.
unsafe impl Send for Handle {}
// SAFETY: shared queries use immutable kernel references; close requires exclusive ownership.
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this object uniquely owns the still-open kernel reference.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}
impl Handle {
    pub fn close(&mut self) -> ProcResult<()> {
        if !self.0.is_null() {
            // SAFETY: exclusive access closes the uniquely owned reference once.
            if unsafe { CloseHandle(self.0) } == 0 {
                return Err(last(
                    ProcErrorCode::StopIncomplete,
                    "close native custody handle",
                ));
            }
            self.0 = std::ptr::null_mut();
        }
        Ok(())
    }
    pub fn new(handle: HANDLE, api: &str) -> ProcResult<Self> {
        use std::os::windows::io::IntoRawHandle;
        crate::windows_native::handle(handle, "own process custody handle")
            .map(|handle| Self(handle.into_raw_handle()))
            .map_err(|e| native(ProcErrorCode::LaunchFailed, api, e.source))
    }
}
pub(super) fn last(code: ProcErrorCode, api: &str) -> ProcError {
    native(code, api, io::Error::last_os_error())
}
pub(super) fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
pub(super) fn lookup(pid: ProcessId) -> ProcResult<Option<Handle>> {
    if pid.0 == 0 {
        return Err(input("pid", "positive native PID required"));
    }
    // SAFETY: process selector, no borrowed pointers; read/synchronize rights only.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid.0,
        )
    };
    if handle.is_null() {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            return Ok(None);
        }
        return Err(native(ProcErrorCode::IdentityUnreadable, "OpenProcess", e));
    }
    Ok(Some(Handle(handle)))
}
fn birth(handle: &Handle) -> ProcResult<StartIdentity> {
    let creation_filetime = crate::windows_native::process_start(handle.0)
        .map_err(|e| native(ProcErrorCode::IdentityUnreadable, e.operation, e.source))?;
    Ok(StartIdentity::Windows { creation_filetime })
}
pub(super) fn exit_status(handle: &Handle) -> ProcResult<Option<ExitStatus>> {
    // SAFETY: retained SYNCHRONIZE process pin; zero timeout cannot block.
    match unsafe { WaitForSingleObject(handle.0, 0) } {
        WAIT_TIMEOUT => Ok(None),
        WAIT_OBJECT_0 => {
            let mut code = 0;
            // SAFETY: only a signalled process reaches this query, preserving actual code 259.
            if unsafe { GetExitCodeProcess(handle.0, &mut code) } == 0 {
                return Err(last(
                    ProcErrorCode::IdentityUnreadable,
                    "GetExitCodeProcess",
                ));
            }
            Ok(Some(ExitStatus::Code(code)))
        }
        _ => Err(last(
            ProcErrorCode::IdentityUnreadable,
            "WaitForSingleObject",
        )),
    }
}
pub(super) fn identity(
    machine: MachineId,
    pid: ProcessId,
    handle: &Handle,
) -> ProcResult<ProcessIdentity> {
    let start = birth(handle)?;
    let mut image = vec![0u16; 32768];
    let mut length = image.len() as u32;
    // SAFETY: writable UTF-16 buffer with explicit capacity in characters.
    if unsafe { QueryFullProcessImageNameW(handle.0, 0, image.as_mut_ptr(), &mut length) } == 0 {
        return Err(last(
            ProcErrorCode::IdentityUnreadable,
            "QueryFullProcessImageNameW",
        ));
    }
    if length == 0 || length as usize >= image.len() {
        return Err(input("process image", "empty or full native image buffer"));
    }
    Ok(ProcessIdentity {
        machine,
        boot: BootIdentity::WindowsAbsoluteCreationClock,
        pid,
        start,
        image: std::ffi::OsString::from_wide(&image[..length as usize]).into(),
    })
}
pub(super) fn observe(
    expected: &ProcessIdentity,
    handle: &Handle,
) -> ProcResult<ProcessObservation> {
    if birth(handle)? != expected.start
        || expected.boot != BootIdentity::WindowsAbsoluteCreationClock
    {
        return Err(changed(expected, None));
    }
    if let Some(status) = exit_status(handle)? {
        // The original retained kernel object proves exit independently of an
        // executable pathname that may be unreadable after process teardown.
        return Ok(ProcessObservation::Exited {
            expected: expected.clone(),
            evidence: ExitEvidence::KernelHandleSignalled,
            status,
            observed_at_unix_ns: now()?,
        });
    }
    let found = identity(expected.machine.clone(), expected.pid, handle)?;
    if found != *expected {
        return Err(changed(expected, Some(&found)));
    }
    Ok(ProcessObservation::Live(LiveObservation {
        identity: found,
        state: NativeState::Running,
        parent: None,
        observed_at_unix_ns: now()?,
    }))
}

pub(crate) fn read_process(machine: MachineId, pid: ProcessId) -> ProcResult<ProcessRead> {
    let Some(handle) = lookup(pid)? else {
        return Ok(ProcessRead::Absent {
            pid,
            observed_at_unix_ns: now()?,
        });
    };
    if let Some(status) = exit_status(&handle)? {
        return Ok(ProcessRead::ExitedRecord {
            pid,
            boot: BootIdentity::WindowsAbsoluteCreationClock,
            start: birth(&handle)?,
            state: NativeState::Exited,
            status,
            observed_at_unix_ns: now()?,
        });
    }
    let expected = identity(machine, pid, &handle)?;
    match observe(&expected, &handle)? {
        ProcessObservation::Live(live) => Ok(ProcessRead::Present(live)),
        ProcessObservation::Exited {
            status,
            observed_at_unix_ns,
            ..
        } => Ok(ProcessRead::ExitedRecord {
            pid,
            boot: expected.boot,
            start: expected.start,
            state: NativeState::Exited,
            status,
            observed_at_unix_ns,
        }),
    }
}
