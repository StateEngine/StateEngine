//! Read-only package identity observation of a caller-retained child. This port
//! never grants process control or treats an API failure as an unpackaged image.
use crate::{NativeFailure, ProcError, ProcErrorCode, ProcErrorDetail, ProcResult, ProcessId};
use std::{io, os::windows::io::AsRawHandle, ptr};
use windows_sys::Win32::{
    Foundation::{APPMODEL_ERROR_NO_PACKAGE, ERROR_INSUFFICIENT_BUFFER},
    Storage::Packaging::Appx::GetPackageFullName,
    System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION},
};

/// The caller keeps its original child process handle alive across this query,
/// so its PID cannot be recycled. This observation is never a stop authority.
pub fn process_has_package_identity(pid: ProcessId) -> ProcResult<bool> {
    if pid.0 == 0 {
        return Err(failed(
            "package identity PID",
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "a retained direct child's positive PID is required",
            ),
        ));
    }
    // SAFETY: read-only process lookup; no pointers or inherited handles.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid.0) };
    let process = crate::windows_native::handle(raw, "OpenProcess(package identity)")
        .map_err(|e| failed(e.operation, e.source))?;
    let mut length = 0;
    // SAFETY: retained query handle and documented null-buffer sizing call.
    let result =
        unsafe { GetPackageFullName(process.as_raw_handle(), &mut length, ptr::null_mut()) };
    match result {
        APPMODEL_ERROR_NO_PACKAGE => Ok(false),
        ERROR_INSUFFICIENT_BUFFER if length > 0 => Ok(true),
        0 | ERROR_INSUFFICIENT_BUFFER => Err(failed(
            "GetPackageFullName",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "package identity sizing returned no nonempty identity extent",
            ),
        )),
        other => Err(failed(
            "GetPackageFullName",
            io::Error::from_raw_os_error(other as i32),
        )),
    }
}
fn failed(api: &str, error: io::Error) -> ProcError {
    ProcError {
        code: ProcErrorCode::IdentityUnreadable,
        detail: Box::new(ProcErrorDetail::Input {
            field: "native process package identity".into(),
            reason: error.to_string(),
        }),
        native: Some(NativeFailure {
            api: api.into(),
            code: error.raw_os_error().map(i64::from),
            reason: error.to_string(),
        }),
    }
}
