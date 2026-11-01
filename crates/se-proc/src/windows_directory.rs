use crate::{NativeFailure, ProcError, ProcErrorCode, ProcErrorDetail, ProcResult};
use std::{ffi::OsString, io, os::windows::ffi::OsStringExt, path::PathBuf};

/// Reads the native Windows directory without consulting the caller's environment.
/// The result preserves native UTF-16 and never falls back to an assumed drive.
pub fn windows_directory() -> ProcResult<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    // SAFETY: initialized writable UTF-16 buffer with its exact native capacity.
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    } as usize;
    if length == 0 {
        let cause = io::Error::last_os_error();
        return Err(ProcError {
            code: ProcErrorCode::IdentityUnreadable,
            detail: Box::new(ProcErrorDetail::Input {
                field: "native Windows directory".into(),
                reason: "GetWindowsDirectoryW failed".into(),
            }),
            native: Some(NativeFailure {
                api: "GetWindowsDirectoryW".into(),
                code: cause.raw_os_error().map(i64::from),
                reason: cause.to_string(),
            }),
        });
    }
    if length >= buffer.len() {
        return Err(ProcError {
            code: ProcErrorCode::ResourceLimit,
            detail: Box::new(ProcErrorDetail::Capacity {
                resource: "native Windows directory UTF-16 units".into(),
                limit: buffer.len() as u64 - 1,
            }),
            native: None,
        });
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}
