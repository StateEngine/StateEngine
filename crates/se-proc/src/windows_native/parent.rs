//! Query a retained process's creator without enumerating every process.
//! Unsupported query APIs fall back to the existing Toolhelp walk at the caller.
use super::{Error, Result, invalid};
use std::{ffi::c_void, io, mem::size_of, sync::OnceLock};
use windows_sys::Win32::{
    Foundation::*,
    System::{LibraryLoader::*, Threading::PROCESS_BASIC_INFORMATION},
};
type Query = unsafe extern "system" fn(HANDLE, i32, *mut c_void, u32, *mut u32) -> NTSTATUS;
fn query() -> Option<Query> {
    static QUERY: OnceLock<Option<Query>> = OnceLock::new();
    *QUERY.get_or_init(|| {
        let name: Vec<u16> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
        // SAFETY: terminated DLL name; ntdll is the process-lifetime native runtime.
        let module = unsafe { GetModuleHandleW(name.as_ptr()) };
        if module.is_null() {
            return None;
        }
        // SAFETY: process-lifetime module and terminated ASCII export name.
        let export =
            unsafe { GetProcAddress(module, c"NtQueryInformationProcess".as_ptr().cast()) }?;
        // SAFETY: this named NT export has the Query signature documented by
        // winternl.h; runtime resolution preserves the legacy fallback if absent.
        Some(unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, Query>(export) })
    })
}
/// None means this query is unavailable for the retained handle; it never means
/// the creator is absent. The caller must use its complete Toolhelp fallback.
pub(crate) fn parent(process: HANDLE, expected_pid: u32) -> Result<Option<u32>> {
    let Some(query) = query() else {
        return Ok(None);
    };
    let mut info = PROCESS_BASIC_INFORMATION::default();
    let mut returned = 0;
    // SAFETY: caller retains the query-capable process handle; class 0 is
    // ProcessBasicInformation, with exact aligned output and length storage.
    let status = unsafe {
        query(
            process,
            0,
            (&mut info as *mut PROCESS_BASIC_INFORMATION).cast(),
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut returned,
        )
    };
    if matches!(
        status,
        STATUS_INVALID_INFO_CLASS
            | STATUS_NOT_IMPLEMENTED
            | STATUS_ACCESS_DENIED
            | STATUS_INFO_LENGTH_MISMATCH
    ) {
        return Ok(None);
    }
    if status < 0 {
        return Err(Error {
            operation: "query retained process creator",
            // SAFETY: converts the returned NTSTATUS without reading another call's last-error state.
            source: io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32),
        });
    }
    if returned as usize != size_of::<PROCESS_BASIC_INFORMATION>()
        || info.UniqueProcessId != expected_pid as usize
    {
        return Err(invalid(
            "query retained process creator",
            "native process result has a different size or process ID",
        ));
    }
    let parent = u32::try_from(info.InheritedFromUniqueProcessId).map_err(|_| {
        invalid(
            "query retained process creator",
            "native parent process ID exceeds u32",
        )
    })?;
    Ok(Some(parent))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn targeted_creator_matches_native_snapshot() -> std::result::Result<(), String> {
        // SAFETY: GetCurrentProcess returns a non-owning process-lifetime pseudo handle.
        let process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };
        let pid = std::process::id();
        let creator = parent(process, pid).map_err(|e| format!("{}: {}", e.operation, e.source))?;
        let snapshot =
            super::super::parents().map_err(|e| format!("{}: {}", e.operation, e.source))?;
        assert_eq!(creator, snapshot.get(&pid).copied());
        assert!(
            creator.is_some(),
            "supported Windows query unexpectedly fell back"
        );
        assert!(
            parent(process, pid.wrapping_add(1)).is_err(),
            "a wrong claimed PID was accepted"
        );
        Ok(())
    }
}
