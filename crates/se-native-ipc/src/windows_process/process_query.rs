//! Shared runtime binding for read-only retained-process queries.
use std::{ffi::c_void, fs::File, os::windows::io::AsRawHandle, sync::OnceLock};
use windows_sys::Win32::{Foundation::*, System::LibraryLoader::*};
pub type Query = unsafe extern "system" fn(HANDLE, i32, *mut c_void, u32, *mut u32) -> NTSTATUS;
pub fn query() -> Option<Query> {
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

/// Positive kernel comparison with the file section used to start this process.
/// Returns `Ok(true)` on a verified match, `Ok(false)` on a verified mismatch
/// (`STATUS_NOT_SAME_DEVICE`), and `Err(status)` when the native query itself
/// is unavailable or refused.
///
/// # Safety
/// `process` must be a valid query-capable Windows process handle (or current-process pseudo handle).
pub unsafe fn check_mapped_executable(
    process: HANDLE,
    file: &File,
) -> std::result::Result<bool, NTSTATUS> {
    const PROCESS_IMAGE_FILE_MAPPING: i32 = 44;
    const STATUS_NOT_SAME_DEVICE: NTSTATUS = 0xC000_00D4_u32 as NTSTATUS;
    const STATUS_NOT_IMPLEMENTED: NTSTATUS = 0xC000_0002_u32 as NTSTATUS;
    let Some(query) = query() else {
        return Err(STATUS_NOT_IMPLEMENTED);
    };
    let mut handle = file.as_raw_handle();
    // SAFETY: process and executable handles remain open for the query. This
    // information class takes a pointer to one initialized HANDLE as input.
    let status = unsafe {
        query(
            process,
            PROCESS_IMAGE_FILE_MAPPING,
            (&mut handle as *mut HANDLE).cast(),
            std::mem::size_of::<HANDLE>() as u32,
            std::ptr::null_mut(),
        )
    };
    match status {
        0 => Ok(true),
        STATUS_NOT_SAME_DEVICE => Ok(false),
        other => Err(other),
    }
}

/// Positive kernel comparison with the file section used to start this process.
/// A pathname reopened after a rename does not establish this relationship.
///
/// # Safety
/// `process` must be a valid query-capable Windows process handle (or current-process pseudo handle).
pub unsafe fn maps_executable(process: HANDLE, file: &File) -> bool {
    // SAFETY: caller upholds the valid query-capable process handle contract.
    unsafe { check_mapped_executable(process, file) == Ok(true) }
}
