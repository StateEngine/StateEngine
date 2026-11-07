//! Shared runtime binding for read-only retained-process queries.
use std::{ffi::c_void, sync::OnceLock};
use windows_sys::Win32::{Foundation::*, System::LibraryLoader::*};
type Query = unsafe extern "system" fn(HANDLE, i32, *mut c_void, u32, *mut u32) -> NTSTATUS;
pub(super) fn query() -> Option<Query> {
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
