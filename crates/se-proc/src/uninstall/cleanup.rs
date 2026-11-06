//! Fixed system interpreter and minimal environment for the readable carrier.
use super::*;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

#[cfg(test)]
#[path = "../../tests/support/uninstall_carrier_environment.rs"]
mod environment_tests;

pub(super) fn environment(root: &Path) -> Result<Vec<u16>> {
    let mut windows = vec![0u16; 32768];
    // SAFETY: initialized UTF-16 output and explicit capacity for the native Windows directory.
    let count = unsafe {
        windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
            windows.as_mut_ptr(),
            windows.len() as u32,
        )
    } as usize;
    if count == 0 || count >= windows.len() {
        return Err(native::last("resolve cleanup Windows directory"));
    }
    let windows = std::ffi::OsString::from_wide(&windows[..count]);
    let mut block = Vec::new();
    // Fixed allowlist. No caller environment, module paths, profiler hooks,
    // framework configuration or command search path reaches the carrier.
    for (name, value) in [
        ("SystemRoot", windows.as_os_str()),
        ("TEMP", root.as_os_str()),
        ("TMP", root.as_os_str()),
        ("windir", windows.as_os_str()),
    ] {
        block.extend(name.encode_utf16());
        block.push(b'=' as u16);
        let units: Vec<_> = value.encode_wide().collect();
        if units.contains(&0) {
            return Err(refuse("prepare cleanup environment", "NUL in native path"));
        }
        block.extend(units);
        block.push(0);
    }
    block.push(0);
    Ok(block)
}
pub(super) fn system_powershell() -> Result<PathBuf> {
    let mut path = vec![0u16; 32768];
    // SAFETY: initialized UTF-16 output with explicit native capacity.
    let count = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            path.as_mut_ptr(),
            path.len() as u32,
        )
    } as usize;
    if count == 0 || count >= path.len() {
        return Err(native::last("resolve system cleanup executable"));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&path[..count]))
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe"))
}
