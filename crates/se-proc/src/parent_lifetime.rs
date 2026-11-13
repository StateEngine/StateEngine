//! Keep a package-manager CLI invocation within its wrapper's lifetime.
use std::{io, os::windows::io::AsRawHandle};
use windows_sys::Win32::{
    Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
    Storage::FileSystem::SYNCHRONIZE,
    System::Threading::*,
};

/// Retain the actual creator, never a caller-selected unrelated process.
/// This lifetime belongs only to this invocation; detached services do not inherit it.
pub fn retain_package_parent(expected: u32) -> io::Result<()> {
    // SAFETY: this borrowed pseudo handle refers to the current process.
    let current = unsafe { GetCurrentProcess() };
    let pid = std::process::id();
    let parent = match crate::windows_native::parent(current, pid).map_err(|e| e.source)? {
        Some(parent) => parent,
        None => crate::windows_native::parents()
            .map_err(|e| e.source)?
            .get(&pid)
            .copied()
            .ok_or_else(|| io::Error::other("package wrapper creator is absent"))?,
    };
    if expected == 0 || parent != expected {
        return Err(io::Error::other(
            "package wrapper is not the native creator",
        ));
    }
    // SAFETY: query and synchronize access only; the successful handle is owned below.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, parent) };
    let retained =
        crate::windows_native::handle(raw, "retain package wrapper").map_err(|e| e.source)?;
    let created =
        crate::windows_native::process_start(retained.as_raw_handle()).map_err(|e| e.source)?;
    let child = crate::windows_native::process_start(current).map_err(|e| e.source)?;
    // SAFETY: retained process handle has synchronize access; zero timeout never blocks.
    let state = unsafe { WaitForSingleObject(retained.as_raw_handle(), 0) };
    if created > child || state != WAIT_TIMEOUT {
        return Err(io::Error::other(
            "package wrapper exited or its PID was reused",
        ));
    }
    std::thread::Builder::new()
        .name("package-parent".into())
        .spawn(move || {
            // SAFETY: this thread owns the retained synchronize-capable handle until wait ends.
            let state = unsafe { WaitForSingleObject(retained.as_raw_handle(), INFINITE) };
            // Fail closed even if the native wait itself fails. Do not block on output.
            std::process::exit(if state == WAIT_OBJECT_0 { 1 } else { 70 });
        })?;
    Ok(())
}
