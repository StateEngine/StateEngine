//! Read-only creator image for choosing a human-readable CLI shell syntax.
use std::{
    ffi::OsString,
    io,
    os::windows::{ffi::OsStringExt, io::AsRawHandle},
    path::PathBuf,
};
use windows_sys::Win32::System::Threading::*;

pub fn parent_process_image() -> io::Result<Option<PathBuf>> {
    // SAFETY: the current-process pseudo handle is borrowed for this query.
    let current = unsafe { GetCurrentProcess() };
    let pid = std::process::id();
    let parent = match crate::windows_native::parent(current, pid).map_err(|e| e.source)? {
        Some(parent) => parent,
        None => crate::windows_native::parents()
            .map_err(|e| e.source)?
            .get(&pid)
            .copied()
            .ok_or_else(|| io::Error::other("creator is absent from the native snapshot"))?,
    };
    if parent == 0 {
        return Ok(None);
    }
    // SAFETY: read-only query access to the recorded creator; successful open is owned below.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, parent) };
    let process =
        crate::windows_native::handle(raw, "query command shell").map_err(|e| e.source)?;
    let created =
        crate::windows_native::process_start(process.as_raw_handle()).map_err(|e| e.source)?;
    let child = crate::windows_native::process_start(current).map_err(|e| e.source)?;
    if created > child {
        return Err(io::Error::other("creator PID has been reused"));
    }
    let mut image = vec![0u16; 32768];
    let mut length = image.len() as u32;
    // SAFETY: retained query handle and initialized UTF-16 output with explicit capacity.
    if unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), 0, image.as_mut_ptr(), &mut length)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if length == 0 || length as usize >= image.len() {
        return Err(io::Error::other(
            "creator image exceeds the native query bound",
        ));
    }
    Ok(Some(PathBuf::from(OsString::from_wide(
        &image[..length as usize],
    ))))
}
