use super::*;
use std::{
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, OwnedHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE},
};

pub(super) fn start(
    path: &Path,
    stdin: &OwnedHandle,
    inherited: &mut [windows_sys::Win32::Foundation::HANDLE],
) -> Result<OwnedHandle> {
    let mut line: Vec<u16> = std::ffi::OsStr::new("se --stateengine-private-uninstall-handoff")
        .encode_wide()
        .chain(Some(0))
        .collect();
    command(&native::wide(path)?, &mut line, stdin, inherited, 0, None)
}
pub(super) fn command(
    application: &[u16],
    line: &mut [u16],
    stdin: &OwnedHandle,
    inherited: &[HANDLE],
    flags: u32,
    environment: Option<&[u16]>,
) -> Result<OwnedHandle> {
    let result = command_inner(application, line, stdin, inherited, flags, environment);
    // Originals in this process must not remain inheritable for later children.
    // Child-table entries are independent and retain their startup flags.
    let mut clear_error = None;
    for raw in inherited.iter().copied().chain(Some(stdin.as_raw_handle())) {
        if let Err(cause) = native::clear_inherit(raw) {
            clear_error.get_or_insert(cause);
        }
    }
    match (result, clear_error) {
        (Ok(process), None) => Ok(process),
        (Err(cause), _) | (Ok(_), Some(cause)) => Err(cause),
    }
}
fn command_inner(
    application: &[u16],
    line: &mut [u16],
    stdin: &OwnedHandle,
    inherited: &[HANDLE],
    flags: u32,
    environment: Option<&[u16]>,
) -> Result<OwnedHandle> {
    let mut streams = Vec::new();
    let mut handles: Vec<HANDLE> = Vec::new();
    let mut attributes = crate::windows_native::attributes::Attributes::new(
        1,
        "size uninstall process attributes",
        "initialize uninstall process attributes",
    )
    .map_err(|e| error(e.operation, e.source))?;
    for which in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: standard-handle selector is a native constant; no pointers are dereferenced.
        let raw = unsafe { GetStdHandle(which) };
        // Human-only admission requires a real console. Preserve these exact
        // output handles so the helper can report the final measured result.
        streams.push(native::duplicate_same(raw, true)?);
    }
    handles.extend_from_slice(inherited);
    handles.push(stdin.as_raw_handle());
    handles.extend(streams.iter().map(AsRawHandle::as_raw_handle));
    attributes
        .set(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            &handles,
            "set exact uninstall handle inheritance",
        )
        .map_err(|e| error(e.operation, e.source))?;
    // SAFETY: native POD output accepts an all-zero initialization.
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin.as_raw_handle();
    startup.StartupInfo.hStdOutput = streams[0].as_raw_handle();
    startup.StartupInfo.hStdError = streams[1].as_raw_handle();
    startup.lpAttributeList = attributes.pointer();
    // SAFETY: native POD output accepts an all-zero initialization.
    let mut result: PROCESS_INFORMATION = unsafe { zeroed() };
    // SAFETY: terminated owned command/path buffers, initialized startup outputs, and explicit retained inheritance list.
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | flags,
            environment.map_or(ptr::null(), |block| block.as_ptr().cast()),
            ptr::null(),
            &startup.StartupInfo,
            &mut result,
        )
    } == 0
    {
        return Err(native::last("launch protected uninstall helper"));
    }
    let process = native::handle(result.hProcess, "pin uninstall helper")?;
    for stream in &streams {
        native::clear_inherit(stream.as_raw_handle())?;
    }
    let _thread = native::handle(result.hThread, "close uninstall helper thread")?;
    Ok(process)
}
