//! Reuse the native attribute allocator for atomic job and closed handle inheritance.
use super::*;
use std::os::windows::ffi::OsStrExt;
pub(super) fn start(
    image: &Path,
    job: &OwnedHandle,
    channel: &OwnedHandle,
    stderr: &OwnedHandle,
) -> io::Result<OwnedHandle> {
    let application: Vec<_> = image.as_os_str().encode_wide().chain(Some(0)).collect();
    if application.len() > 32768 || application[..application.len() - 1].contains(&0) {
        return Err(invalid("Atlas executable path exceeds native bounds"));
    }
    let mut line: Vec<_> = format!("se {ENTRY}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let null = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("NUL")?;
    let mut raw = ptr::null_mut();
    // SAFETY: retained null device/process handles and writable duplicate output.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            null.as_raw_handle(),
            GetCurrentProcess(),
            &mut raw,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(last("DuplicateHandle(Atlas null device)"));
    }
    let null = owned(raw, "duplicate worker null device")?;
    let handles = [
        channel.as_raw_handle(),
        null.as_raw_handle(),
        stderr.as_raw_handle(),
    ];
    let jobs = [job.as_raw_handle()];
    let mut attributes = crate::windows_native::attributes::Attributes::new(
        2,
        "size Atlas attributes",
        "initialize Atlas attributes",
    )
    .map_err(native_error)?;
    attributes
        .set(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            &handles,
            "UpdateProcThreadAttribute(Atlas HANDLE_LIST, 3 handles)",
        )
        .map_err(native_error)?;
    attributes
        .set(
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            &jobs,
            "UpdateProcThreadAttribute(Atlas JOB_LIST, 1 job)",
        )
        .map_err(native_error)?;
    // SAFETY: documented startup/process POD outputs; initialized before use.
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of_val(&startup) as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[2];
    startup.lpAttributeList = attributes.pointer();
    // A closed environment supplies no provider, credentials, config or shell.
    let environment = [0u16, 0];
    let directory: Vec<_> = image
        .parent()
        .ok_or_else(|| invalid("Atlas executable parent absent"))?
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    // SAFETY: initialized native POD receives newly owned process/thread handles.
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    // SAFETY: all buffers, referenced attribute arrays and inherited handles stay
    // alive; job membership precedes first user instruction, with no escape flag.
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            directory.as_ptr(),
            &startup.StartupInfo,
            &mut info,
        )
    } == 0
    {
        return Err(last(
            "CreateProcessW(Atlas inherited handles and atomic job)",
        ));
    }
    let process = owned(info.hProcess, "pin Atlas process")?;
    let _thread = owned(info.hThread, "retain Atlas initial thread")?;
    Ok(process)
}
