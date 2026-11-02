use crate::state_files::{Result, StateFileErrorCode, failure, io_error};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{Foundation::*, System::Threading::*};

fn error(operation: &'static str, path: &Path) -> crate::state_files::StateFileError {
    io_error(operation, path, io::Error::last_os_error())
}

fn duplicate(raw: HANDLE, path: &Path) -> Result<OwnedHandle> {
    let mut copy = ptr::null_mut();
    // SAFETY: the caller retains the original; duplicate exactly its rights
    // within this process and mark only the copy inheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut copy,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(error("duplicate claimed installer handle", path));
    }
    // SAFETY: DuplicateHandle transferred unique ownership of a valid handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(copy) })
}

fn attributes<'a>(
    handles: &'a [HANDLE],
    path: &Path,
) -> Result<crate::windows_native::attributes::Attributes<'a>> {
    let mut attributes = crate::windows_native::attributes::Attributes::new(
        1,
        "size installer handle allowlist",
        "initialize installer handle allowlist",
    )
    .map_err(|e| io_error(e.operation, path, e.source))?;
    attributes
        .set(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles,
            "bind installer handle allowlist",
        )
        .map_err(|e| io_error(e.operation, path, e.source))?;
    Ok(attributes)
}

// Windows argv quoting: quote each argument, double backslashes before quotes
// and before the closing quote. No shell concatenation or command expansion.
fn quote(value: &OsStr, line: &mut Vec<u16>, path: &Path) -> Result<()> {
    let units: Vec<_> = value.encode_wide().collect();
    if units.contains(&0) {
        return Err(failure(
            StateFileErrorCode::Unsupported,
            "installer argument contains NUL",
            path,
        ));
    }
    line.push(b'"' as u16);
    let mut slashes = 0;
    for unit in units {
        if unit == b'\\' as u16 {
            slashes += 1;
        } else {
            line.extend(std::iter::repeat_n(
                b'\\' as u16,
                slashes * if unit == b'"' as u16 { 2 } else { 1 },
            ));
            if unit == b'"' as u16 {
                line.push(b'\\' as u16);
            }
            line.push(unit);
            slashes = 0;
        }
    }
    line.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    line.push(b'"' as u16);
    Ok(())
}

pub(super) fn run(
    claim: &File,
    executable: &OsStr,
    args: &[OsString],
    created: Option<&OsStr>,
) -> Result<i32> {
    let path = Path::new(executable);
    let mut application: Vec<_> = executable.encode_wide().collect();
    if application.contains(&0) {
        return Err(failure(
            StateFileErrorCode::Unsupported,
            "installer executable contains NUL",
            path,
        ));
    }
    application.push(0);
    let mut line = Vec::new();
    quote(executable, &mut line, path)?;
    for argument in args {
        line.push(b' ' as u16);
        quote(argument, &mut line, path)?;
    }
    if line.len() >= 32767 {
        return Err(failure(
            StateFileErrorCode::Unsupported,
            "installer command exceeds native command-line bound",
            path,
        ));
    }
    line.push(0);
    let environment = environment::build(created, path)?;
    let claim = duplicate(claim.as_raw_handle(), path)?;
    let mut owned = vec![claim];
    let mut stdio = [ptr::null_mut(); 3];
    for (index, raw) in [
        io::stdin().as_raw_handle(),
        io::stdout().as_raw_handle(),
        io::stderr().as_raw_handle(),
    ]
    .into_iter()
    .enumerate()
    {
        if !raw.is_null() && raw != INVALID_HANDLE_VALUE {
            let handle = duplicate(raw, path)?;
            stdio[index] = handle.as_raw_handle();
            owned.push(handle);
        }
    }
    let handles: Vec<_> = owned.iter().map(AsRawHandle::as_raw_handle).collect();
    let attributes = attributes(&handles, path)?;
    // SAFETY: native POD initialized before all required startup fields below.
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdio[0];
    startup.StartupInfo.hStdOutput = stdio[1];
    startup.StartupInfo.hStdError = stdio[2];
    startup.lpAttributeList = attributes.pointer();
    // SAFETY: writable native POD process/thread result.
    let mut process: PROCESS_INFORMATION = unsafe { zeroed() };
    // SAFETY: terminated application and mutable command line, retained handle
    // allowlist and startup buffers. Inherit only stdio and the claim duplicate.
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            environment
                .as_ref()
                .map_or(ptr::null(), |block| block.as_ptr().cast()),
            ptr::null(),
            &startup.StartupInfo,
            &mut process,
        )
    } == 0
    {
        return Err(error("start installer under native claim", path));
    }
    // SAFETY: successful CreateProcessW transferred these two unique handles.
    let process_handle = unsafe { OwnedHandle::from_raw_handle(process.hProcess) };
    // SAFETY: same successful native result, independently owned thread handle.
    let thread_handle = unsafe { OwnedHandle::from_raw_handle(process.hThread) };
    drop(thread_handle);
    drop(attributes);
    drop(owned);
    // SAFETY: exact child process handle, retained for the whole finite process
    // lifetime; the installer itself determines how long its work needs.
    if unsafe { WaitForSingleObject(process_handle.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
        return Err(error("wait for claimed installer", path));
    }
    let mut code = 0;
    // SAFETY: exited retained child and writable exit status output.
    if unsafe { GetExitCodeProcess(process_handle.as_raw_handle(), &mut code) } == 0 {
        return Err(error("read installer exit status", path));
    }
    Ok(code as i32)
}

#[path = "install_environment_windows.rs"]
mod environment;

#[cfg(test)]
#[path = "../../../tests/support/windows_install_inheritance.rs"]
mod judges;
