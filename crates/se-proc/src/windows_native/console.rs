//! Resolve a console through its kernel connection, never the writable
//! ProcessConsoleHostProcess hint or a process's executable name.
use super::{Error, Result, handle, invalid, last};
use std::{io, mem::size_of, os::windows::io::AsRawHandle, ptr};
use windows_sys::Win32::{
    Foundation::*,
    System::{Diagnostics::Debug::ReadProcessMemory, IO::DeviceIoControl, Threading::*},
};

fn word(process: HANDLE, address: usize, width: usize) -> Result<usize> {
    let mut value = [0_u8; size_of::<usize>()];
    let mut read = 0;
    if address == 0 || !matches!(width, 4 | 8) || width > value.len() {
        return Err(invalid(
            "read console reference",
            "invalid native address width",
        ));
    }
    // SAFETY: the remote address is never dereferenced locally; the kernel
    // copies at most width bytes into our initialized, exactly bounded output.
    if unsafe {
        ReadProcessMemory(
            process,
            address as *const _,
            value.as_mut_ptr().cast(),
            width,
            &mut read,
        )
    } == 0
    {
        return Err(last("read console reference"));
    }
    if read != width {
        return Err(invalid(
            "read console reference",
            "incomplete native pointer",
        ));
    }
    Ok(usize::from_le_bytes(value))
}

fn parameters(process: HANDLE, expected_pid: u32) -> Result<(usize, usize)> {
    let query = super::process_query::query().ok_or_else(|| {
        invalid(
            "locate console reference",
            "native process query is unavailable",
        )
    })?;
    let mut info = PROCESS_BASIC_INFORMATION::default();
    let mut returned = 0;
    // SAFETY: retained query handle, exact initialized class-0 output and size.
    let code = unsafe {
        query(
            process,
            0,
            (&mut info as *mut PROCESS_BASIC_INFORMATION).cast(),
            size_of_val(&info) as u32,
            &mut returned,
        )
    };
    if code < 0 {
        return Err(status("locate console reference", code));
    }
    if returned as usize != size_of_val(&info) || info.UniqueProcessId != expected_pid as usize {
        return Err(invalid(
            "locate console reference",
            "native root identity or output size changed",
        ));
    }
    let mut wow64 = 0;
    // SAFETY: retained process and initialized BOOL output.
    if unsafe { IsWow64Process(process, &mut wow64) } == 0 {
        return Err(last("query console process architecture"));
    }
    let (peb, width) = if wow64 != 0 && size_of::<usize>() == 8 {
        let mut peb = 0_usize;
        // SAFETY: class 26 returns the WOW64 PEB address in a native ULONG_PTR.
        let code = unsafe {
            query(
                process,
                26,
                (&mut peb as *mut usize).cast(),
                size_of::<usize>() as u32,
                &mut returned,
            )
        };
        if code < 0 {
            return Err(status("locate WOW64 console reference", code));
        }
        if returned as usize != size_of::<usize>() || peb == 0 {
            return Err(invalid(
                "locate WOW64 console reference",
                "missing or incomplete WOW64 PEB",
            ));
        }
        (peb, 4)
    } else {
        if size_of::<usize>() == 4 && wow64 == 0 {
            let mut caller_wow64 = 0;
            // SAFETY: process-lifetime pseudo handle and initialized BOOL output.
            if unsafe { IsWow64Process(GetCurrentProcess(), &mut caller_wow64) } == 0 {
                return Err(last("query console reader architecture"));
            }
            if caller_wow64 != 0 {
                return Err(invalid(
                    "locate console reference",
                    "32-bit reader cannot inspect a native 64-bit console",
                ));
            }
        }
        (info.PebBaseAddress as usize, size_of::<usize>())
    };
    let address = peb
        .checked_add(width * 4)
        .filter(|_| peb != 0)
        .ok_or_else(|| invalid("locate console reference", "invalid PEB address"))?;
    // PEB's four-pointer prefix ends at ProcessParameters (0x20/0x10).
    let parameters = word(process, address, width)?;
    if parameters == 0 {
        return Err(invalid(
            "locate console reference",
            "process parameters are unavailable",
        ));
    }
    Ok((parameters, width))
}

/// The PEB supplies only a handle selector. ConDrv itself proves the server;
/// writable process metadata cannot turn an ordinary child into a console host.
pub(crate) fn server(process: HANDLE, expected_pid: u32) -> Result<u32> {
    let (parameters_before, width) = parameters(process, expected_pid)?;
    // RTL_USER_PROCESS_PARAMETERS starts with four ULONGs, then ConsoleHandle,
    // on both native and WOW64 layouts. Do not read argv or arbitrary buffers.
    let address = parameters_before.checked_add(16).ok_or_else(|| {
        invalid(
            "read console reference",
            "process parameter address overflow",
        )
    })?;
    let reference = word(process, address, width)?;
    if reference == 0
        || reference >= usize::MAX - 2
        || (width == 4 && reference >= u32::MAX as usize - 2)
    {
        return Err(invalid(
            "read console reference",
            "console reference is absent or not initialized",
        ));
    }
    let mut raw = ptr::null_mut();
    // SAFETY: retained source process and an untrusted handle selector; the
    // kernel validates it and transfers exactly one non-inheritable duplicate.
    if unsafe {
        DuplicateHandle(
            process,
            reference as HANDLE,
            GetCurrentProcess(),
            &mut raw,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(last("pin console connection"));
    }
    let connection = handle(raw, "pin console connection")?;
    let mut pid = 0_usize;
    let mut bytes = 0;
    // IOCTL_CONDRV_GET_SERVER_PID: FILE_DEVICE_CONSOLE, function 8,
    // METHOD_NEITHER, FILE_ANY_ACCESS. The output is a HANDLE-sized process ID,
    // not a process handle; resolve and retain its native identity separately.
    // SAFETY: retained connection, no input, exact initialized synchronous
    // output; the kernel driver supplies the server, not user process metadata.
    if unsafe {
        DeviceIoControl(
            connection.as_raw_handle(),
            0x0050_0023,
            ptr::null(),
            0,
            (&mut pid as *mut usize).cast(),
            size_of::<usize>() as u32,
            &mut bytes,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last("query console driver server"));
    }
    // This METHOD_NEITHER query writes the PID directly but can report zero
    // bytes returned. Its synchronous success and the initialized PID, rather
    // than the byte count, establish the result.
    if pid == 0 || pid == expected_pid as usize {
        return Err(invalid(
            "query console driver server",
            "invalid console server identity",
        ));
    }
    if parameters(process, expected_pid)? != (parameters_before, width)
        || word(process, address, width)? != reference
    {
        return Err(invalid(
            "query console driver server",
            "root console association changed during observation",
        ));
    }
    // Do not retain the connection: that could extend the console's lifetime.
    u32::try_from(pid).map_err(|_| {
        invalid(
            "query console driver server",
            "console server PID exceeds u32",
        )
    })
}

fn status(operation: &'static str, code: NTSTATUS) -> Error {
    Error {
        operation,
        // SAFETY: translates the returned status without another last-error read.
        source: io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(code) } as i32),
    }
}
