//! Socket readiness without blocking socket timeouts.
/// Wait at most `wait` for a socket to be readable (or writable). Unlike a
/// blocking socket timeout, readiness leaves the connection's state defined,
/// so a caller may keep waiting on an idle connection.
pub(crate) fn socket_ready(
    socket: std::os::windows::io::RawSocket,
    write: bool,
    wait: std::time::Duration,
) -> std::io::Result<bool> {
    use windows_sys::Win32::Networking::WinSock::{
        POLLRDNORM, POLLWRNORM, SOCKET_ERROR, WSAGetLastError, WSAPOLLFD, WSAPoll,
    };
    let mut entry = WSAPOLLFD {
        fd: socket as usize,
        events: if write { POLLWRNORM } else { POLLRDNORM },
        revents: 0,
    };
    let millis = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: one initialized entry for the duration of the call.
    let ready = unsafe { WSAPoll(&mut entry, 1, millis) };
    if ready == SOCKET_ERROR {
        // SAFETY: reads this thread's last Winsock error.
        return Err(std::io::Error::from_raw_os_error(unsafe {
            WSAGetLastError()
        }));
    }
    // Hang-up and error count as ready, so the next read or write reports them.
    Ok(ready > 0 && entry.revents != 0)
}

/// Query the OS-verified peer process ID on a connected Windows AF_UNIX socket.
pub(crate) fn peer_pid(socket: std::os::windows::io::RawSocket) -> Option<u32> {
    use std::{mem::size_of, ptr};
    use windows_sys::Win32::Networking::WinSock::WSAIoctl;
    const SIO_AF_UNIX_GETPEERPID: u32 = 0x5800_0100;
    let mut pid = 0u32;
    let mut bytes = 0u32;
    // SAFETY: live AF_UNIX socket handle and writable u32 output buffers.
    let rc = unsafe {
        WSAIoctl(
            socket as usize,
            SIO_AF_UNIX_GETPEERPID,
            ptr::null(),
            0,
            (&mut pid as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut bytes,
            ptr::null_mut(),
            None,
        )
    };
    (rc == 0 && bytes == size_of::<u32>() as u32 && pid != 0).then_some(pid)
}

/// Query the OS-verified live `(pid, creation_filetime)` of the peer on a
/// connected Windows AF_UNIX socket. Returns `None` if the PID cannot be read,
/// the process cannot be opened, or it has already exited.
pub(crate) fn peer_identity(socket: std::os::windows::io::RawSocket) -> Option<(u32, u64)> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::{
        Foundation::{FILETIME, WAIT_TIMEOUT},
        System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            WaitForSingleObject,
        },
    };
    let pid = peer_pid(socket)?;
    // SAFETY: positive validated PID, read-only query/synchronize access, no handle inheritance.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if raw.is_null() {
        return None;
    }
    // SAFETY: OpenProcess transferred sole ownership of a valid process handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: retained handle, zero-timeout liveness check.
    if unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } != WAIT_TIMEOUT {
        return None;
    }
    let mut created = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = created;
    let mut kernel = created;
    let mut user = created;
    // SAFETY: retained query-capable process handle and valid FILETIME output pointers.
    if unsafe {
        GetProcessTimes(
            handle.as_raw_handle(),
            &mut created,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return None;
    }
    let birth = u64::from(created.dwLowDateTime) | (u64::from(created.dwHighDateTime) << 32);
    Some((pid, birth))
}
