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
