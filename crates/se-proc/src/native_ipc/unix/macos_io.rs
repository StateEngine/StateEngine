//! Poll the original I/O bound without changing socket options after peer close.
use super::IpcIoBound;
use std::{
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
};

pub(super) fn configure(stream: &UnixStream) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: fresh owned socket and correctly sized native integer input.
    if unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ready_io(
    stream: &UnixStream,
    bound: &IpcIoBound,
    events: libc::c_short,
    mut operation: impl FnMut(&UnixStream) -> io::Result<usize>,
) -> io::Result<usize> {
    loop {
        let remaining = bound.remaining()?;
        let mut wait = libc::pollfd {
            fd: stream.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: one retained socket descriptor and initialized stack output.
        let ready = unsafe { libc::poll(&mut wait, 1, remaining.as_millis().clamp(1, 10) as i32) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            continue;
        }
        bound.remaining()?;
        // A hangup may still carry buffered bytes. Let the nonblocking native
        // read distinguish those bytes from EOF; never turn readiness into EOF.
        match operation(stream) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            result => return result,
        }
    }
}

pub(super) fn read(
    stream: &UnixStream,
    bound: &IpcIoBound,
    buffer: &mut [u8],
) -> io::Result<usize> {
    ready_io(stream, bound, libc::POLLIN, |mut stream| {
        stream.read(buffer)
    })
}

pub(super) fn write(stream: &UnixStream, bound: &IpcIoBound, buffer: &[u8]) -> io::Result<usize> {
    ready_io(stream, bound, libc::POLLOUT, |mut stream| {
        stream.write(buffer)
    })
}
