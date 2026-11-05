//! A finite nonblocking stderr pipe: diagnostics cannot stall the child or
//! allocate an unbounded owner buffer when a native library aborts.
use std::{
    fs::File,
    io::{self, Read},
    os::fd::FromRawFd,
    process::Stdio,
};
const LIMIT: usize = 4096;
pub(super) struct Diagnostics {
    input: File,
    bytes: Vec<u8>,
    truncated: bool,
    error: Option<io::Error>,
}
impl Diagnostics {
    pub(super) fn pipe() -> io::Result<(Self, Stdio)> {
        let mut fds = [-1; 2];
        // SAFETY: exactly two writable descriptor slots; successful pipe2
        // transfers ownership of both newly created descriptors below.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: each successful pipe descriptor is owned exactly once.
        let input = unsafe { File::from_raw_fd(fds[0]) };
        // SAFETY: the distinct successful write descriptor is owned exactly once.
        let output = unsafe { File::from_raw_fd(fds[1]) };
        // SAFETY: this is our retained pipe; the kernel rounds to one page.
        if unsafe { libc::fcntl(fds[0], libc::F_SETPIPE_SZ, LIMIT as i32) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            Self {
                input,
                bytes: Vec::new(),
                truncated: false,
                error: None,
            },
            output.into(),
        ))
    }
    pub(super) fn drain(&mut self) {
        let mut buffer = [0u8; 1024];
        // A hostile/noisy child cannot turn a progress callback into an
        // unbounded drain. The pipe's write end is also nonblocking.
        for _ in 0..8 {
            match self.input.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let keep = (LIMIT - self.bytes.len()).min(n);
                    self.bytes.extend_from_slice(&buffer[..keep]);
                    self.truncated |= keep < n;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    self.error = Some(error);
                    break;
                }
            }
        }
    }
    pub(super) fn report(&mut self) -> String {
        self.drain();
        format!(
            "stderr={:?}; stderr_truncated={}; stderr_at_capacity={}; stderr_read_error={:?}",
            String::from_utf8_lossy(&self.bytes),
            self.truncated,
            self.bytes.len() == LIMIT,
            self.error.as_ref().map(ToString::to_string)
        )
    }
}
