//! A private second exec permit for a console joined to its owned backend.
//! No listener, shell, durable helper, or separate process scope is introduced.
use super::*;
use sha2::{Digest, Sha256};
use std::{ffi::OsString, os::unix::ffi::OsStrExt, path::Path};

const MAX_BYTES: usize = 65536;
const MAX_ARGS: usize = 1025;

pub(super) fn payload(
    executable: &Path,
    arguments: &[OsString],
) -> ProcResult<(Vec<u8>, [u8; 32])> {
    if arguments.len() >= MAX_ARGS {
        return Err(capacity("console argument count", (MAX_ARGS - 1) as u64));
    }
    let mut bytes = vec![0; 4];
    let mut digest = Sha256::new();
    for argument in
        std::iter::once(executable.as_os_str()).chain(arguments.iter().map(|a| a.as_os_str()))
    {
        let argument = argument.as_bytes();
        if argument.contains(&0) {
            return Err(input("console argument", "NUL is not permitted"));
        }
        if bytes.len() + argument.len() + 1 > MAX_BYTES + 4 {
            return Err(capacity("console argument bytes", MAX_BYTES as u64));
        }
        digest.update((argument.len() as u64).to_le_bytes());
        digest.update(argument);
        bytes.extend_from_slice(argument);
        bytes.push(0);
    }
    let length = (bytes.len() - 4) as u32;
    bytes[..4].copy_from_slice(&length.to_le_bytes());
    Ok((bytes, digest.finalize().into()))
}

/// Called only inside the reserved fork child, with all pointers and backend
/// streams prepared before fork. All operations are async-signal-safe.
pub(super) unsafe fn start_backend(
    streams: &[i32; 3],
    executable: *const libc::c_char,
    arguments: &[*const libc::c_char],
    environment: &[*const libc::c_char],
    error_fd: i32,
) -> i32 {
    // SAFETY: caller retains the prepared buffers and descriptors until exec.
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return *libc::__errno_location();
        }
        if pid == 0 {
            for (target, source) in streams.iter().enumerate() {
                if libc::dup2(*source, target as i32) < 0 {
                    report(error_fd, *libc::__errno_location());
                }
            }
            libc::execve(executable, arguments.as_ptr(), environment.as_ptr());
            report(error_fd, *libc::__errno_location());
        }
        for descriptor in streams {
            libc::close(*descriptor);
        }
        0
    }
}
unsafe fn report(error_fd: i32, number: i32) -> ! {
    // SAFETY: fixed initialized packet, retained exec error channel; no unwind.
    unsafe {
        let number = number.to_le_bytes();
        let packet = [b'E', number[0], number[1], number[2], number[3]];
        libc::write(error_fd, packet.as_ptr().cast(), packet.len());
        libc::_exit(127)
    }
}
unsafe fn read_exact(descriptor: i32, bytes: &mut [u8]) -> i32 {
    let mut offset = 0;
    // SAFETY: caller supplies the inherited private channel and a bounded output.
    unsafe {
        while offset < bytes.len() {
            let n = libc::read(
                descriptor,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
            );
            if n < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            if n <= 0 {
                return libc::EPIPE;
            }
            offset += n as usize;
        }
    }
    0
}
/// The original native helper becomes the TUI. Its backend and viewer stay in
/// its original group, and retain no helper error/authorization fd after exec.
pub(super) unsafe fn exec_console(
    authorization: i32,
    executable: *const libc::c_char,
    environment: &[*const libc::c_char],
) -> i32 {
    // SAFETY: fixed stack buffers; private bounded input is parsed without any
    // allocation, locks, formatting, or unwinding in the post-fork child.
    unsafe {
        let mut header = [0; 4];
        let number = read_exact(authorization, &mut header);
        if number != 0 {
            return number;
        }
        let length = u32::from_le_bytes(header) as usize;
        if length == 0 || length > MAX_BYTES {
            return libc::E2BIG;
        }
        let mut bytes = [0u8; MAX_BYTES];
        let number = read_exact(authorization, &mut bytes[..length]);
        if number != 0 {
            return number;
        }
        if bytes[length - 1] != 0 {
            return libc::EPROTO;
        }
        let mut argv = [std::ptr::null(); MAX_ARGS + 1];
        let mut count = 0;
        let mut start = 0;
        for index in 0..length {
            if bytes[index] == 0 {
                if count == MAX_ARGS {
                    return libc::E2BIG;
                }
                argv[count] = bytes.as_ptr().add(start).cast::<libc::c_char>();
                count += 1;
                start = index + 1;
            }
        }
        libc::execve(executable, argv.as_ptr(), environment.as_ptr());
        *libc::__errno_location()
    }
}

impl Scope {
    pub fn prepare_window_exec(&mut self, arguments: &[OsString]) -> ProcResult<[u8; 32]> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| input("console exec", "missing child"))?;
        let expected = child
            .pre_exec
            .as_ref()
            .ok_or_else(|| input("console exec", "missing root checkpoint"))?;
        if !child.deferred
            || !child.authorized
            || child.window_payload.is_some()
            || child.authorization.is_none()
        {
            return Err(input(
                "console exec",
                "requires the original authorized backend and an unstaged console",
            ));
        }
        identity::verify_live_identity(expected)?;
        let (bytes, digest) = payload(&self.executable, arguments)?;
        child.window_payload = Some(bytes);
        Ok(digest)
    }
    pub fn authorize_window_exec(&mut self) -> ProcResult<()> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| input("console exec", "missing child"))?;
        let expected = child
            .pre_exec
            .as_ref()
            .ok_or_else(|| input("console exec", "missing root checkpoint"))?;
        identity::verify_live_identity(expected)?;
        let bytes = child
            .window_payload
            .take()
            .ok_or_else(|| input("console exec", "requires staged arguments"))?;
        let file = child
            .authorization
            .take()
            .ok_or_else(|| input("console exec", "permit was already consumed or revoked"))?;
        // SAFETY: live owned private socket, bounded prepared frame. Any short
        // write revokes the permit; it cannot authorize a truncated argv.
        let count = unsafe {
            libc::send(
                file.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if count != bytes.len() as isize {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "authorize console exec",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }
}
