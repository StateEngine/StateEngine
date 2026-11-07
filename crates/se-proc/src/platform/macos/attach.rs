//! Private installed-image entry. The inherited channel selects only this
//! process; it grants no authority over any other process or persistent state.
use crate::{support::*, *};
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::File,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    ptr,
    time::{Duration, Instant},
};

pub(crate) const ENTRY: &str = "--stateengine-private-process-attach";
pub(super) const CONTROL: i32 = 3;
pub(super) const EVENTS: i32 = 4;
const MAX_FRAME: usize = 512 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Payload {
    executable: Vec<u8>,
    arguments: Vec<Vec<u8>>,
    environment: Vec<Vec<u8>>,
    cwd: Vec<u8>,
    expires_ns: u64,
}
impl Payload {
    pub(super) fn encode(spec: &LaunchSpec) -> ProcResult<zeroize::Zeroizing<Vec<u8>>> {
        let mut environment = Vec::with_capacity(spec.environment.entries.len());
        for (key, value) in &spec.environment.entries {
            let mut bytes = key.as_bytes().to_vec();
            bytes.push(b'=');
            bytes.extend_from_slice(value.as_bytes());
            environment.push(bytes);
        }
        let payload = Self {
            executable: spec.executable.as_os_str().as_bytes().to_vec(),
            arguments: spec
                .arguments
                .iter()
                .map(|arg| arg.as_bytes().to_vec())
                .collect(),
            environment,
            cwd: spec.cwd.as_os_str().as_bytes().to_vec(),
            expires_ns: monotonic_ns()?
                .checked_add(
                    u64::try_from(
                        spec.deadline
                            .saturating_duration_since(Instant::now())
                            .as_nanos(),
                    )
                    .map_err(|_| input("attach deadline", "native duration overflow"))?,
                )
                .ok_or_else(|| input("attach deadline", "native clock overflow"))?,
        };
        let mut bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(&payload)
                .map_err(|error| input("attach payload", &error.to_string()))?,
        );
        if bytes.len() > MAX_FRAME {
            return Err(capacity("attach frame bytes", MAX_FRAME as u64));
        }
        let size = (bytes.len() as u32).to_le_bytes();
        bytes.splice(..0, size);
        Ok(bytes)
    }
}

fn monotonic_ns() -> ProcResult<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: read-only native clock query with exact initialized output.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(native(
            ProcErrorCode::LaunchFailed,
            "read attach monotonic clock",
            io::Error::last_os_error(),
        ));
    }
    if time.tv_sec < 0 || !(0..1_000_000_000).contains(&time.tv_nsec) {
        return Err(input("attach native clock", "invalid native timespec"));
    }
    (time.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(time.tv_nsec as u64))
        .ok_or_else(|| input("attach native clock", "native clock exceeds range"))
}

pub(super) fn ready(file: &File, events: i16, deadline: Instant) -> ProcResult<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(error(
                ProcErrorCode::LaunchTimedOut,
                ProcErrorDetail::Input {
                    field: "attach deadline".into(),
                    reason: "original native setup deadline elapsed".into(),
                },
            ));
        }
        let mut poll = libc::pollfd {
            fd: file.as_raw_fd(),
            events,
            revents: 0,
        };
        let milliseconds = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: one retained native endpoint, exact aligned output and finite timeout.
        let count = unsafe { libc::poll(&mut poll, 1, milliseconds) };
        if count > 0 {
            if Instant::now() >= deadline {
                continue;
            }
            return Ok(());
        }
        if count == 0 {
            continue;
        }
        let cause = io::Error::last_os_error();
        if cause.kind() != io::ErrorKind::Interrupted {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "poll attach channel",
                cause,
            ));
        }
    }
}
fn read_exact(file: &mut File, mut bytes: &mut [u8], deadline: Instant) -> ProcResult<()> {
    while !bytes.is_empty() {
        ready(file, libc::POLLIN, deadline)?;
        match file.read(bytes) {
            Ok(0) => {
                return Err(input(
                    "attach authorization",
                    "launching host closed its channel",
                ));
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(cause)
                if matches!(
                    cause.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(cause) => {
                return Err(native(
                    ProcErrorCode::LaunchFailed,
                    "read attach channel",
                    cause,
                ));
            }
        }
    }
    Ok(())
}
pub(super) fn send(file: &mut File, mut bytes: &[u8], deadline: Instant) -> ProcResult<()> {
    while !bytes.is_empty() {
        ready(file, libc::POLLOUT, deadline)?;
        match file.write(bytes) {
            Ok(0) => {
                return Err(input(
                    "attach channel",
                    "native channel made no write progress",
                ));
            }
            Ok(count) => bytes = &bytes[count..],
            Err(cause)
                if matches!(
                    cause.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) => {}
            Err(cause) => {
                return Err(native(
                    ProcErrorCode::LaunchFailed,
                    "write attach channel",
                    cause,
                ));
            }
        }
    }
    Ok(())
}
fn cstring(bytes: Vec<u8>) -> ProcResult<CString> {
    CString::new(bytes).map_err(|_| input("attach payload", "native string contains NUL"))
}

pub(crate) fn entry() -> ProcResult<()> {
    // SAFETY: this function runs only at the installed private process entry,
    // before threads/file owners, and adopts the two designated inherited endpoints.
    let mut control = unsafe { File::from_raw_fd(CONTROL) };
    // SAFETY: distinct inherited write endpoint owned exclusively by this helper.
    let mut events = unsafe { File::from_raw_fd(EVENTS) };
    let result = execute(&mut control, &mut events);
    if let Err(error) = &result {
        let code = error
            .native
            .as_ref()
            .and_then(|n| n.code)
            .and_then(|n| i32::try_from(n).ok())
            .unwrap_or(libc::EINVAL);
        let mut packet = vec![b'E'];
        packet.extend_from_slice(&code.to_le_bytes());
        // The pipe is nonblocking; failure remains an error exit/closed channel,
        // never a claimed successful exec or an unbounded diagnostic write.
        let _ = events.write(&packet);
        // SAFETY: this is the dedicated transient child. Keep its result channel
        // open until kernel exit, rather than dropping it while the helper can run.
        unsafe {
            libc::_exit(126);
        }
    }
    result
}
fn execute(control: &mut File, events: &mut File) -> ProcResult<()> {
    // The descriptors must close at vendor exec, but remain open while paused.
    for file in [&*control, &*events] {
        // SAFETY: adopted private descriptor; no shared host flags are changed.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "protect attach descriptor",
                io::Error::last_os_error(),
            ));
        }
    }
    // No provider or public launch is authorized by reaching this private entry.
    // Initial setup is bounded even if a malformed caller never sends a frame.
    let initial = Instant::now() + Duration::from_secs(30);
    let mut length = [0u8; 4];
    read_exact(control, &mut length, initial)?;
    let size = u32::from_le_bytes(length) as usize;
    if size > MAX_FRAME {
        return Err(capacity("attach frame bytes", MAX_FRAME as u64));
    }
    let mut bytes = zeroize::Zeroizing::new(vec![0u8; size]);
    read_exact(control, &mut bytes, initial)?;
    let payload: Payload =
        serde_json::from_slice(&bytes).map_err(|e| input("attach frame", &e.to_string()))?;
    // Budget starts at the parent's native sample; delivery cannot renew it.
    let local_start = Instant::now();
    let remaining = payload.expires_ns.saturating_sub(monotonic_ns()?);
    let deadline = local_start + Duration::from_nanos(remaining.min(30_000_000_000));
    let executable = cstring(payload.executable)?;
    let cwd = cstring(payload.cwd)?;
    let args = std::iter::once(executable.clone())
        .chain(
            payload
                .arguments
                .into_iter()
                .map(CString::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| input("attach arguments", "NUL is not permitted"))?,
        )
        .collect::<Vec<_>>();
    let environment = payload
        .environment
        .into_iter()
        .map(cstring)
        .collect::<ProcResult<Vec<_>>>()?;
    let argv = args
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(Some(ptr::null()))
        .collect::<Vec<_>>();
    let envp = environment
        .iter()
        .map(|arg| arg.as_ptr())
        .chain(Some(ptr::null()))
        .collect::<Vec<_>>();
    // SAFETY: terminated native path, before vendor exec, only this helper's cwd changes.
    if unsafe { libc::chdir(cwd.as_ptr()) } < 0 {
        return Err(native(
            ProcErrorCode::LaunchFailed,
            "attach chdir",
            io::Error::last_os_error(),
        ));
    }
    send(events, b"R", deadline)?;
    let mut permit = [0u8];
    read_exact(control, &mut permit, deadline)?;
    if permit != [1] {
        return Err(input(
            "attach authorization",
            "explicit exec permit required",
        ));
    }
    // SAFETY: valid terminated argv/envp/path storage survives until successful
    // process replacement; no shell or ambient environment supplies arguments.
    unsafe {
        libc::execve(executable.as_ptr(), argv.as_ptr(), envp.as_ptr());
    }
    Err(native(
        ProcErrorCode::LaunchFailed,
        "attach execve",
        io::Error::last_os_error(),
    ))
}
