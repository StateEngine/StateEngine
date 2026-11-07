use super::attach;
use crate::{support::*, *};
use std::{
    ffi::CString,
    fs::File,
    io::{self, Read},
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::Path,
    ptr,
    time::Instant,
};

pub(super) struct Child {
    pub pid: ProcessId,
    pub events: File,
    control: Option<File>,
    payload: Option<zeroize::Zeroizing<Vec<u8>>>,
    deadline: Instant,
    pub pre_exec: Option<ProcessIdentity>,
    pub root: Option<ProcessIdentity>,
    pub status: Option<ExitStatus>,
    pub protocol: Vec<u8>,
    pub authorized: bool,
    pub eof: bool,
}

fn fail(api: &str, code: i32) -> ProcError {
    native(
        ProcErrorCode::LaunchFailed,
        api,
        io::Error::from_raw_os_error(code),
    )
}
fn check(api: &str, code: i32) -> ProcResult<()> {
    if code != 0 {
        return Err(fail(api, code));
    }
    Ok(())
}
fn duplicate(file: &File) -> ProcResult<File> {
    // SAFETY: retained source; a new close-on-exec descriptor above the helper slots.
    let raw = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if raw < 0 {
        return Err(native(
            ProcErrorCode::LaunchFailed,
            "duplicate attach endpoint",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful fcntl returns exclusive descriptor ownership.
    Ok(unsafe { File::from_raw_fd(raw) })
}
fn pair() -> ProcResult<(File, File)> {
    // std serializes its close-on-exec fallback with std process creation;
    // our native children additionally use POSIX_SPAWN_CLOEXEC_DEFAULT.
    let (a, b) = UnixStream::pair()
        .map_err(|e| native(ProcErrorCode::LaunchFailed, "attach socketpair", e))?;
    for stream in [&a, &b] {
        stream
            .set_nonblocking(true)
            .map_err(|e| native(ProcErrorCode::LaunchFailed, "nonblocking attach socket", e))?;
        let enabled: libc::c_int = 1;
        // SAFETY: retained socket and exact scalar option; no process-global signal policy changes.
        if unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as _,
            )
        } < 0
        {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "protect attach socket writes",
                io::Error::last_os_error(),
            ));
        }
    }
    Ok((OwnedFd::from(a).into(), OwnedFd::from(b).into()))
}

struct Actions(libc::posix_spawn_file_actions_t);
impl Actions {
    fn new() -> ProcResult<Self> {
        let mut value = MaybeUninit::uninit();
        // SAFETY: native constructor initializes the exact opaque output on success.
        check("posix_spawn_file_actions_init", unsafe {
            libc::posix_spawn_file_actions_init(value.as_mut_ptr())
        })?;
        // SAFETY: native init above succeeded.
        Ok(Self(unsafe { value.assume_init() }))
    }
    fn dup(&mut self, source: &File, target: i32) -> ProcResult<()> {
        // SAFETY: initialized action list, retained source and nonnegative fixed target.
        check("posix_spawn_file_actions_adddup2", unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut self.0, source.as_raw_fd(), target)
        })
    }
}
impl Drop for Actions {
    fn drop(&mut self) {
        // SAFETY: initialized opaque list, destroyed exactly once after posix_spawn.
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.0);
        }
    }
}
struct Attributes(libc::posix_spawnattr_t);
impl Attributes {
    fn new() -> ProcResult<Self> {
        let mut value = MaybeUninit::uninit();
        // SAFETY: native constructor initializes the exact opaque output on success.
        check("posix_spawnattr_init", unsafe {
            libc::posix_spawnattr_init(value.as_mut_ptr())
        })?;
        // SAFETY: native init succeeded; RAII retains partial setup for cleanup.
        let mut value = Self(unsafe { value.assume_init() });
        // SAFETY: native POD signal masks, filled before use and never shared.
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        // SAFETY: initialized writable mask.
        unsafe {
            libc::sigemptyset(&mut mask);
        }
        // SAFETY: initialized attributes and exact empty signal mask.
        check("posix_spawnattr_setsigmask", unsafe {
            libc::posix_spawnattr_setsigmask(&mut value.0, &mask)
        })?;
        // SAFETY: initialized writable signal set for child-only default dispositions.
        unsafe {
            libc::sigfillset(&mut mask);
            libc::sigdelset(&mut mask, libc::SIGKILL);
            libc::sigdelset(&mut mask, libc::SIGSTOP);
        }
        // SAFETY: initialized attributes and signal set.
        check("posix_spawnattr_setsigdefault", unsafe {
            libc::posix_spawnattr_setsigdefault(&mut value.0, &mask)
        })?;
        // SAFETY: zero requests the new child's own PID as its process group.
        check("posix_spawnattr_setpgroup", unsafe {
            libc::posix_spawnattr_setpgroup(&mut value.0, 0)
        })?;
        let flags = libc::POSIX_SPAWN_SETPGROUP
            | libc::POSIX_SPAWN_SETSIGMASK
            | libc::POSIX_SPAWN_SETSIGDEF
            | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        // SAFETY: initialized attributes and native flag constants.
        check("posix_spawnattr_setflags", unsafe {
            libc::posix_spawnattr_setflags(&mut value.0, flags as _)
        })?;
        Ok(value)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: initialized opaque attributes destroyed once after native spawn.
        unsafe {
            libc::posix_spawnattr_destroy(&mut self.0);
        }
    }
}

pub(super) fn begin(spec: LaunchSpec, helper: &Path) -> ProcResult<Child> {
    let payload = attach::Payload::encode(&spec)?;
    let helper = CString::new(helper.as_os_str().as_bytes())
        .map_err(|_| input("helper image", "NUL is not permitted"))?;
    let entry =
        CString::new(attach::ENTRY).map_err(|_| input("helper entry", "NUL is not permitted"))?;
    let arguments = [
        helper.as_ptr().cast_mut(),
        entry.as_ptr().cast_mut(),
        ptr::null_mut(),
    ];
    let environment = [ptr::null_mut()];
    let null = File::options()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|e| native(ProcErrorCode::LaunchFailed, "open provider null device", e))?;
    let streams = [spec.stdio.stdin, spec.stdio.stdout, spec.stdio.stderr]
        .map(|stream| duplicate(stream.as_ref().unwrap_or(&null)));
    let [stdin, stdout, stderr] = streams;
    let streams = [stdin?, stdout?, stderr?];
    let (control, child_control) = pair()?;
    let (events, child_events) = pair()?;
    let child_control = duplicate(&child_control)?;
    let child_events = duplicate(&child_events)?;
    let mut actions = Actions::new()?;
    for (target, stream) in streams.iter().enumerate() {
        actions.dup(stream, target as i32)?;
    }
    actions.dup(&child_control, attach::CONTROL)?;
    actions.dup(&child_events, attach::EVENTS)?;
    let attributes = Attributes::new()?;
    // Allocate all retained bookkeeping before the child can exist.
    let protocol = Vec::with_capacity(8);
    let mut pid: libc::pid_t = 0;
    // SAFETY: initialized native actions/attributes and terminated argv/envp;
    // the installed helper receives only the explicit descriptor allowlist.
    check("posix_spawn process attach", unsafe {
        libc::posix_spawn(
            &mut pid,
            helper.as_ptr(),
            &actions.0,
            &attributes.0,
            arguments.as_ptr(),
            environment.as_ptr(),
        )
    })?;
    // No fallible native query or write may precede retaining this child in Scope.
    Ok(Child {
        pid: ProcessId(pid as u32),
        events,
        control: Some(control),
        payload: Some(payload),
        deadline: spec.deadline,
        pre_exec: None,
        root: None,
        status: None,
        protocol,
        authorized: false,
        eof: false,
    })
}
impl Child {
    pub fn arm(&mut self) -> ProcResult<()> {
        let payload = self
            .payload
            .take()
            .ok_or_else(|| input("attach setup", "frame already sent"))?;
        let control = self
            .control
            .as_mut()
            .ok_or_else(|| input("attach setup", "authorization channel closed"))?;
        attach::send(control, &payload, self.deadline)
    }
    pub fn read_events(&mut self) -> ProcResult<()> {
        let mut bytes = [0u8; 8];
        loop {
            match self.events.read(&mut bytes) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(count) => {
                    if self.protocol.len() + count > 8 {
                        return Err(capacity("attach result bytes", 8));
                    }
                    self.protocol.extend_from_slice(&bytes[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => {
                    return Err(native(
                        ProcErrorCode::LaunchFailed,
                        "read attach results",
                        error,
                    ));
                }
            }
        }
    }
    pub fn authorize(&mut self) -> ProcResult<()> {
        if self.authorized {
            return Err(input("attach exec", "authorization already consumed"));
        }
        let control = self
            .control
            .as_mut()
            .ok_or_else(|| input("attach exec", "authorization channel closed"))?;
        attach::send(control, &[1], self.deadline)?;
        self.authorized = true;
        self.control = None;
        Ok(())
    }
    pub fn cancel_paused(&mut self) {
        self.control = None;
    }
    pub fn peek_status(&mut self) -> ProcResult<Option<ExitStatus>> {
        if self.status.is_some() {
            return Ok(self.status.clone());
        }
        let mut status = 0;
        // SAFETY: exactly this retained, unreaped child; this never selects a
        // process by name or reaps any sibling. The scope lock serializes calls.
        let observed = unsafe { libc::waitpid(self.pid.0 as i32, &mut status, libc::WNOHANG) };
        if observed == 0 {
            return Ok(None);
        }
        if observed < 0 {
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "waitpid owned provider",
                io::Error::last_os_error(),
            ));
        }
        self.status = Some(if libc::WIFEXITED(status) {
            ExitStatus::Code(libc::WEXITSTATUS(status) as u32)
        } else if libc::WIFSIGNALED(status) {
            ExitStatus::Signal {
                number: libc::WTERMSIG(status) as u32,
                core_dumped: libc::WCOREDUMP(status),
            }
        } else {
            return Err(input(
                "provider wait status",
                "unexpected nonterminal wait result",
            ));
        });
        Ok(self.status.clone())
    }
}
