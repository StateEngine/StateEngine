//! Lightweight OS-contained child process primitive for ACP `terminal/*`.
//!
//! - Unix: places the child in a new session/process group (`setsid`) so
//!   `kill_tree` signals `-pgid` with `SIGKILL` (never by process name).
//! - Windows: assigns the child to an anonymous `KILL_ON_JOB_CLOSE` Job Object
//!   and terminates the job atomically on `kill_tree` / `Drop`.
use std::{
    ffi::OsString,
    io,
    path::PathBuf,
    process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex},
};

/// Launch specification for a contained child process.
#[derive(Clone, Debug)]
pub struct ContainedChildSpec {
    pub command: OsString,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub env: Vec<(OsString, OsString)>,
}

/// Normalized process exit status.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainedExit {
    pub exit_code: Option<u32>,
    pub signal: Option<String>,
}

impl ContainedExit {
    fn from_status(status: ExitStatus) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = status.signal() {
                return Self {
                    exit_code: None,
                    signal: Some(unix_signal_name(sig)),
                };
            }
            Self {
                exit_code: status.code().and_then(|c| u32::try_from(c).ok()),
                signal: None,
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                exit_code: status.code().and_then(|c| u32::try_from(c).ok()),
                signal: None,
            }
        }
    }
}

#[cfg(unix)]
fn unix_signal_name(sig: i32) -> String {
    match sig {
        libc::SIGHUP => "SIGHUP".into(),
        libc::SIGINT => "SIGINT".into(),
        libc::SIGQUIT => "SIGQUIT".into(),
        libc::SIGKILL => "SIGKILL".into(),
        libc::SIGTERM => "SIGTERM".into(),
        libc::SIGABRT => "SIGABRT".into(),
        libc::SIGSEGV => "SIGSEGV".into(),
        libc::SIGPIPE => "SIGPIPE".into(),
        other => format!("SIG{other}"),
    }
}

#[cfg(windows)]
struct JobGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

// SAFETY: A Win32 Job Object handle is an opaque kernel handle safe to transfer
// across threads; `CloseHandle` runs only once in `Drop`.
#[cfg(windows)]
unsafe impl Send for JobGuard {}
// SAFETY: `AssignProcessToJobObject` and `TerminateJobObject` are kernel-synchronized
// on the Job Object handle, and `CloseHandle` runs only after the last `Arc` drops.
#[cfg(windows)]
unsafe impl Sync for JobGuard {}

#[cfg(windows)]
impl JobGuard {
    fn create_kill_on_close() -> io::Result<Self> {
        use std::mem::{size_of, zeroed};
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        // SAFETY: Null security attributes and null name create an anonymous job.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let guard = Self { handle };
        // SAFETY: Zeroed POD struct for Win32 SetInformationJobObject.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `guard.handle` is a live job handle and `info` has exact size.
        let ok = unsafe {
            SetInformationJobObject(
                guard.handle,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(guard)
    }

    fn assign(&self, child: &Child) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        // SAFETY: Both `self.handle` and `child.as_raw_handle()` are live handles.
        let ok = unsafe { AssignProcessToJobObject(self.handle, child.as_raw_handle()) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn terminate(&self) -> io::Result<()> {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        // SAFETY: `self.handle` is a live job handle owned by `self`.
        let ok = unsafe { TerminateJobObject(self.handle, 1) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for JobGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        if !self.handle.is_null() {
            // SAFETY: `self.handle` is uniquely owned and closed once on drop.
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

/// Thread-safe handle that terminates the contained process tree without
/// blocking behind `wait()`. Guards against signalling a recycled Unix pgid
/// after the child has been reaped.
#[derive(Clone)]
pub struct ContainedKiller {
    #[cfg(unix)]
    pgid: libc::pid_t,
    #[cfg(windows)]
    job: Arc<JobGuard>,
    reaped: Arc<Mutex<bool>>,
}

impl ContainedKiller {
    /// Terminate the entire contained process tree (process group on Unix,
    /// Job Object on Windows). Never kills by process name.
    pub fn kill_tree(&self) -> io::Result<()> {
        let reaped = self
            .reaped
            .lock()
            .map_err(|_| io::Error::other("contained killer state poisoned"))?;
        if *reaped {
            return Ok(());
        }
        #[cfg(unix)]
        {
            // SAFETY: Negative `pgid` targets only this child's isolated group,
            // and `reaped == false` proves the leader has not been reaped yet.
            let rc = unsafe { libc::kill(-self.pgid, libc::SIGKILL) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(err);
                }
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            self.job.terminate()
        }
    }
}

/// An OS-contained child process whose entire descendant tree is killed on
/// [`ContainedChild::kill_tree`] or [`Drop`].
pub struct ContainedChild {
    child: Child,
    killer: ContainedKiller,
    reaped_exit: Option<ContainedExit>,
}

impl ContainedChild {
    /// Spawn a contained child process with piped stdout/stderr and null stdin.
    pub fn spawn(spec: ContainedChildSpec) -> io::Result<(Self, ChildStdout, ChildStderr)> {
        let mut cmd = Command::new(&spec.command);
        cmd.args(&spec.args)
            .current_dir(&spec.cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in &spec.env {
            cmd.env(name, value);
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // SAFETY: `setsid` is async-signal-safe and isolates the child in
            // its own session and process group (`pgid == child.id()`).
            unsafe {
                cmd.pre_exec(|| {
                    if libc::setsid() == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let mut child = cmd.spawn()?;
            let pgid = libc::pid_t::try_from(child.id())
                .map_err(|_| io::Error::other("child pid exceeds pid_t"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| io::Error::other("child stdout pipe absent"))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| io::Error::other("child stderr pipe absent"))?;
            let killer = ContainedKiller {
                pgid,
                reaped: Arc::new(Mutex::new(false)),
            };
            Ok((
                Self {
                    child,
                    killer,
                    reaped_exit: None,
                },
                stdout,
                stderr,
            ))
        }

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            use windows_sys::Win32::System::Threading::{
                CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW,
            };
            let job = Arc::new(JobGuard::create_kill_on_close()?);
            cmd.creation_flags(CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP);
            let mut child = cmd.spawn()?;
            if let Err(err) = job.assign(&child) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| io::Error::other("child stdout pipe absent"))?;
            let stderr = child
                .stderr
                .take()
                .ok_or_else(|| io::Error::other("child stderr pipe absent"))?;
            let killer = ContainedKiller {
                job,
                reaped: Arc::new(Mutex::new(false)),
            };
            Ok((
                Self {
                    child,
                    killer,
                    reaped_exit: None,
                },
                stdout,
                stderr,
            ))
        }
    }

    /// Return a thread-safe killer handle for concurrent termination.
    pub fn killer(&self) -> ContainedKiller {
        self.killer.clone()
    }

    /// Non-blocking exit check.
    pub fn try_wait(&mut self) -> io::Result<Option<ContainedExit>> {
        if let Some(exit) = &self.reaped_exit {
            return Ok(Some(exit.clone()));
        }
        if let Some(status) = self.child.try_wait()? {
            if let Ok(mut guard) = self.killer.reaped.lock() {
                *guard = true;
            }
            let exit = ContainedExit::from_status(status);
            self.reaped_exit = Some(exit.clone());
            return Ok(Some(exit));
        }
        Ok(None)
    }

    /// Blocking wait until the child exits.
    pub fn wait(&mut self) -> io::Result<ContainedExit> {
        if let Some(exit) = &self.reaped_exit {
            return Ok(exit.clone());
        }
        let status = self.child.wait()?;
        if let Ok(mut guard) = self.killer.reaped.lock() {
            *guard = true;
        }
        let exit = ContainedExit::from_status(status);
        self.reaped_exit = Some(exit.clone());
        Ok(exit)
    }

    /// Terminate the entire contained process tree.
    pub fn kill_tree(&mut self) -> io::Result<()> {
        self.killer.kill_tree()
    }
}

impl Drop for ContainedChild {
    fn drop(&mut self) {
        if self.reaped_exit.is_none() {
            let _ = self.killer.kill_tree();
            let _ = self.child.wait();
            if let Ok(mut guard) = self.killer.reaped.lock() {
                *guard = true;
            }
        }
    }
}
