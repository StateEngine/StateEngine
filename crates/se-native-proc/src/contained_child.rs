//! Lightweight OS-contained child process primitive for ACP `terminal/*`.
//!
//! - Unix: places the child in a new session/process group (`setsid`) so
//!   `kill_tree` signals `-pgid` with `SIGKILL` and polls until `ESRCH`
//!   witnesses the entire process group empty (even after the leader exits).
//! - Windows: launches the child `CREATE_SUSPENDED`, attaches it to an
//!   anonymous `KILL_ON_JOB_CLOSE` Job Object before resuming its primary
//!   thread, and drains `ActiveProcesses == 0` on `kill_tree`.
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

/// Maximum time `kill_tree` waits to witness process-group / Job Object drain.
const KILL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const KILL_POLL_INTERVAL: Duration = Duration::from_millis(10);

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

fn is_baseline_env_key(key: &OsStr) -> bool {
    let Some(s) = key.to_str() else {
        return false;
    };
    let upper = s.to_ascii_uppercase();
    if upper.starts_with("LC_") {
        return true;
    }
    matches!(
        upper.as_str(),
        "PATH"
            | "HOME"
            | "USER"
            | "LOGNAME"
            | "TMPDIR"
            | "TEMP"
            | "TMP"
            | "LANG"
            | "TERM"
            | "SHELL"
            | "USERPROFILE"
            | "USERNAME"
            | "SYSTEMROOT"
            | "COMSPEC"
            | "WINDIR"
            | "PATHEXT"
            | "APPDATA"
            | "LOCALAPPDATA"
            | "PROGRAMFILES"
            | "PROGRAMFILES(X86)"
            | "COMMONPROGRAMFILES"
            | "SYSTEMDRIVE"
    )
}

fn build_sanitized_env(overrides: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    let mut entries: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(k, _)| is_baseline_env_key(k))
        .collect();
    for (name, val) in overrides {
        entries.retain(|(existing, _)| {
            #[cfg(windows)]
            {
                !existing.eq_ignore_ascii_case(name)
            }
            #[cfg(not(windows))]
            {
                existing != name
            }
        });
        entries.push((name.clone(), val.clone()));
    }
    entries
}

#[cfg(unix)]
mod unix_imp {
    use super::*;
    use std::{
        os::{
            fd::OwnedFd,
            unix::process::{CommandExt, ExitStatusExt},
        },
        process::{Child, Command, ExitStatus, Stdio},
        sync::Mutex,
    };

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

    pub(super) fn exit_from_status(status: ExitStatus) -> ContainedExit {
        if let Some(sig) = status.signal() {
            return ContainedExit {
                exit_code: None,
                signal: Some(unix_signal_name(sig)),
            };
        }
        ContainedExit {
            exit_code: status.code().and_then(|c| u32::try_from(c).ok()),
            signal: None,
        }
    }

    #[derive(Clone)]
    pub(super) struct KillerState {
        pgid: libc::pid_t,
        /// Set to true ONLY once the leader is reaped AND `kill(-pgid, 0) == ESRCH`
        /// has been witnessed, so surviving grandchildren are still terminated.
        group_empty: Arc<Mutex<bool>>,
        leader_reaped: Arc<Mutex<bool>>,
    }

    impl KillerState {
        pub(super) fn mark_leader_reaped(&self) {
            if let Ok(mut reaped) = self.leader_reaped.lock() {
                *reaped = true;
            }
            // If no grandchildren remain, mark empty immediately to prevent
            // signalling a future recycled pgid.
            // SAFETY: `kill(-pgid, 0)` only probes process-group existence.
            if unsafe { libc::kill(-self.pgid, 0) } < 0
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                && let Ok(mut empty) = self.group_empty.lock()
            {
                *empty = true;
            }
        }

        pub(super) fn kill_tree(&self) -> io::Result<()> {
            let mut empty = self
                .group_empty
                .lock()
                .map_err(|_| io::Error::other("contained killer state poisoned"))?;
            if *empty {
                return Ok(());
            }
            let deadline = Instant::now() + KILL_DRAIN_TIMEOUT;
            loop {
                // SAFETY: Negative `pgid` targets only this child's isolated group,
                // and `*empty == false` means the group has not yet been witnessed empty.
                let rc = unsafe { libc::kill(-self.pgid, libc::SIGKILL) };
                if rc < 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ESRCH) {
                        if self.leader_reaped.lock().is_ok_and(|g| *g) {
                            *empty = true;
                        }
                        return Ok(());
                    }
                    return Err(err);
                }
                // Check whether the group is now empty.
                // SAFETY: `kill(-pgid, 0)` only probes whether any member survives.
                let probe = unsafe { libc::kill(-self.pgid, 0) };
                if probe < 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ESRCH) {
                        if self.leader_reaped.lock().is_ok_and(|g| *g) {
                            *empty = true;
                        }
                        return Ok(());
                    }
                    return Err(err);
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other(format!(
                        "contained process group {} still has live descendants after SIGKILL",
                        self.pgid
                    )));
                }
                std::thread::sleep(KILL_POLL_INTERVAL);
            }
        }
    }

    pub(super) struct Inner {
        child: Child,
        killer: KillerState,
        reaped_exit: Option<ContainedExit>,
    }

    impl Inner {
        pub(super) fn spawn(spec: ContainedChildSpec) -> io::Result<(Self, File, File)> {
            let mut cmd = Command::new(&spec.command);
            cmd.args(&spec.args)
                .current_dir(&spec.cwd)
                .env_clear()
                .envs(build_sanitized_env(&spec.env))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
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
            let killer = KillerState {
                pgid,
                group_empty: Arc::new(Mutex::new(false)),
                leader_reaped: Arc::new(Mutex::new(false)),
            };
            Ok((
                Self {
                    child,
                    killer,
                    reaped_exit: None,
                },
                File::from(OwnedFd::from(stdout)),
                File::from(OwnedFd::from(stderr)),
            ))
        }

        pub(super) fn killer(&self) -> KillerState {
            self.killer.clone()
        }

        pub(super) fn try_wait(&mut self) -> io::Result<Option<ContainedExit>> {
            if let Some(exit) = &self.reaped_exit {
                return Ok(Some(exit.clone()));
            }
            if let Some(status) = self.child.try_wait()? {
                self.killer.mark_leader_reaped();
                let exit = exit_from_status(status);
                self.reaped_exit = Some(exit.clone());
                return Ok(Some(exit));
            }
            Ok(None)
        }

        pub(super) fn wait(&mut self) -> io::Result<ContainedExit> {
            if let Some(exit) = &self.reaped_exit {
                return Ok(exit.clone());
            }
            let status = self.child.wait()?;
            self.killer.mark_leader_reaped();
            let exit = exit_from_status(status);
            self.reaped_exit = Some(exit.clone());
            Ok(exit)
        }
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            if self.reaped_exit.is_none() {
                let _ = self.killer.kill_tree();
                let _ = self.child.wait();
                self.killer.mark_leader_reaped();
            }
            let _ = self.killer.kill_tree();
        }
    }
}

#[cfg(windows)]
mod win_imp {
    use super::*;
    use std::{
        mem::{size_of, zeroed},
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
            WAIT_OBJECT_0, WAIT_TIMEOUT,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
                QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
            },
            Pipes::CreatePipe,
            Threading::{
                CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
                CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetExitCodeProcess,
                PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW,
                TerminateProcess, WaitForSingleObject,
            },
        },
    };

    struct JobGuard {
        handle: HANDLE,
    }

    // SAFETY: A Win32 Job Object handle is an opaque kernel handle safe to transfer
    // across threads; `CloseHandle` runs only once in `Drop`.
    unsafe impl Send for JobGuard {}
    // SAFETY: `AssignProcessToJobObject`, `TerminateJobObject`, and `QueryInformationJobObject`
    // are kernel-synchronized on the handle; `CloseHandle` runs only after the last `Arc` drops.
    unsafe impl Sync for JobGuard {}

    impl JobGuard {
        fn create_kill_on_close() -> io::Result<Self> {
            // SAFETY: Null security attributes and null name create an anonymous job.
            let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
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

        fn assign_handle(&self, process: HANDLE) -> io::Result<()> {
            // SAFETY: Both `self.handle` and `process` are live kernel handles.
            let ok = unsafe { AssignProcessToJobObject(self.handle, process) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        fn active_processes(&self) -> io::Result<u32> {
            // SAFETY: Zeroed POD struct for `QueryInformationJobObject`.
            let mut acct: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
            // SAFETY: `self.handle` is live and `acct` has exact size.
            let ok = unsafe {
                QueryInformationJobObject(
                    self.handle,
                    JobObjectBasicAccountingInformation,
                    (&raw mut acct).cast(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(acct.ActiveProcesses)
        }

        fn terminate_and_drain(&self) -> io::Result<()> {
            // SAFETY: `self.handle` is a live job handle owned by `self`.
            let ok = unsafe { TerminateJobObject(self.handle, 1) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            let deadline = Instant::now() + KILL_DRAIN_TIMEOUT;
            loop {
                if self.active_processes()? == 0 {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::other(
                        "Windows Job Object still has active processes after TerminateJobObject",
                    ));
                }
                std::thread::sleep(KILL_POLL_INTERVAL);
            }
        }
    }

    impl Drop for JobGuard {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                // SAFETY: `self.handle` is uniquely owned and closed once on drop.
                unsafe {
                    CloseHandle(self.handle);
                }
            }
        }
    }

    #[derive(Clone)]
    pub(super) struct KillerState {
        job: Arc<JobGuard>,
    }

    impl KillerState {
        pub(super) fn kill_tree(&self) -> io::Result<()> {
            self.job.terminate_and_drain()
        }
    }

    fn create_inheritable_pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 1,
        };
        let mut read_raw = ptr::null_mut();
        let mut write_raw = ptr::null_mut();
        // SAFETY: `CreatePipe` writes two valid handles on success.
        if unsafe { CreatePipe(&mut read_raw, &mut write_raw, &sa, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Both raw handles were just created and uniquely owned.
        let read = unsafe { OwnedHandle::from_raw_handle(read_raw) };
        // SAFETY: Both raw handles were just created and uniquely owned.
        let write = unsafe { OwnedHandle::from_raw_handle(write_raw) };
        // Parent's read end must NOT be inherited by the child.
        // SAFETY: `read` is a live pipe handle.
        if unsafe { SetHandleInformation(read.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((read, write))
    }

    fn open_nul_inheritable() -> io::Result<OwnedHandle> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 1,
        };
        let nul: Vec<u16> = "NUL\0".encode_utf16().collect();
        // SAFETY: `nul` is NUL-terminated and `sa` is valid for this call.
        let raw = unsafe {
            CreateFileW(
                nul.as_ptr(),
                windows_sys::Win32::Foundation::GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &sa,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `CreateFileW` transferred one uniquely owned handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
    }

    fn quote_win_arg(arg: &OsStr, out: &mut Vec<u16>) {
        let units: Vec<u16> = arg.encode_wide().collect();
        let needs_quotes = units.is_empty()
            || units
                .iter()
                .any(|&u| u == b' ' as u16 || u == b'\t' as u16 || u == b'"' as u16);
        if !needs_quotes {
            out.extend_from_slice(&units);
            return;
        }
        out.push(b'"' as u16);
        let mut backslashes = 0usize;
        for u in units {
            if u == b'\\' as u16 {
                backslashes += 1;
            } else if u == b'"' as u16 {
                for _ in 0..(backslashes * 2 + 1) {
                    out.push(b'\\' as u16);
                }
                out.push(b'"' as u16);
                backslashes = 0;
            } else {
                for _ in 0..backslashes {
                    out.push(b'\\' as u16);
                }
                backslashes = 0;
                out.push(u);
            }
        }
        for _ in 0..(backslashes * 2) {
            out.push(b'\\' as u16);
        }
        out.push(b'"' as u16);
    }

    fn build_win_cmdline(command: &OsStr, args: &[OsString]) -> Vec<u16> {
        let mut out = Vec::new();
        quote_win_arg(command, &mut out);
        for arg in args {
            out.push(b' ' as u16);
            quote_win_arg(arg, &mut out);
        }
        out.push(0);
        out
    }

    fn build_win_env_block(entries: &[(OsString, OsString)]) -> Vec<u16> {
        let mut out = Vec::new();
        for (k, v) in entries {
            out.extend(k.encode_wide());
            out.push(b'=' as u16);
            out.extend(v.encode_wide());
            out.push(0);
        }
        if out.is_empty() {
            out.push(0);
        }
        out.push(0);
        out
    }

    pub(super) struct Inner {
        process: OwnedHandle,
        killer: KillerState,
        reaped_exit: Option<ContainedExit>,
    }

    impl Inner {
        pub(super) fn spawn(spec: ContainedChildSpec) -> io::Result<(Self, File, File)> {
            let job = Arc::new(JobGuard::create_kill_on_close()?);
            let stdin_nul = open_nul_inheritable()?;
            let (stdout_read, stdout_write) = create_inheritable_pipe()?;
            let (stderr_read, stderr_write) = create_inheritable_pipe()?;

            let mut cmdline = build_win_cmdline(&spec.command, &spec.args);
            let env_block = build_win_env_block(&build_sanitized_env(&spec.env));
            let mut cwd_wide: Vec<u16> = spec.cwd.as_os_str().encode_wide().collect();
            cwd_wide.push(0);

            // SAFETY: Zeroed POD `STARTUPINFOW` with explicit stdio handles.
            let mut si: STARTUPINFOW = unsafe { zeroed() };
            si.cb = size_of::<STARTUPINFOW>() as u32;
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = stdin_nul.as_raw_handle();
            si.hStdOutput = stdout_write.as_raw_handle();
            si.hStdError = stderr_write.as_raw_handle();

            // SAFETY: Zeroed POD output struct for `CreateProcessW`.
            let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
            let flags = CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_NEW_PROCESS_GROUP
                | CREATE_UNICODE_ENVIRONMENT;
            // SAFETY: `cmdline`, `env_block`, `cwd_wide`, and `si` remain valid for this call.
            // `CREATE_SUSPENDED` prevents the child from executing any instruction before
            // `AssignProcessToJobObject` attaches it to the `KILL_ON_JOB_CLOSE` Job Object.
            let ok = unsafe {
                CreateProcessW(
                    ptr::null(),
                    cmdline.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    1,
                    flags,
                    env_block.as_ptr().cast(),
                    cwd_wide.as_ptr(),
                    &si,
                    &mut pi,
                )
            };
            drop(stdin_nul);
            drop(stdout_write);
            drop(stderr_write);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `CreateProcessW` succeeded and transferred unique ownership of both handles.
            let process = unsafe { OwnedHandle::from_raw_handle(pi.hProcess) };
            // SAFETY: `CreateProcessW` succeeded and transferred unique ownership of both handles.
            let thread = unsafe { OwnedHandle::from_raw_handle(pi.hThread) };

            if let Err(err) = job.assign_handle(process.as_raw_handle()) {
                // SAFETY: `process` is a live suspended process we own; terminate before failing.
                unsafe {
                    TerminateProcess(process.as_raw_handle(), 1);
                }
                return Err(err);
            }
            // SAFETY: `thread` is the suspended primary thread now inside `job`.
            if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
                let err = io::Error::last_os_error();
                let _ = job.terminate_and_drain();
                return Err(err);
            }
            drop(thread);

            Ok((
                Self {
                    process,
                    killer: KillerState { job },
                    reaped_exit: None,
                },
                File::from(stdout_read),
                File::from(stderr_read),
            ))
        }

        pub(super) fn killer(&self) -> KillerState {
            self.killer.clone()
        }

        pub(super) fn try_wait(&mut self) -> io::Result<Option<ContainedExit>> {
            if let Some(exit) = &self.reaped_exit {
                return Ok(Some(exit.clone()));
            }
            // SAFETY: `self.process` is a live process handle.
            let rc = unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) };
            if rc == WAIT_TIMEOUT {
                return Ok(None);
            }
            if rc != WAIT_OBJECT_0 {
                return Err(io::Error::last_os_error());
            }
            let exit = self.read_exit_code()?;
            self.reaped_exit = Some(exit.clone());
            Ok(Some(exit))
        }

        pub(super) fn wait(&mut self) -> io::Result<ContainedExit> {
            if let Some(exit) = &self.reaped_exit {
                return Ok(exit.clone());
            }
            // SAFETY: `self.process` is a live process handle.
            let rc = unsafe { WaitForSingleObject(self.process.as_raw_handle(), u32::MAX) };
            if rc != WAIT_OBJECT_0 {
                return Err(io::Error::last_os_error());
            }
            let exit = self.read_exit_code()?;
            self.reaped_exit = Some(exit.clone());
            Ok(exit)
        }

        fn read_exit_code(&self) -> io::Result<ContainedExit> {
            let mut code = 0u32;
            // SAFETY: `self.process` is a live exited process handle.
            if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(ContainedExit {
                exit_code: Some(code),
                signal: None,
            })
        }
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            let _ = self.killer.kill_tree();
        }
    }
}

#[cfg(unix)]
use unix_imp as imp;
#[cfg(windows)]
use win_imp as imp;

/// Thread-safe handle that terminates the contained process tree without
/// blocking behind `wait()`.
#[derive(Clone)]
pub struct ContainedKiller(imp::KillerState);

impl ContainedKiller {
    /// Terminate the entire contained process tree and wait until the OS
    /// witnesses no surviving members (process group `ESRCH` on Unix, Job
    /// Object `ActiveProcesses == 0` on Windows). Never kills by process name.
    pub fn kill_tree(&self) -> io::Result<()> {
        self.0.kill_tree()
    }
}

/// An OS-contained child process whose entire descendant tree is killed on
/// [`ContainedChild::kill_tree`] or [`Drop`].
pub struct ContainedChild(imp::Inner);

impl ContainedChild {
    /// Spawn a contained child process with sanitized baseline environment,
    /// piped stdout/stderr, and null stdin.
    pub fn spawn(spec: ContainedChildSpec) -> io::Result<(Self, File, File)> {
        let (inner, stdout, stderr) = imp::Inner::spawn(spec)?;
        Ok((Self(inner), stdout, stderr))
    }

    /// Return a thread-safe killer handle for concurrent termination.
    pub fn killer(&self) -> ContainedKiller {
        ContainedKiller(self.0.killer())
    }

    /// Non-blocking exit check.
    pub fn try_wait(&mut self) -> io::Result<Option<ContainedExit>> {
        self.0.try_wait()
    }

    /// Blocking wait until the child exits.
    pub fn wait(&mut self) -> io::Result<ContainedExit> {
        self.0.wait()
    }

    /// Terminate the entire contained process tree.
    pub fn kill_tree(&mut self) -> io::Result<()> {
        self.0.killer().kill_tree()
    }
}
