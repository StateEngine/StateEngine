use super::*;
use std::{
    mem::zeroed,
    os::{fd::OwnedFd, unix::process::CommandExt},
    process::{Child, Command, Stdio},
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

fn siginfo_pid(info: &libc::siginfo_t) -> libc::pid_t {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `waitid` populated `info` with a valid `SIGCHLD` record.
        unsafe { info.si_pid() }
    }
    #[cfg(not(target_os = "linux"))]
    {
        info.si_pid
    }
}

fn siginfo_status(info: &libc::siginfo_t) -> i32 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `waitid` populated `info` with a valid `SIGCHLD` record.
        unsafe { info.si_status() }
    }
    #[cfg(not(target_os = "linux"))]
    {
        info.si_status
    }
}

fn exit_from_siginfo(info: &libc::siginfo_t) -> ContainedExit {
    let status = siginfo_status(info);
    if info.si_code == libc::CLD_EXITED {
        ContainedExit {
            exit_code: u32::try_from(status).ok(),
            signal: None,
        }
    } else {
        ContainedExit {
            exit_code: None,
            signal: Some(unix_signal_name(status)),
        }
    }
}

fn exit_from_wait_status(status: libc::c_int) -> ContainedExit {
    if libc::WIFSIGNALED(status) {
        ContainedExit {
            exit_code: None,
            signal: Some(unix_signal_name(libc::WTERMSIG(status))),
        }
    } else if libc::WIFEXITED(status) {
        ContainedExit {
            exit_code: u32::try_from(libc::WEXITSTATUS(status)).ok(),
            signal: None,
        }
    } else {
        ContainedExit {
            exit_code: None,
            signal: None,
        }
    }
}

/// Non-blocking, non-reaping check whether the leader process has exited.
/// Uses `waitid(P_PID, pgid, ..., WEXITED | WNOHANG | WNOWAIT)` so the leader's
/// zombie and `pgid` remain pinned in the kernel until `kill_tree_until` reaps it.
fn leader_is_exited_no_reap(pgid: libc::pid_t) -> io::Result<bool> {
    loop {
        // SAFETY: Zero initialization is the documented `waitid` no-event state.
        let mut info: libc::siginfo_t = unsafe { zeroed() };
        // SAFETY: Exact unreaped child owned by this process; `WNOWAIT` retains
        // the PID/PGID pin and `WNOHANG` never blocks.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                pgid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Ok(siginfo_pid(&info) != 0);
    }
}

/// On Darwin/XNU, `kill(-pgid, sig)` returns `EPERM` when every remaining
/// member of the process group is already a zombie waiting to be reaped.
fn is_darwin_eperm(err: &io::Error) -> bool {
    #[cfg(target_os = "macos")]
    {
        err.raw_os_error() == Some(libc::EPERM)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = err;
        false
    }
}

struct UnixGroupState {
    /// Captured leader exit status, preserved across `kill_tree_until` reap so
    /// subsequent `wait()` / `terminal/output` / `terminal/wait_for_exit` keep
    /// reporting the exact exit code or signal.
    observed_exit: Option<ContainedExit>,
    /// `false` while the session leader remains unreaped (which pins `pgid` in
    /// the kernel). Once `true`, `SIGKILL` is never sent to `-pgid` again.
    leader_reaped: bool,
    /// `true` ONLY once `leader_reaped == true` AND `kill(-pgid, 0) == ESRCH`
    /// has been witnessed.
    group_empty: bool,
}

#[derive(Clone)]
pub(super) struct KillerState {
    pgid: libc::pid_t,
    state: Arc<Mutex<UnixGroupState>>,
}

impl KillerState {
    /// Signal `-pgid` with `SIGKILL` while the unreaped leader pins `pgid`.
    /// Containment boundary: POSIX process-group signalling reaches every
    /// descendant remaining in `-pgid`; a descendant that calls `setsid` or
    /// `setpgid` leaves this process group and cannot be targeted by `-pgid`.
    /// On Darwin, `EPERM` is accepted only when `waitid(WNOWAIT)` independently
    /// witnesses that the leader has already exited.
    fn signal_group_while_pinned(&self) -> io::Result<()> {
        // SAFETY: Negative `pgid` targets only this child's isolated group,
        // and the caller holds `state` with `leader_reaped == false`, proving
        // the unreaped leader still pins `pgid` in the kernel.
        let rc = unsafe { libc::kill(-self.pgid, libc::SIGKILL) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(());
            }
            if is_darwin_eperm(&err) && leader_is_exited_no_reap(self.pgid)? {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }

    /// Terminate the entire process group `-pgid` up to `deadline`:
    /// 1. While the leader is unreaped (`pgid` kernel-pinned), send `SIGKILL`
    ///    to `-pgid`, then reap the leader via `waitpid(pgid, ..., WNOHANG)`
    ///    while preserving its exit status in `state.observed_exit`.
    /// 2. After reaping the leader (never sending `SIGKILL` to the numeric
    ///    `pgid` again), probe `kill(-pgid, 0)` up to `deadline` until `ESRCH`
    ///    witnesses that EVERY member of `-pgid` has terminated.
    pub(super) fn kill_tree_until(&self, deadline: Instant) -> io::Result<()> {
        // Phase 1: signal -pgid while the unreaped leader pins pgid, then reap
        // the leader without holding `self.state` across sleeps so concurrent
        // callers never block past their own deadlines.
        loop {
            let mut should_sleep = false;
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| io::Error::other("contained killer state poisoned"))?;
                if state.group_empty {
                    return Ok(());
                }
                if state.leader_reaped {
                    break;
                }
                self.signal_group_while_pinned()?;
                let mut raw_status: libc::c_int = 0;
                // SAFETY: Exact unreaped child owned by this process;
                // `state` lock prevents double-reap.
                let rc = unsafe { libc::waitpid(self.pgid, &mut raw_status, libc::WNOHANG) };
                if rc == self.pgid {
                    if state.observed_exit.is_none() {
                        state.observed_exit = Some(exit_from_wait_status(raw_status));
                    }
                    state.leader_reaped = true;
                    break;
                }
                if rc < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() != io::ErrorKind::Interrupted {
                        return Err(err);
                    }
                } else {
                    should_sleep = true;
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::other(format!(
                    "contained leader {} did not exit after SIGKILL before deadline",
                    self.pgid
                )));
            }
            if should_sleep {
                std::thread::sleep(KILL_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
            }
        }
        // Phase 2: leader is now reaped; probe `kill(-pgid, 0)` only until
        // `ESRCH` witnesses that all non-leader descendants in `-pgid` exited.
        loop {
            // SAFETY: Signal 0 only probes whether any member remains in `-pgid`.
            let probe = unsafe { libc::kill(-self.pgid, 0) };
            if probe < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ESRCH) {
                    if let Ok(mut state) = self.state.lock() {
                        state.group_empty = true;
                    }
                    return Ok(());
                }
                if !is_darwin_eperm(&err) {
                    return Err(err);
                }
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::other(format!(
                    "contained process group {} still has live descendants after SIGKILL",
                    self.pgid
                )));
            }
            std::thread::sleep(KILL_POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
        }
    }
}

pub(super) struct Inner {
    _child: Child,
    killer: KillerState,
    skip_drop_drain: bool,
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
            state: Arc::new(Mutex::new(UnixGroupState {
                observed_exit: None,
                leader_reaped: false,
                group_empty: false,
            })),
        };
        Ok((
            Self {
                _child: child,
                killer,
                skip_drop_drain: false,
            },
            File::from(OwnedFd::from(stdout)),
            File::from(OwnedFd::from(stderr)),
        ))
    }

    pub(super) fn killer(&self) -> KillerState {
        self.killer.clone()
    }

    fn wait_no_reap(&mut self, flags: libc::c_int) -> io::Result<Option<ContainedExit>> {
        if let Ok(state) = self.killer.state.lock()
            && let Some(exit) = &state.observed_exit
        {
            return Ok(Some(exit.clone()));
        }
        loop {
            // SAFETY: Zero initialization is the documented `waitid` no-event state.
            let mut info: libc::siginfo_t = unsafe { zeroed() };
            // SAFETY: Exact unreaped child owned by `self`; `WNOWAIT` retains
            // the leader's PID/PGID in the kernel until `kill_tree_until`.
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.killer.pgid as libc::id_t,
                    &mut info,
                    flags,
                )
            };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if err.raw_os_error() == Some(libc::ECHILD)
                    && let Ok(state) = self.killer.state.lock()
                    && let Some(exit) = &state.observed_exit
                {
                    return Ok(Some(exit.clone()));
                }
                return Err(err);
            }
            if siginfo_pid(&info) == 0 {
                return Ok(None);
            }
            let exit = exit_from_siginfo(&info);
            if let Ok(mut state) = self.killer.state.lock()
                && state.observed_exit.is_none()
            {
                state.observed_exit = Some(exit.clone());
            }
            return Ok(Some(exit));
        }
    }

    pub(super) fn try_wait(&mut self) -> io::Result<Option<ContainedExit>> {
        self.wait_no_reap(libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
    }

    pub(super) fn wait(&mut self) -> io::Result<ContainedExit> {
        self.wait_no_reap(libc::WEXITED | libc::WNOWAIT)?
            .ok_or_else(|| io::Error::other("waitid returned without child exit record"))
    }

    pub(super) fn terminate_and_reap_until(&mut self, deadline: Instant) -> io::Result<()> {
        self.killer.kill_tree_until(deadline)
    }

    pub(super) fn disarm_drop_drain(&mut self) {
        self.skip_drop_drain = true;
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if !self.skip_drop_drain {
            let _ = self
                .killer
                .kill_tree_until(Instant::now() + KILL_DRAIN_TIMEOUT);
        }
    }
}
