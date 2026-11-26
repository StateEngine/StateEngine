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

/// Non-blocking, non-reaping check whether the leader process has exited.
/// Uses `waitid(P_PID, pgid, ..., WEXITED | WNOHANG | WNOWAIT)` so the leader's
/// zombie and `pgid` remain pinned in the kernel until `terminate_and_reap`.
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

#[derive(Clone)]
pub(super) struct KillerState {
    pgid: libc::pid_t,
    /// `false` while the session leader remains unreaped (which pins `pgid`
    /// in the kernel so it cannot be recycled). Once `true`, `SIGKILL` is
    /// never sent to the numeric `pgid` again.
    leader_reaped: Arc<Mutex<bool>>,
}

impl KillerState {
    /// Signal `-pgid` with `SIGKILL` while the unreaped leader pins `pgid`.
    /// Containment boundary: POSIX process-group signalling reaches every
    /// descendant remaining in `-pgid`; a descendant that calls `setsid` or
    /// `setpgid` leaves this process group and cannot be targeted by `-pgid`.
    /// On Darwin, `EPERM` is only accepted when `waitid(WNOWAIT)` independently
    /// witnesses that the leader has already exited.
    fn signal_group_while_pinned(&self) -> io::Result<()> {
        // SAFETY: Negative `pgid` targets only this child's isolated group,
        // and the caller holds `leader_reaped` with value `false`, proving
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

    /// Signal `-pgid` with `SIGKILL` and wait (bounded by `KILL_DRAIN_TIMEOUT`)
    /// until `waitid(WNOWAIT)` witnesses that the leader has terminated, while
    /// keeping the leader unreaped so output/exit status and `pgid` identity
    /// remain intact for subsequent calls and `terminate_and_reap`.
    pub(super) fn kill_tree(&self) -> io::Result<()> {
        let reaped = self
            .leader_reaped
            .lock()
            .map_err(|_| io::Error::other("contained killer state poisoned"))?;
        if *reaped {
            return Ok(());
        }
        let deadline = Instant::now() + KILL_DRAIN_TIMEOUT;
        loop {
            self.signal_group_while_pinned()?;
            if leader_is_exited_no_reap(self.pgid)? {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "contained leader {} did not exit after SIGKILL",
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
    observed_exit: Option<ContainedExit>,
    reaped: bool,
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
            leader_reaped: Arc::new(Mutex::new(false)),
        };
        Ok((
            Self {
                child,
                killer,
                observed_exit: None,
                reaped: false,
            },
            File::from(OwnedFd::from(stdout)),
            File::from(OwnedFd::from(stderr)),
        ))
    }

    pub(super) fn killer(&self) -> KillerState {
        self.killer.clone()
    }

    fn wait_no_reap(&mut self, flags: libc::c_int) -> io::Result<Option<ContainedExit>> {
        if let Some(exit) = &self.observed_exit {
            return Ok(Some(exit.clone()));
        }
        loop {
            // SAFETY: Zero initialization is the documented `waitid` no-event state.
            let mut info: libc::siginfo_t = unsafe { zeroed() };
            // SAFETY: Exact unreaped child owned by `self`; `WNOWAIT` retains
            // the leader's PID/PGID in the kernel until `terminate_and_reap`.
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
                return Err(err);
            }
            if siginfo_pid(&info) == 0 {
                return Ok(None);
            }
            let exit = exit_from_siginfo(&info);
            self.observed_exit = Some(exit.clone());
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

    pub(super) fn terminate_and_reap(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + KILL_DRAIN_TIMEOUT;
        {
            let mut reaped = self
                .killer
                .leader_reaped
                .lock()
                .map_err(|_| io::Error::other("contained killer state poisoned"))?;
            if !self.reaped {
                // Signal the entire process group while the unreaped leader
                // still guarantees `pgid` ownership in the kernel.
                self.killer.signal_group_while_pinned()?;
                loop {
                    if self.child.try_wait()?.is_some() {
                        self.reaped = true;
                        *reaped = true;
                        break;
                    }
                    if Instant::now() >= deadline {
                        return Err(io::Error::other(format!(
                            "contained leader {} did not exit after SIGKILL",
                            self.killer.pgid
                        )));
                    }
                    std::thread::sleep(KILL_POLL_INTERVAL);
                }
            }
        }
        // Leader is now reaped; never send SIGKILL to the numeric pgid again.
        // Probe `kill(-pgid, 0)` only until `ESRCH` witnesses the group empty.
        loop {
            // SAFETY: Signal 0 only probes whether any member remains in `-pgid`.
            let probe = unsafe { libc::kill(-self.killer.pgid, 0) };
            if probe < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ESRCH) {
                    return Ok(());
                }
                if !is_darwin_eperm(&err) {
                    return Err(err);
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(format!(
                    "contained process group {} still has live descendants after SIGKILL",
                    self.killer.pgid
                )));
            }
            std::thread::sleep(KILL_POLL_INTERVAL);
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.terminate_and_reap();
    }
}
