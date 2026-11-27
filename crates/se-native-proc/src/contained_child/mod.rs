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
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as imp;
#[cfg(windows)]
use windows as imp;

/// Thread-safe handle that terminates the contained process tree without
/// blocking behind `wait()`.
#[derive(Clone)]
pub struct ContainedKiller(imp::KillerState);

impl ContainedKiller {
    /// Terminate the entire contained process tree and wait until the OS
    /// witnesses no surviving members (process group `ESRCH` on Unix, Job
    /// Object `ActiveProcesses == 0` on Windows). Never kills by process name.
    pub fn kill_tree(&self) -> io::Result<()> {
        self.kill_tree_until(Instant::now() + KILL_DRAIN_TIMEOUT)
    }

    /// Terminate the entire contained process tree and wait up to `deadline`
    /// until the OS witnesses no surviving members.
    pub fn kill_tree_until(&self, deadline: Instant) -> io::Result<()> {
        self.0.kill_tree_until(deadline)
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
        self.0
            .killer()
            .kill_tree_until(Instant::now() + KILL_DRAIN_TIMEOUT)
    }

    /// Terminate the entire contained process tree, reap the leader (releasing
    /// its kernel PID/PGID witness only after `SIGKILL`), and wait up to
    /// `deadline` until the OS witnesses no surviving descendants.
    pub fn terminate_and_reap_until(&mut self, deadline: Instant) -> io::Result<()> {
        self.0.terminate_and_reap_until(deadline)
    }

    /// Skip the fallback blocking drain in `Drop` when a caller (such as a
    /// deadline-bounded destructor) has already attempted termination within
    /// its budget and must not restart a fresh drain.
    pub fn disarm_drop_drain(&mut self) {
        self.0.disarm_drop_drain();
    }
}
