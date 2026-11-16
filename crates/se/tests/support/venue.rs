//! Venue-aware host controls. On a hosted Windows runner every same-user
//! process is contained in the runner's job, so no detached (outside-all-jobs)
//! runtime host can be launched from it. These controls classify the venue
//! with the same broker scan a launch would run, drive the product's own
//! reported foreground host where a control needs a live host, and report the
//! detached coverage the venue cannot grade. Absent and unreadable stay
//! separate facts.
use std::{
    io::Read,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Venue {
    /// A detached runtime host can be launched from this venue (or this is
    /// not Windows, where startup is never job-constrained).
    Detached,
    /// No verified same-user detached broker: `examined` same-user processes
    /// were fully verified as non-brokers and `unreadable` process contexts
    /// could not be verified.
    NoBroker { examined: usize, unreadable: usize },
}
impl Venue {
    pub fn is_no_broker(&self) -> bool {
        matches!(self, Self::NoBroker { .. })
    }
    /// The one venue fact a control prints when reporting unsupported coverage.
    pub fn coverage(&self) -> String {
        match self {
            Self::Detached => "a detached runtime host can be launched from this venue".into(),
            Self::NoBroker {
                examined,
                unreadable,
            } => format!(
                "no verified detached broker among {examined} examined same-user processes; {unreadable} process contexts unreadable"
            ),
        }
    }
}
/// Classifies whether this venue can launch a detached runtime host using the
/// same broker scan a launch would run; no process is created. `home` reads
/// the persisted machine id when present, otherwise a synthetic label is
/// stamped (the probe discards the identities it reads, so the label is inert).
pub fn probe(home: Option<&Path>) -> Check<Venue> {
    #[cfg(windows)]
    {
        let machine = match home {
            Some(home) => {
                let bytes = std::fs::read(home.join("machine.json"))?;
                let parsed: serde_json::Value = serde_json::from_slice(&bytes)?;
                let id = parsed["machine_id"]
                    .as_str()
                    .ok_or("home machine.json has no machine_id")?;
                se_types::MachineId::new(id)
                    .map_err(|error| format!("home machine.json is not a machine id: {error}"))?
            }
            None => se_types::MachineId::new("control-venue-probe")
                .map_err(|error| format!("venue probe label is not a machine id: {error}"))?,
        };
        Ok(match se_proc::detached_venue(&machine, Instant::now() + Duration::from_secs(45))? {
            se_proc::DetachedVenue::NoBroker {
                examined,
                unreadable,
            } => Venue::NoBroker {
                examined,
                unreadable,
            },
            _ => Venue::Detached,
        })
    }
    #[cfg(not(windows))]
    {
        let _ = home;
        Ok(Venue::Detached)
    }
}
/// Extracts the host PID from a public `se status --json` value, or `None`
/// while the runtime is not running.
pub fn status_pid(value: &serde_json::Value) -> Check<Option<u32>> {
    match value["runtime"]["state"].as_str() {
        Some("running") => {
            let pid = value["runtime"]["process"]["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .ok_or("running status carries no host PID")?;
            Ok(Some(pid))
        }
        _ => Ok(None),
    }
}
/// The product's own reported foreground host: the spawned `se up` is the
/// host. It is observed and stopped through the public CLI from this separate
/// client, exactly as the pinned no-broker contract requires.
pub struct Foreground {
    child: Arc<Mutex<Option<Child>>>,
    captured: Arc<Mutex<(Vec<u8>, Vec<u8)>>>,
}
impl Foreground {
    /// Spawns an already-configured `se up` command with captured stdio.
    pub fn spawn(mut command: Command) -> Check<Self> {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let child = command.spawn()?;
        let captured = Arc::new(Mutex::new((Vec::new(), Vec::new())));
        if let Some(mut stdout) = child.stdout.take() {
            let sink = Arc::clone(&captured);
            std::thread::spawn(move || {
                let mut buffer = Vec::new();
                let _ = stdout.read_to_end(&mut buffer);
                sink.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .0 = buffer;
            });
        }
        if let Some(mut stderr) = child.stderr.take() {
            let sink = Arc::clone(&captured);
            std::thread::spawn(move || {
                let mut buffer = Vec::new();
                let _ = stderr.read_to_end(&mut buffer);
                sink.lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .1 = buffer;
            });
        }
        Ok(Self {
            child: Arc::new(Mutex::new(Some(child))),
            captured,
        })
    }
    /// Polls the public status reader until the foreground host reports
    /// running. `status` returns the host PID when running, `None` while
    /// startup is pending, or an error to fail the fixture.
    pub fn wait_running(
        &self,
        until: Instant,
        mut status: impl FnMut() -> Check<Option<u32>>,
    ) -> Check<u32> {
        loop {
            let exited = self.child.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(child) = exited.as_ref()
                && let Some(exit) = child.try_wait()?
            {
                return Err(self.reported(format!(
                    "foreground host exited before reporting running (exit {exit})"
                )));
            }
            match status() {
                Ok(Some(pid)) => return Ok(pid),
                Ok(None) => (),
                Err(error) => return Err(error),
            }
            if Instant::now() >= until {
                return Err(self.reported(
                    "foreground host did not report running within the fixture bound",
                ));
            }
            std::thread::park_timeout(Duration::from_millis(100));
        }
    }
    /// Waits for the foreground host to report running; on any failure, stops
    /// the exact spawned host through the public CLI and proves the exact
    /// child exited before reporting the original error.
    pub fn start_up(
        &self,
        until_running: Instant,
        until_exit: Instant,
        status: impl FnMut() -> Check<Option<u32>>,
        mut down: impl FnMut() -> Check<std::process::Output>,
    ) -> Check<u32> {
        match self.wait_running(until_running, status) {
            Ok(pid) => Ok(pid),
            Err(error) => {
                let _ = down();
                let _ = self.wait_for_exit(until_exit);
                Err(error)
            }
        }
    }
    /// Waits for the exact spawned host to exit after a public stop.
    pub fn wait_for_exit(&self, until: Instant) -> Check<()> {
        loop {
            let mut child = self
                .child
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match child.as_mut() {
                None => return Ok(()),
                Some(child) => match child.try_wait()? {
                    Some(_) => {
                        *child = None;
                        return Ok(());
                    }
                    None => (),
                },
            }
            if Instant::now() >= until {
                return Err(self.reported(
                    "exact spawned host did not exit after public shutdown",
                ));
            }
            std::thread::park_timeout(Duration::from_millis(10));
        }
    }
    /// Reaps the exact spawned host after an outside observer proved its exit.
    pub fn reap(&self) {
        let mut child = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(child) = child.as_mut() {
            let _ = child.wait();
        }
        *child = None;
    }
    /// Stops the exact spawned host as a last resort so a failed fixture
    /// never leaks a running host; the child is this process's direct child.
    pub fn stop(&self) {
        let mut child = self
            .child
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(child) = child.as_mut() {
            if child.try_wait().is_ok_and(|exit| exit.is_none()) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        *child = None;
    }
    fn reported(&self, reason: String) -> Box<dyn std::error::Error> {
        let (stdout, stderr) = {
            let captured = self
                .captured
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                String::from_utf8_lossy(&captured.0).into_owned(),
                String::from_utf8_lossy(&captured.1).into_owned(),
            )
        };
        format!("{reason}; stdout: {stdout}; stderr: {stderr}").into()
    }
}
impl Drop for Foreground {
    fn drop(&mut self) {
        self.stop();
    }
}
