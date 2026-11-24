//! For fixtures that start a runtime with plain commands: run the fixture's
//! own `down` on every return or panic, and keep a reaper armed for a test
//! process that is killed before any drop can run. The including test crate
//! declares `home_reaper` once, beside this module.
use crate::home_reaper::HomeReaper;
use std::{io, path::Path, process::Command};

/// For fixtures that start a runtime with plain commands: `down` on every
/// return or panic, and the reaper for a killed test process.
pub struct HostGuard {
    down: Command,
    _reaper: HomeReaper,
}

impl HostGuard {
    /// `cleared` states whether `down` called `env_clear`; see `HomeReaper`.
    pub fn arm(down: Command, home: &Path, cleared: bool) -> io::Result<Self> {
        Ok(Self {
            _reaper: HomeReaper::arm(&down, home, cleared)?,
            down,
        })
    }
}

impl Drop for HostGuard {
    fn drop(&mut self) {
        // A runtime already stopped by the test answers `down` as not running.
        match self.down.output() {
            Ok(output) if output.status.success() => {}
            Ok(output) => eprintln!(
                "test runtime cleanup `down` failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => eprintln!("test runtime cleanup `down` did not run: {error}"),
        }
    }
}
