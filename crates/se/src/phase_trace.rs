//! Temporary CLI timing spans for author measurements; never records input bytes.
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(crate) struct Phase {
    name: &'static str,
    started: Instant,
    enabled: bool,
}
impl Phase {
    pub(crate) fn new(name: &'static str) -> Self {
        Self {
            name,
            started: Instant::now(),
            enabled: std::env::var_os("SE_CLI_PHASE_PROFILE").is_some(),
        }
    }
}
impl Drop for Phase {
    fn drop(&mut self) {
        if self.enabled {
            eprintln!(
                "cli.phase {} {}",
                self.name,
                self.started.elapsed().as_nanos()
            );
            if self.name == "cli_main" {
                event("main_exit");
            }
        }
    }
}
pub(crate) fn event(name: &str) {
    if std::env::var_os("SE_CLI_PHASE_PROFILE").is_some()
        && let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH)
    {
        eprintln!("cli.event {} {}", name, now.as_nanos());
    }
}
