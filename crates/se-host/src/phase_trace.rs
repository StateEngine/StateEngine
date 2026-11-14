//! Temporary phase observations for author measurements; no authority or payload bytes.
pub(crate) fn profile_phase<T>(name: &str, action: impl FnOnce() -> T) -> T {
    let started = std::time::Instant::now();
    let value = action();
    if std::env::var_os("SE_CLI_PHASE_PROFILE").is_some() {
        eprintln!("cli.phase {} {}", name, started.elapsed().as_nanos());
    }
    value
}

#[cfg(feature = "listener")]
pub(crate) struct HostPhaseSpan {
    name: &'static str,
    started: std::time::Instant,
}
#[cfg(feature = "listener")]
impl HostPhaseSpan {
    pub(crate) fn new(name: &'static str) -> Self {
        Self {
            name,
            started: std::time::Instant::now(),
        }
    }
}
#[cfg(feature = "listener")]
impl Drop for HostPhaseSpan {
    fn drop(&mut self) {
        let elapsed = self.started.elapsed().as_nanos();
        if let Some(path) = std::env::var_os("SE_HOST_PHASE_PROFILE") {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.append(true);
            if let Ok(mut file) = options.open(path) {
                let line = format!(
                    "host.phase {} {} {}\n",
                    std::process::id(),
                    self.name,
                    elapsed
                );
                let _ = file.write_all(line.as_bytes());
            }
        }
    }
}
