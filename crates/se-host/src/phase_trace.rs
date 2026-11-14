//! Temporary client timing spans; no authority, credentials or payload bytes.
pub(crate) fn profile_phase<T>(name: &str, action: impl FnOnce() -> T) -> T {
    let started = std::time::Instant::now();
    let value = action();
    if std::env::var_os("SE_CLI_PHASE_PROFILE").is_some() {
        eprintln!("cli.phase {} {}", name, started.elapsed().as_nanos());
    }
    value
}
