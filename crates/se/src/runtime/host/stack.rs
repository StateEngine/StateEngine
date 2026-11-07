//! The Windows PE entry stack is 1 MiB. Nested debug launch/checkpoint
//! futures exceed that budget; run the standalone loop on an explicit stack
//! in every build profile, without changing process identity or custody.
use se_types::Result;

pub(super) fn run<T: Send>(work: impl FnOnce() -> T + Send) -> Result<T> {
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("se-host".into())
            // Eight MiB matches the ordinary Linux main-thread budget and
            // leaves room for launch, stop and recovery planning in debug.
            .stack_size(8 * 1024 * 1024)
            .spawn_scoped(scope, work)
            .map_err(|error| {
                se_core::scope::unreadable("Windows host executor stack", &error.to_string())
                    .with_cause(error)
            })?;
        match worker.join() {
            Ok(result) => Ok(result),
            // Preserve the existing panic/unwind and bootstrap-guard behavior.
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}
