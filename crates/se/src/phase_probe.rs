//! Diagnostic-only monotonic clocks for an attribution build.
use std::{
    sync::{Mutex, OnceLock},
    time::Instant,
};
static CLOCK: OnceLock<(Instant, Mutex<Vec<(&'static str, u128)>>)> = OnceLock::new();
pub struct Guard;
pub fn begin() -> Guard {
    if std::env::var_os("SE_OBSERVE_PHASES").is_some() {
        let _ = CLOCK.set((Instant::now(), Mutex::new(Vec::new())));
        mark("main.enter");
    }
    Guard
}
pub fn mark(label: &'static str) {
    if let Some((start, events)) = CLOCK.get() {
        if let Ok(mut events) = events.lock() {
            events.push((label, start.elapsed().as_nanos()));
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        mark("main.exit");
        if let Some((_, events)) = CLOCK.get() {
            if let Ok(events) = events.lock() {
                eprintln!(
                    "AGENT_PHASE_TRACE {}",
                    serde_json::json!({
                        "pid": std::process::id(), "events": *events,
                    })
                );
            }
        }
    }
}
