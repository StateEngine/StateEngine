//! Development-only native interval observations; no check is bypassed.
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub(in crate::state_files) struct Span {
    label: &'static str,
    start: Instant,
    wall: Option<u128>,
}
impl Span {
    pub(in crate::state_files) fn new(label: &'static str) -> Self {
        Self {
            label,
            start: Instant::now(),
            wall: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_micros()),
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_micros();
        eprintln!(
            "native-stage-timing {}",
            serde_json::json!({
                "pid":std::process::id(), "thread":format!("{:?}",std::thread::current().id()),
                "stage":self.label, "start_us":self.wall,
                "end_us":self.wall.map(|start|start+elapsed), "elapsed_us":elapsed,
                "scope":"inclusive interval, not a success or exit witness"
            })
        );
    }
}
