//! Coalesced idle and growth notifications; no SQLite state or I/O.
use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Default)]
struct Edges {
    idle_at: Option<Instant>,
    growth: bool,
}
#[derive(Clone, Default)]
pub(crate) struct Wake(Arc<(Mutex<Edges>, Condvar)>);

impl Wake {
    pub(crate) fn idle(&self) {
        let (lock, condition) = &*self.0;
        let mut edges = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        edges.idle_at = Some(Instant::now());
        condition.notify_all();
    }
    pub(crate) fn growth(&self) {
        let (lock, condition) = &*self.0;
        let mut edges = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        edges.growth = true;
        condition.notify_all();
    }
    pub(crate) fn take_growth(&self) -> bool {
        let mut edges = self
            .0
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut edges.growth)
    }
    /// Idle edges restart quiet time; growth and shutdown bypass it. A debt
    /// retry supplies a cap, but an otherwise settled host waits indefinitely.
    pub(crate) fn wait(&self, closed: &AtomicBool, cap: Option<Duration>, quiet: Duration) -> bool {
        let deadline = cap.map(|cap| Instant::now() + cap);
        let (lock, condition) = &*self.0;
        let mut edges = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        while !closed.load(Ordering::Acquire) && !edges.growth {
            match edges.idle_at.map(|edge| edge + quiet).or(deadline) {
                None => {
                    edges = condition
                        .wait(edges)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break;
                    }
                    edges = condition
                        .wait_timeout(edges, left)
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .0;
                }
            }
        }
        edges.idle_at = None;
        closed.load(Ordering::Acquire)
    }
}
