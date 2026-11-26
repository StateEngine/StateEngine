//! One background slot for optional reads a caller must not wait on past a
//! deadline. The caller stops waiting at the deadline; a late read finishes
//! on its own thread and frees the slot, so at most one is ever outstanding.
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Instant,
};

/// What a bounded read gave its caller.
#[derive(Debug)]
pub enum Bounded<T> {
    Done(T),
    /// The deadline passed first; the read finishes in the background.
    Late,
    /// An earlier late read still holds the slot.
    Busy,
    /// The read thread could not start, or stopped without an answer.
    Failed(String),
}

#[derive(Default)]
pub struct ReadSlot {
    busy: Arc<AtomicBool>,
}

/// Frees the slot when the read ends, even by unwinding.
struct Release(Arc<AtomicBool>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl ReadSlot {
    pub fn within<T: Send + 'static>(
        &self,
        deadline: Instant,
        read: impl FnOnce() -> T + Send + 'static,
    ) -> Bounded<T> {
        if self.busy.swap(true, Ordering::AcqRel) {
            return Bounded::Busy;
        }
        let release = Release(Arc::clone(&self.busy));
        let (send, receive) = mpsc::sync_channel(1);
        let spawned = thread::Builder::new()
            .name("se-atlas-bounded-read".into())
            .spawn(move || {
                let value = read();
                // Free the slot before answering, so a caller that got this
                // answer never finds its own read still holding it.
                drop(release);
                // The caller may have stopped waiting; a late answer is dropped.
                let _ = send.send(value);
            });
        if let Err(error) = spawned {
            return Bounded::Failed(format!("the read thread did not start: {error}"));
        }
        match receive.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(value) => Bounded::Done(value),
            Err(mpsc::RecvTimeoutError::Timeout) => Bounded::Late,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Bounded::Failed("the read thread stopped without an answer".into())
            }
        }
    }
}
