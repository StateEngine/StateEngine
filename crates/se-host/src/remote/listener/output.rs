//! Revocation clears finite private queues and cancels the socket writer.
use super::*;
use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Notify;
pub(super) struct Queued {
    pub text: String,
    pub use_watch: bool,
}
pub(super) struct Output {
    queue: Mutex<(VecDeque<Queued>, usize, usize)>,
    pub wake: Notify,
    pub stop: Notify,
    pub invalid: AtomicBool,
    pub closed: AtomicBool,
}
impl Default for Output {
    fn default() -> Self {
        Self {
            queue: Mutex::new((VecDeque::new(), 0, 0)),
            wake: Notify::new(),
            stop: Notify::new(),
            invalid: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }
}
impl Output {
    /// Caller holds only the finite Security::output_fence, never a SQL pin.
    pub fn enqueue(&self, text: String, use_watch: bool) -> Result<()> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| super::super::channel::unavailable("client output queue unreadable"))?;
        if self.invalid.load(Ordering::Acquire) {
            return Err(super::super::channel::unavailable(
                "client output is fenced",
            ));
        }
        if queue.2 >= REMOTE_CLIENT_QUEUE_FRAMES
            || text.len() > REMOTE_CLIENT_QUEUE_BYTES.saturating_sub(queue.1)
        {
            return Err(super::super::channel::unavailable(
                "client output queue overflow; reconnect from consumed cursors",
            ));
        }
        queue.1 += text.len();
        queue.2 += 1;
        queue.0.push_back(Queued { text, use_watch });
        drop(queue);
        self.wake.notify_one();
        Ok(())
    }
    pub fn pop(&self) -> Result<Option<Queued>> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| super::super::channel::unavailable("client output queue unreadable"))?;
        if self.invalid.load(Ordering::Acquire) {
            queue.0.clear();
            queue.1 = 0;
            queue.2 = 0;
            return Ok(None);
        }
        Ok(queue.0.pop_front())
    }
    /// Retain the in-flight frame in the same queue budget until its flush ends.
    pub fn sent(&self, len: usize) -> Result<()> {
        let mut queue = self
            .queue
            .lock()
            .map_err(|_| super::super::channel::unavailable("client output queue unreadable"))?;
        if !self.invalid.load(Ordering::Acquire) {
            queue.1 = queue.1.checked_sub(len).ok_or_else(|| {
                super::super::channel::unavailable("client output byte accounting differs")
            })?;
            queue.2 = queue.2.checked_sub(1).ok_or_else(|| {
                super::super::channel::unavailable("client output frame accounting differs")
            })?;
        }
        Ok(())
    }
    pub fn invalidate(&self) {
        self.invalid.store(true, Ordering::Release);
        if let Ok(mut queue) = self.queue.lock() {
            queue.0.clear();
            queue.1 = 0;
            queue.2 = 0;
        }
        self.stop.notify_waiters();
        self.wake.notify_waiters();
    }
}
impl auth::OutputInvalidation for Output {
    fn invalidate(&self) {
        Output::invalidate(self)
    }
    fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}
