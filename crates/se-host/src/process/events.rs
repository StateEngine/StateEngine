//! Coalesced native nudges on the host's supplied reactor. Native state remains
//! authoritative; a wake is never an exit, exec or process-count witness.
use se_proc::{ExitNotice, ExitSink};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct Wake {
    pub event: Arc<Notify>,
    startup_stop: AtomicBool,
    pub awaiting_window: AtomicBool,
}
impl Wake {
    pub fn request_startup_stop(&self) {
        self.startup_stop.store(true, Ordering::Release);
        self.event.notify_waiters();
        self.event.notify_one();
    }
    pub fn require_startup(&self) -> se_types::Result<()> {
        if self.startup_stop.load(Ordering::Acquire) {
            return Err(se_types::SeError::new(se_types::Detail::Cancelled(
                se_types::details::Cancelled {
                    op: "agent launch readiness".into(),
                },
            )));
        }
        Ok(())
    }
    /// Only provider handshake waits may be interrupted here. The coordinator
    /// retains native custody, joins accepted effects, and runs normal cleanup;
    /// this never wraps native allocation or an accepted store commit.
    pub async fn readiness<T>(
        &self,
        future: impl std::future::Future<Output = se_types::Result<T>>,
    ) -> se_types::Result<T> {
        use std::{future::Future, task::Poll};
        let mut future = std::pin::pin!(future);
        loop {
            let changed = self.event.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.require_startup()?;
            let result = std::future::poll_fn(|cx| {
                if let Poll::Ready(value) = future.as_mut().poll(cx) {
                    return Poll::Ready(Some(value));
                }
                changed.as_mut().poll(cx).map(|()| None)
            })
            .await;
            if let Some(result) = result {
                return result;
            }
        }
    }
}
impl ExitSink for Wake {
    fn notify(&self, _notice: ExitNotice) {
        self.event.notify_waiters();
        self.event.notify_one();
    }
}

#[cfg(unix)]
pub(crate) use super::reactor::Reactor;
