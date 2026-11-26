//! An open client call/watch extends an automatically started host's life.
//! An installed broker, saved link or enabled listener is not active work.
use crate::http::mail::Waits;
use se_types::{Result, SeError};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

pub(crate) struct Activity {
    // None retains the host after an accounting fault instead of claiming idle.
    count: Mutex<Option<usize>>,
    changed: Notify,
}
impl Activity {
    pub(crate) fn new() -> Self {
        Self {
            count: Mutex::new(Some(0)),
            changed: Notify::new(),
        }
    }
    fn idle(&self) -> bool {
        self.count.lock().is_ok_and(|count| *count == Some(0))
    }
}
pub(crate) struct Work(Arc<Waits>);
impl Waits {
    pub(crate) fn client_work(self: &Arc<Self>) -> Result<Work> {
        let mut count = self.client_activity.count.lock().map_err(|_| {
            SeError::invalid(
                "client activity",
                "readable owning host activity accounting",
            )
        })?;
        *count = count.and_then(|n| n.checked_add(1));
        if count.is_none() {
            return Err(SeError::invalid(
                "client activity",
                "an available activity counter",
            ));
        }
        self.client_activity.changed.notify_waiters();
        Ok(Work(self.clone()))
    }
}
impl Drop for Work {
    fn drop(&mut self) {
        if let Ok(mut count) = self.0.client_activity.count.lock() {
            *count = count.and_then(|n| n.checked_sub(1));
        }
        self.0.client_activity.changed.notify_waiters();
    }
}
/// The existing native idle window restarts after client work closes.
/// This shares the existing idle timer and adds no task or network subscription.
pub(crate) async fn idle(waits: Arc<Waits>, activity: &mut tokio::sync::watch::Receiver<u32>) {
    loop {
        let changed = waits.client_activity.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if !waits.client_activity.idle() {
            changed.await;
            continue;
        }
        let expiry = super::serve::idle_expiry(activity);
        tokio::select! { biased;
            _ = changed => (),
            _ = expiry => {
                if waits.client_activity.idle() { return; }
            }
        }
    }
}
