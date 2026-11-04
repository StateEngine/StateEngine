//! Coalesced native nudges on the host's supplied reactor. Native state remains
//! authoritative; a wake is never an exit, exec or process-count witness.
use se_proc::{ExitNotice, ExitSink};
use std::sync::Arc;
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct Wake {
    pub event: Arc<Notify>,
}
impl ExitSink for Wake {
    fn notify(&self, _notice: ExitNotice) {
        self.event.notify_waiters();
        self.event.notify_one();
    }
}

#[cfg(unix)]
pub(crate) use super::reactor::Reactor;
