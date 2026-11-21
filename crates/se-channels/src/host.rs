//! Host-supplied execution boundary for private messaging channels.
//! Keeps store reads, atomic commits, custody launches, and deadlines abstract
//! so `se-channels` never depends on `se-host`.
use se_core::{commit::Cx, ops::agent_launch::LaunchPlan};
use se_store::{Admission, AtomicBatch, CommitReceipt, SqliteSnapshot};
use se_types::{Generation, IdempotencyKey, Result, SeError, StoreId};
use std::{
    any::Any,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
pub type BoxedBlockingWork = Box<dyn FnOnce() -> Result<Box<dyn Any + Send>> + Send>;
pub type BoxedReadWork =
    Box<dyn FnOnce(&mut Cx<'_, SqliteSnapshot>) -> Result<Box<dyn Any + Send>> + Send>;

/// Remaining-time and cancellation bound shared between host calls and channel loops.
#[derive(Clone)]
pub struct ChannelDeadline {
    at: Instant,
    budget: Duration,
    cancelled: Arc<AtomicBool>,
}

impl ChannelDeadline {
    pub fn from_parts(at: Instant, budget: Duration, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            at,
            budget,
            cancelled,
        }
    }

    pub fn from_timeout(timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(SeError::invalid(
                "channel timeout",
                "a positive bounded duration",
            ));
        }
        let at = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| SeError::invalid("channel deadline", "a representable deadline"))?;
        let deadline = Self {
            at,
            budget: timeout,
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        deadline.remaining()?;
        Ok(deadline)
    }

    pub fn at(&self) -> Instant {
        self.at
    }

    pub fn cancelled(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    pub fn remaining(&self) -> Result<Duration> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(SeError::new(se_types::Detail::Cancelled(
                se_types::details::Cancelled {
                    op: "local IPC".into(),
                },
            )));
        }
        self.at
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                SeError::new(se_types::Detail::DeadlineExceeded(
                    se_types::details::DeadlineExceeded {
                        op: "local IPC".into(),
                        deadline_ms: self.budget.as_millis().min(u128::from(u64::MAX)) as u64,
                    },
                ))
            })
    }
}

/// Converts a host or channel deadline reference into a [`ChannelDeadline`].
pub trait AsChannelDeadline {
    fn as_channel_deadline(&self) -> ChannelDeadline;
}

impl AsChannelDeadline for ChannelDeadline {
    fn as_channel_deadline(&self) -> ChannelDeadline {
        self.clone()
    }
}

/// Narrow runtime port implemented by `se-host` to back [`crate::Channels`].
pub trait ChannelHost: Send + Sync {
    fn generation(&self) -> Generation;
    fn store_id(&self) -> StoreId;
    fn has_custody(&self) -> bool;
    fn run_blocking(
        &self,
        owned: bool,
        deadline: &ChannelDeadline,
        work: BoxedBlockingWork,
    ) -> HostFuture<'_, Box<dyn Any + Send>>;
    fn read_snapshot(
        &self,
        admission: Admission,
        deadline: &ChannelDeadline,
        work: BoxedReadWork,
    ) -> HostFuture<'_, Box<dyn Any + Send>>;
    fn submit_batch(
        &self,
        batch: AtomicBatch,
        operation: &'static str,
        key: IdempotencyKey,
        deadline: &ChannelDeadline,
    ) -> HostFuture<'_, CommitReceipt>;
    fn execute_launch(
        &self,
        plan: Box<LaunchPlan>,
        admission: Admission,
        deadline: &ChannelDeadline,
    ) -> HostFuture<'_, ()>;
}
