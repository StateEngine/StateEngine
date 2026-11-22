//! Narrow runtime port implemented by `se-host` to back the Atlas owner driver.
use crate::atlas_runtime::record_fence::RecordFeedFence;
use se_store::ReadPhase;
use se_types::{Generation, Result};
use std::{any::Any, future::Future, pin::Pin, sync::Arc, time::Duration};

pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
pub type BoxedWork = Box<dyn FnOnce() -> Result<Box<dyn Any + Send>> + Send>;

pub trait AtlasHost: Send + Sync {
    fn generation(&self) -> Generation;
    fn records(&self) -> &Arc<RecordFeedFence>;
    fn checked_read_phase(&self) -> Result<ReadPhase>;
    fn run_background_owned(
        &self,
        timeout: Duration,
        work: BoxedWork,
    ) -> HostFuture<'_, Box<dyn Any + Send>>;
    fn run_owned(
        &self,
        remaining: Duration,
        work: BoxedWork,
    ) -> HostFuture<'_, Box<dyn Any + Send>>;
}
