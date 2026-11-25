//! The four host capabilities history import needs. The host keeps its
//! blocking pool, read-pin generation checks and writer pipeline behind them.
use se_harness::Deadline;
use se_store::{Admission, AtomicBatch, CommitReceipt, Profile, SqliteSnapshot};
use se_types::{Read, Result};
use std::{future::Future, pin::Pin, sync::Arc};

pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
pub type Context = Arc<dyn HistoryPort>;
/// Work for one foreground job; its value returns through the caller's channel.
pub type BlockingWork = Box<dyn FnOnce() -> Result<()> + Send>;
/// Reads under one owner pin; the host closes the pin after it returns.
pub type ReadPin<'a> = Box<dyn FnOnce(&mut SqliteSnapshot) -> Result<()> + 'a>;

pub trait HistoryPort: Send + Sync + 'static {
    /// Run one finite foreground job; no read handle outlives it.
    fn run_blocking<'a>(&'a self, deadline: &'a Deadline, work: BlockingWork)
    -> PortFuture<'a, ()>;
    /// One generation-checked owner read pin, closed before returning.
    fn snapshot(&self, admission: &Admission, read: ReadPin<'_>) -> Result<()>;
    /// Commit through the host's ordinary writer and pending-write observer.
    fn append<'a>(
        &'a self,
        batch: AtomicBatch,
        deadline: &'a Deadline,
    ) -> PortFuture<'a, CommitReceipt>;
    /// Profiles of the active owner configuration, if a coordinator exposes them.
    fn owner_profiles(&self) -> Read<Vec<Profile>>;
}
