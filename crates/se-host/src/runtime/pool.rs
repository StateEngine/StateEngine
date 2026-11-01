//! Bounded shared finite-work slots on the supplied executor. At most one can
//! contain maintenance, leaving foreground capacity without another runtime.
use crate::client::lease::Deadline;
use se_types::{Result, SeError};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    runtime::Handle,
    sync::Semaphore,
    time::{Instant, timeout_at},
};

#[derive(Clone)]
pub struct BlockingPool {
    runtime: Handle,
    total: Arc<Semaphore>,
    background: Arc<Semaphore>,
    capacity: u32,
}
#[derive(Clone, Copy)]
pub enum BlockingClass {
    Foreground,
    Background,
}
impl BlockingPool {
    pub(crate) fn handle(&self) -> Handle {
        self.runtime.clone()
    }
    pub fn new(runtime: Handle) -> Self {
        Self::configured(runtime, se_core::config_policy::MIN_BLOCKING_JOBS)
    }
    pub fn with_jobs(runtime: Handle, jobs: std::num::NonZeroU32) -> Result<Self> {
        if !(se_core::config_policy::MIN_BLOCKING_JOBS..=se_core::config_policy::MAX_BLOCKING_JOBS)
            .contains(&jobs.get())
        {
            return Err(SeError::invalid(
                "host blocking jobs",
                "a finite cap in 2..=8",
            ));
        }
        Ok(Self::configured(runtime, jobs.get()))
    }
    fn configured(runtime: Handle, capacity: u32) -> Self {
        Self {
            runtime,
            total: Arc::new(Semaphore::new(capacity as usize)),
            background: Arc::new(Semaphore::new(1)),
            capacity,
        }
    }
    /// Listener native checks share the foreground admission with planning and
    /// continuation jobs. A timed-out job retains its slot until it really exits.
    pub fn foreground_admission(&self) -> Arc<Semaphore> {
        Arc::clone(&self.total)
    }
    pub async fn run<T, F>(&self, class: BlockingClass, deadline: &Deadline, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        deadline.remaining()?;
        // A maintenance job holds its gate before shared admission. At most
        // one such job can occupy a finite-work slot.
        let maintenance = match class {
            BlockingClass::Foreground => None,
            BlockingClass::Background => Some(
                within(deadline, Arc::clone(&self.background).acquire_owned())
                    .await?
                    .map_err(|_| pool_error("maintenance admission closed"))?,
            ),
        };
        let permit = within(deadline, Arc::clone(&self.total).acquire_owned())
            .await?
            .map_err(|_| pool_error("bounded blocking admission closed"))?;
        deadline.remaining()?;
        let job = self.runtime.spawn_blocking(move || {
            let _permits = (permit, maintenance);
            work()
        });
        let result = within(deadline, job)
            .await?
            .map_err(|error| pool_error(&format!("bounded blocking job failed: {error}")))?;
        deadline.remaining()?;
        result
    }
    /// Resource-producing/closing jobs must return their custody even if the
    /// caller's clock expires during native work. Admission is deadline-bound;
    /// the finite native job is joined, never detached with an owned result.
    pub(crate) async fn run_owned<T, F>(&self, deadline: &Deadline, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        let permit = self.admit_owned(deadline).await?;
        self.run_admitted_owned(permit, work).await
    }
    pub(crate) async fn admit_owned(
        &self,
        deadline: &Deadline,
    ) -> Result<tokio::sync::OwnedSemaphorePermit> {
        let permit = within(deadline, Arc::clone(&self.total).acquire_owned())
            .await?
            .map_err(|_| pool_error("owned-work admission closed"))?;
        deadline.remaining()?;
        Ok(permit)
    }
    pub(crate) async fn run_admitted_owned<T, F>(
        &self,
        permit: tokio::sync::OwnedSemaphorePermit,
        work: F,
    ) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        self.runtime
            .spawn_blocking(move || {
                let _permit = permit;
                work()
            })
            .await
            .map_err(|error| pool_error(&format!("owned blocking work failed: {error}")))?
    }
    /// Called after fencing admission and joining connection tasks. Acquire in
    /// maintenance's gate-then-shared order, so queued maintenance cannot deadlock
    /// against shutdown. Holding every shared permit also joins timed-out jobs.
    pub async fn quiesce(&self, deadline: &Deadline) -> Result<()> {
        let maintenance = within(deadline, Arc::clone(&self.background).acquire_owned())
            .await?
            .map_err(|_| pool_error("maintenance admission closed"))?;
        let total = within(
            deadline,
            Arc::clone(&self.total).acquire_many_owned(self.capacity),
        )
        .await?
        .map_err(|_| pool_error("shared blocking admission closed"))?;
        drop((total, maintenance));
        Ok(())
    }
}
/// Cancellation is observed while awaiting a queue slot or finite job. Dropping
/// a JoinHandle never frees its occupied permit or cancels native work.
pub(crate) async fn within<T>(deadline: &Deadline, future: impl Future<Output = T>) -> Result<T> {
    let mut future = std::pin::pin!(future);
    loop {
        let remaining = deadline.remaining()?;
        let tick = std::time::Instant::now() + remaining.min(Duration::from_millis(50));
        if let Ok(value) = timeout_at(Instant::from_std(tick), &mut future).await {
            return Ok(value);
        }
    }
}
fn pool_error(reason: &str) -> SeError {
    se_core::scope::unreadable("host blocking pool", reason)
}
