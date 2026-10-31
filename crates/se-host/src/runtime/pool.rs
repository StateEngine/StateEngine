//! Finite synchronous work on the supplied executor. A reserved foreground slot
//! cannot be occupied by background work; neither slot creates another runtime.
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
    foreground: Arc<Semaphore>,
    background: Arc<Semaphore>,
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
        Self {
            runtime,
            foreground: Arc::new(Semaphore::new(1)),
            background: Arc::new(Semaphore::new(1)),
        }
    }
    /// Listener native checks share the foreground admission with planning and
    /// continuation jobs. A timed-out job retains its slot until it really exits.
    pub fn foreground_admission(&self) -> Arc<Semaphore> {
        Arc::clone(&self.foreground)
    }
    pub async fn run<T, F>(&self, class: BlockingClass, deadline: &Deadline, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T> + Send + 'static,
    {
        deadline.remaining()?;
        let slots = match class {
            BlockingClass::Foreground => &self.foreground,
            BlockingClass::Background => &self.background,
        };
        let permit = within(deadline, Arc::clone(slots).acquire_owned())
            .await?
            .map_err(|_| pool_error("bounded blocking admission closed"))?;
        deadline.remaining()?;
        let job = self.runtime.spawn_blocking(move || {
            let _permit = permit;
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
        let permit = within(deadline, Arc::clone(&self.foreground).acquire_owned())
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
    /// Called after fencing new admission and joining connection tasks. Holding
    /// both permits proves every accepted native/plan/continuation job exited,
    /// including jobs whose caller's deadline expired first.
    pub async fn quiesce(&self, deadline: &Deadline) -> Result<()> {
        let foreground = within(deadline, Arc::clone(&self.foreground).acquire_owned())
            .await?
            .map_err(|_| pool_error("foreground admission closed"))?;
        let background = within(deadline, Arc::clone(&self.background).acquire_owned())
            .await?
            .map_err(|_| pool_error("background admission closed"))?;
        drop((foreground, background));
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
