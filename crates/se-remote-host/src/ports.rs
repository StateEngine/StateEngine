//! Narrow host-supplied runtime ports for `se-remote-host`.
use se_remote::RemoteFuture;
use se_types::{Result, SeError};
use std::{any::Any, time::Duration};

/// Default blocking-pool bound for remote session and authorization checks.
pub const SESSION_BLOCKING_TIMEOUT: Duration = Duration::from_secs(30);

/// Bounded foreground blocking execution port implemented by the host blocking pool.
pub trait BlockingRunner: Send + Sync {
    fn run_foreground(
        &self,
        timeout: Duration,
        work: Box<dyn FnOnce() -> Result<Box<dyn Any + Send>> + Send>,
    ) -> RemoteFuture<'_, Box<dyn Any + Send>>;
    fn run_owned(
        &self,
        timeout: Duration,
        work: Box<dyn FnOnce() -> Result<Box<dyn Any + Send>> + Send>,
    ) -> RemoteFuture<'_, Box<dyn Any + Send>>;
}

/// Run a typed finite foreground blocking job through the host runner port.
pub async fn run_foreground<T: Send + 'static>(
    runner: &dyn BlockingRunner,
    timeout: Duration,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let boxed = runner
        .run_foreground(
            timeout,
            Box::new(move || work().map(|value| Box::new(value) as Box<dyn Any + Send>)),
        )
        .await?;
    boxed.downcast::<T>().map(|value| *value).map_err(|_| {
        SeError::invalid(
            "remote blocking job",
            "the expected typed foreground blocking result",
        )
    })
}

/// Run a typed owned blocking job through the host runner port.
pub async fn run_owned<T: Send + 'static>(
    runner: &dyn BlockingRunner,
    timeout: Duration,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    let boxed = runner
        .run_owned(
            timeout,
            Box::new(move || work().map(|value| Box::new(value) as Box<dyn Any + Send>)),
        )
        .await?;
    boxed.downcast::<T>().map(|value| *value).map_err(|_| {
        SeError::invalid(
            "remote owned blocking job",
            "the expected typed owned blocking result",
        )
    })
}

/// Host observer for accepted writer completion faults.
pub trait WriterFaultObserver: Send + Sync {
    fn observe_writer(&self, error: &se_store::StoreError);
}
