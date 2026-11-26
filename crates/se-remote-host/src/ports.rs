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

/// Boxed read-phase closure executed by a host implementing [`ReturnMailHost`].
pub type ReturnMailReadJob =
    Box<dyn FnOnce(&se_store::ReadPhase) -> se_store::StoreResult<Box<dyn Any + Send>> + Send>;

/// Narrow host runtime port for source-side return-mail couriers.
pub trait ReturnMailHost: Send + Sync {
    fn generation(&self) -> u64;
    fn enable_return_mail(&self);
    fn check_open(&self) -> Result<()>;
    fn resolve_binding<'a>(
        &'a self,
        alias: &'a str,
        call: se_remote::RemoteCallContext,
        admission: &'a se_store::Admission,
        terminal: &'a se_core::admission::HumanTerminal,
    ) -> RemoteFuture<'a, se_remote::broker::Binding>;
    fn connection<'a>(
        &'a self,
        binding: &'a se_remote::broker::Binding,
        call: &'a se_remote::RemoteCallContext,
    ) -> RemoteFuture<'a, std::sync::Arc<dyn se_remote::RemoteClient>>;
    fn store_info(&self) -> RemoteFuture<'_, se_store::StoreInfo>;
    fn read_owned(&self, work: ReturnMailReadJob) -> RemoteFuture<'_, Box<dyn Any + Send>>;
    fn read_background(&self, work: ReturnMailReadJob) -> RemoteFuture<'_, Box<dyn Any + Send>>;
    fn submit_batch(
        &self,
        batch: se_store::AtomicBatch,
        operation: &'static str,
        key: se_types::IdempotencyKey,
    ) -> RemoteFuture<'_, se_store::CommitReceipt>;
}

/// Run a typed owned read against the host's pooled read phase.
pub async fn return_mail_read<T: Send + 'static>(
    host: &dyn ReturnMailHost,
    work: impl FnOnce(&se_store::ReadPhase) -> se_store::StoreResult<T> + Send + 'static,
) -> Result<T> {
    let boxed = host
        .read_owned(Box::new(move |phase| {
            work(phase).map(|value| Box::new(value) as Box<dyn Any + Send>)
        }))
        .await?;
    boxed
        .downcast::<T>()
        .map(|value| *value)
        .map_err(|_| SeError::invalid("return-mail read", "the expected typed read result"))
}

/// Run a typed background read against the host's pooled read phase.
pub async fn return_mail_background_read<T: Send + 'static>(
    host: &dyn ReturnMailHost,
    work: impl FnOnce(&se_store::ReadPhase) -> se_store::StoreResult<T> + Send + 'static,
) -> Result<T> {
    let boxed = host
        .read_background(Box::new(move |phase| {
            work(phase).map(|value| Box::new(value) as Box<dyn Any + Send>)
        }))
        .await?;
    boxed
        .downcast::<T>()
        .map(|value| *value)
        .map_err(|_| SeError::invalid("return-mail read", "the expected typed background result"))
}
