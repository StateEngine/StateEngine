//! Host-side bridge to `se_atlas_host::atlas_owner`.
use super::{ExecutionContext, HostedRuntime, executor};
use crate::client::{ClientOptions, lease::Deadline};
use se_atlas_host::{
    atlas_runtime::record_fence::RecordFeedFence,
    host::{AtlasHost, BoxedWork, HostFuture},
};
use se_store::ReadPhase;
use se_types::{Generation, Result, SeError};
use std::{
    any::Any,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use tokio::sync::watch;

pub use se_atlas_host::atlas_owner::Service;

struct HostAtlasPort {
    context: ExecutionContext,
}

impl AtlasHost for HostAtlasPort {
    fn generation(&self) -> Generation {
        self.context.generation
    }

    fn records(&self) -> &Arc<RecordFeedFence> {
        &self.context.atlas.records
    }

    fn checked_read_phase(&self) -> Result<ReadPhase> {
        executor::checked_pooled_phase(&self.context.reads, self.context.generation)
    }

    fn run_background_owned(
        &self,
        timeout: Duration,
        work: BoxedWork,
    ) -> HostFuture<'_, Box<dyn Any + Send>> {
        let bound = Deadline::from_options(&ClientOptions {
            expected_generation: None,
            timeout,
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        Box::pin(async move {
            let bound = bound?;
            self.context
                .blocking
                .run_background_owned(&bound, work)
                .await
        })
    }

    fn run_owned(
        &self,
        remaining: Duration,
        work: BoxedWork,
    ) -> HostFuture<'_, Box<dyn Any + Send>> {
        let bound = Deadline::from_options(&ClientOptions {
            expected_generation: None,
            timeout: remaining,
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        Box::pin(async move {
            let bound = bound?;
            self.context.blocking.run_owned(&bound, work).await
        })
    }
}

impl HostedRuntime {
    /// Standalone installation, before listen. The service
    /// begins only in serve, after readiness has been published.
    pub fn install_native_atlas(&mut self) -> Result<()> {
        if self.kind != crate::HostKind::Standalone
            || self.phase != crate::HostPhase::Prepared
            || self.atlas_owner.is_some()
        {
            return Err(SeError::invalid(
                "Atlas owner",
                "one standalone installation before listener publication; embedded hosts do not run Atlas",
            ));
        }
        let enabled = self
            .configuration
            .as_ref()
            .ok_or_else(|| {
                SeError::invalid(
                    "Atlas configuration",
                    "resolved host configuration before Atlas installation",
                )
            })?
            .atlas
            .enabled;
        let service = Service::new(
            &self.state_directory,
            self.owner.clone(),
            enabled,
            self.execution.atlas.records.clone(),
        )?;
        self.install_atlas_read_port(service.clone())?;
        self.atlas_owner = Some(service);
        Ok(())
    }
}

pub(super) async fn run(
    service: Arc<Service>,
    context: ExecutionContext,
    stopped: watch::Receiver<Option<Deadline>>,
) -> Result<()> {
    let port = Arc::new(HostAtlasPort { context });
    service.run(port, stopped).await
}

pub(super) async fn close(
    service: Arc<Service>,
    context: &ExecutionContext,
    bound: &Deadline,
) -> Result<()> {
    let port = HostAtlasPort {
        context: context.clone(),
    };
    service.close(&port, bound.remaining()?).await
}
