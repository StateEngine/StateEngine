//! Host-side bridge to `se-channels`, implementing its narrow runtime port
//! and wiring `HostedRuntime` channel lifecycle hooks.
use crate::client::lease::Deadline;
use se_core::store_error::store_error;
use se_store::{Admission, AtomicBatch, CommitReceipt, ReadStore};
use se_types::{Generation, IdempotencyKey, Result, StoreId};
use std::{any::Any, sync::Arc, time::Duration};
use tokio::sync::watch;

pub use se_channels::*;

impl AsChannelDeadline for Deadline {
    fn as_channel_deadline(&self) -> ChannelDeadline {
        self.to_channel_deadline()
    }
}

struct HostChannelPort {
    context: crate::ExecutionContext,
    store: crate::runtime::store::Store,
    store_id: StoreId,
}

impl ChannelHost for HostChannelPort {
    fn generation(&self) -> Generation {
        self.context.generation
    }

    fn store_id(&self) -> StoreId {
        self.store_id.clone()
    }

    fn has_custody(&self) -> bool {
        self.context.custody.get().is_some()
    }

    fn run_blocking(
        &self,
        owned: bool,
        deadline: &ChannelDeadline,
        work: BoxedBlockingWork,
    ) -> HostFuture<'_, Box<dyn Any + Send>> {
        let bound = Deadline::from_channel_deadline(deadline);
        Box::pin(async move {
            let bound = bound?;
            if owned {
                self.context.blocking.run_owned(&bound, work).await
            } else {
                self.context
                    .blocking
                    .run(crate::BlockingClass::Foreground, &bound, work)
                    .await
            }
        })
    }

    fn read_snapshot(
        &self,
        admission: Admission,
        deadline: &ChannelDeadline,
        work: BoxedReadWork,
    ) -> HostFuture<'_, Box<dyn Any + Send>> {
        let bound = Deadline::from_channel_deadline(deadline);
        Box::pin(async move {
            let bound = bound?;
            self.store.read(admission, &bound, work).await
        })
    }

    fn submit_batch(
        &self,
        batch: AtomicBatch,
        operation: &'static str,
        key: IdempotencyKey,
        deadline: &ChannelDeadline,
    ) -> HostFuture<'_, CommitReceipt> {
        let bound = Deadline::from_channel_deadline(deadline);
        Box::pin(async move {
            let bound = bound?;
            let identity = crate::runtime::WriteIdentity {
                operation,
                natural_key: None,
                key: Some(key),
                natural_events: vec![],
            };
            crate::runtime::submit::submit(&self.context, batch, &identity, &bound).await
        })
    }

    fn execute_launch(
        &self,
        plan: Box<se_core::ops::agent_launch::LaunchPlan>,
        admission: Admission,
        deadline: &ChannelDeadline,
    ) -> HostFuture<'_, ()> {
        let bound = Deadline::from_channel_deadline(deadline);
        Box::pin(async move {
            let bound = bound?;
            let coordinator = self
                .context
                .custody
                .get()
                .ok_or_else(|| ChannelError::Unsupported.refusal())?;
            coordinator
                .execute(se_core::ports::CustodyPlan::Launch(plan), admission, &bound)
                .await?;
            Ok(())
        })
    }
}

impl crate::HostedRuntime {
    /// Trusted native Owner ABI, never a tool capability for hosted agents.
    pub fn channels(&self) -> Result<Arc<Channels>> {
        if let Some(service) = self.channels.get() {
            return Ok(service.clone());
        }
        let store_id = self
            .execution
            .reader
            .info()
            .map_err(|e| store_error(&e))?
            .id;
        let credentials = Arc::new(
            NativeChannelCredentials::open(
                &self.state_directory,
                store_id.clone(),
                self.owner.clone(),
            )
            .map_err(ChannelError::refusal)?,
        );
        let port = Arc::new(HostChannelPort {
            context: self.execution.clone(),
            store: crate::runtime::store::Store::for_execution(&self.execution),
            store_id,
        });
        let service = Arc::new(Channels::new(
            port,
            match &self.channel_transport {
                Some(transport) => vec![transport.clone()],
                None => vec![
                    Arc::new(Telegram::new().map_err(ChannelError::refusal)?),
                    Arc::new(Discord::new().map_err(ChannelError::refusal)?),
                ],
            },
            self.configuration.clone(),
            self.owner.clone(),
            credentials,
            self.admission_context().machine_key()?,
            self.fenced.clone(),
        )?);
        if self.channels.set(service.clone()).is_ok() {
            return Ok(service);
        }
        self.channels
            .get()
            .cloned()
            .ok_or_else(|| ChannelError::ReceiverNotRunning.refusal())
    }

    /// Trusted in-process adapter installation, before serving or constructing
    /// Channels. No wire request, model tool or remote client can replace it.
    pub fn install_channel_transport(
        &mut self,
        transport: Arc<dyn ChannelTransport>,
    ) -> Result<()> {
        if self.phase != crate::HostPhase::Prepared
            || self.channels.get().is_some()
            || self.channel_transport.is_some()
        {
            return Err(se_types::SeError::invalid(
                "channel transport",
                "one installation before Channels construction and listener publication",
            ));
        }
        self.channel_transport = Some(transport);
        Ok(())
    }

    /// Trusted in-process test hook shortening the channel receiver's rescan
    /// and poll cycles. Call it before `listen`; production keeps the
    /// ReceiverIntervals defaults and no user configuration surface grows.
    #[doc(hidden)]
    pub fn set_receiver_intervals(&mut self, rescan: Duration, poll: Duration) -> Result<()> {
        if self.phase != crate::HostPhase::Prepared || self.channels.get().is_some() {
            return Err(se_types::SeError::invalid(
                "channel receiver intervals",
                "set before Channels construction and listener publication",
            ));
        }
        self.receiver_intervals = ReceiverIntervals { rescan, poll };
        Ok(())
    }
}

/// Channels prevent the normal auto-start idle exit. They do not create a
/// second OS service or install login persistence behind the Owner's back.
pub(crate) async fn idle(activity: &mut watch::Receiver<u32>, channels: Arc<Channels>) {
    loop {
        crate::runtime::serve::idle_expiry(activity).await;
        let Ok(deadline) = ChannelDeadline::from_timeout(Duration::from_secs(5)) else {
            return;
        };
        let changed = channels.changed().notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        match channels.has_active(&deadline).await {
            Ok(false) => return,
            Ok(true) => changed.await,
            // Unreadable is not idle. Retry a finite point read, preserving the
            // receiver instead of silently stopping a potentially active channel.
            Err(_) => tokio::time::sleep(Duration::from_secs(5)).await,
        }
    }
}
