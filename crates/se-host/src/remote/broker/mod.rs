//! Protected native binding adapter for the source broker.
#[cfg(feature = "remote")]
use super::*;
use crate::client::lease::Deadline;
#[cfg(feature = "remote")]
use se_core::admission::HumanTerminal;
#[cfg(feature = "remote")]
use se_remote::broker::SourceHost;
pub use se_remote::broker::{BrokerBinding, VerifiedSourceSession};
#[cfg(feature = "remote")]
use se_store::Admission;
use se_types::Result;
#[cfg(feature = "remote")]
use se_types::SeError;
#[cfg(feature = "remote")]
use std::sync::Arc;
#[cfg(feature = "remote")]
pub(crate) mod watch;
pub struct RemoteBroker {
    inner: se_remote::broker::RemoteBroker<Deadline>,
    #[cfg(feature = "remote")]
    pub(crate) mailbox: Arc<se_remote_host::return_mail::Mailboxes>,
}
impl std::ops::Deref for RemoteBroker {
    type Target = se_remote::broker::RemoteBroker<Deadline>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl RemoteBroker {
    pub(crate) async fn close(&self) -> Result<()> {
        #[cfg(feature = "remote")]
        let mail = self.mailbox.close().await;
        let remote = self.inner.close().await;
        #[cfg(feature = "remote")]
        mail?;
        remote
    }
    pub(crate) fn fence(&self, revoked: &crate::runtime::mail::Revocations) -> Result<()> {
        self.inner.fence(&revoked.sessions, &revoked.credentials)
    }
    pub(crate) fn fence_committed(
        &self,
        revoked: &crate::runtime::mail::Revocations,
    ) -> Result<()> {
        self.inner
            .fence_committed(&revoked.sessions, &revoked.credentials)
    }
    #[cfg(feature = "remote")]
    pub fn from_protected(
        source_host: RemoteHostId,
        connector: Arc<dyn RemoteConnector>,
        records: Arc<crate::remote::bindings::ProtectedBindings>,
        blocking: crate::BlockingPool,
    ) -> Self {
        Self {
            mailbox: Arc::new(se_remote_host::return_mail::Mailboxes::default()),
            inner: se_remote::broker::RemoteBroker::with_resolver(
                source_host,
                connector,
                Arc::new(ProtectedResolver { records, blocking }),
            ),
        }
    }
    #[cfg(feature = "remote")]
    pub(crate) async fn start_mail(
        self: &Arc<Self>,
        context: &crate::runtime::ExecutionContext,
        source: VerifiedSourceSession,
    ) -> Result<Option<se_types::ErrorBody>> {
        let host: Arc<dyn se_remote_host::ReturnMailHost> = Arc::new(HostReturnMail {
            broker: self.clone(),
            context: context.clone(),
            deadline: None,
        });
        self.mailbox.start_mail(&host, source).await
    }
    #[cfg(feature = "remote")]
    pub(crate) async fn prepare_contact(
        self: &Arc<Self>,
        context: &crate::runtime::ExecutionContext,
        source: &VerifiedSourceSession,
        input: &mut se_core::ops::remote::RemoteSendCall,
        terminal: &HumanTerminal,
        deadline: &Deadline,
    ) -> Result<()> {
        let host: Arc<dyn se_remote_host::ReturnMailHost> = Arc::new(HostReturnMail {
            broker: self.clone(),
            context: context.clone(),
            deadline: Some(deadline.clone()),
        });
        self.mailbox
            .prepare_contact(&host, source, input, terminal)
            .await
    }
    #[cfg(feature = "remote")]
    pub(crate) async fn remember_send(
        self: &Arc<Self>,
        context: &crate::runtime::ExecutionContext,
        source: &VerifiedSourceSession,
        input: &se_core::ops::remote::RemoteSendCall,
        result: &RemoteSendBody,
    ) -> Result<()> {
        let host = HostReturnMail {
            broker: self.clone(),
            context: context.clone(),
            deadline: None,
        };
        self.mailbox
            .remember_send(&host, source, input, result)
            .await
    }
}
#[cfg(feature = "remote")]
struct HostReturnMail {
    broker: Arc<RemoteBroker>,
    context: crate::runtime::ExecutionContext,
    deadline: Option<Deadline>,
}
#[cfg(feature = "remote")]
impl se_remote_host::ReturnMailHost for HostReturnMail {
    fn generation(&self) -> u64 {
        self.context.generation.get()
    }
    fn enable_return_mail(&self) {
        self.context.mail_waits.enable_return_mail();
    }
    fn check_open(&self) -> Result<()> {
        self.broker.check_open()
    }
    fn resolve_binding<'a>(
        &'a self,
        alias: &'a str,
        call: RemoteCallContext,
        admission: &'a Admission,
        terminal: &'a HumanTerminal,
    ) -> RemoteFuture<'a, se_remote::broker::Binding> {
        Box::pin(async move {
            let deadline = match &self.deadline {
                Some(deadline) => deadline.clone(),
                None => crate::remote::remote_deadline()?,
            };
            self.broker
                .resolve(alias, call, admission, terminal, &deadline)
                .await
        })
    }
    fn connection<'a>(
        &'a self,
        binding: &'a se_remote::broker::Binding,
        call: &'a RemoteCallContext,
    ) -> RemoteFuture<'a, Arc<dyn RemoteClient>> {
        Box::pin(async move { self.broker.connection(binding, call).await })
    }
    fn store_info(&self) -> RemoteFuture<'_, se_store::StoreInfo> {
        Box::pin(async move {
            let reader = self.context.reader.clone();
            self.context
                .blocking
                .run_owned(&crate::remote::remote_deadline()?, move || {
                    use se_store::ReadStore;
                    reader
                        .info()
                        .map_err(|e| se_core::store_error::store_error(&e))
                })
                .await
        })
    }
    fn read_owned(
        &self,
        work: Box<
            dyn FnOnce(&se_store::ReadPhase) -> se_store::StoreResult<Box<dyn std::any::Any + Send>>
                + Send,
        >,
    ) -> RemoteFuture<'_, Box<dyn std::any::Any + Send>> {
        Box::pin(async move {
            let reads = self.context.reads.clone();
            let generation = self.context.generation;
            self.context
                .blocking
                .run_owned(&crate::remote::remote_deadline()?, move || {
                    let phase = crate::runtime::executor::checked_pooled_phase(&reads, generation)?;
                    let result = work(&phase).map_err(|e| se_core::store_error::store_error(&e));
                    crate::runtime::executor::close_read(result, phase.close())
                })
                .await
        })
    }
    fn read_background(
        &self,
        work: Box<
            dyn FnOnce(&se_store::ReadPhase) -> se_store::StoreResult<Box<dyn std::any::Any + Send>>
                + Send,
        >,
    ) -> RemoteFuture<'_, Box<dyn std::any::Any + Send>> {
        Box::pin(async move {
            let reads = self.context.reads.clone();
            let generation = self.context.generation;
            self.context
                .blocking
                .run(
                    crate::runtime::BlockingClass::Background,
                    &crate::remote::remote_deadline()?,
                    move || {
                        let phase =
                            crate::runtime::executor::checked_pooled_phase(&reads, generation)?;
                        let result =
                            work(&phase).map_err(|e| se_core::store_error::store_error(&e));
                        crate::runtime::executor::close_read(result, phase.close())
                    },
                )
                .await
        })
    }
    fn submit_batch(
        &self,
        batch: se_store::AtomicBatch,
        operation: &'static str,
        key: se_types::IdempotencyKey,
    ) -> RemoteFuture<'_, se_store::CommitReceipt> {
        Box::pin(async move {
            let identity = crate::runtime::WriteIdentity {
                operation,
                key: Some(key),
                natural_key: None,
                natural_events: Vec::new(),
            };
            crate::runtime::submit::submit(
                &self.context,
                batch,
                &identity,
                &crate::remote::remote_deadline()?,
            )
            .await
        })
    }
}
#[cfg(feature = "remote")]
struct ProtectedResolver {
    records: Arc<crate::remote::bindings::ProtectedBindings>,
    blocking: crate::BlockingPool,
}
#[cfg(feature = "remote")]
impl SourceHost<Deadline> for ProtectedResolver {
    fn resolve(
        &self,
        alias: String,
        call: RemoteCallContext,
        admission: Admission,
        _terminal: HumanTerminal,
        deadline: Deadline,
    ) -> RemoteFuture<'_, BrokerBinding> {
        let records = Arc::clone(&self.records);
        Box::pin(async move {
            self.blocking
                .run_owned(&deadline, move || {
                    let record = se_core::scope::require_present(
                        records.read(&alias)?,
                        "remote binding",
                        "Connect this machine through native Owner control; a missing binding never selects another credential.",
                    )?;
                    if !record.binding.connected {return Err(refused("this machine is disconnected; explicitly add it again to reconnect"));}
                    let signer = if call.source().is_some() {
                        records.lead_signer(&record, &call)?
                    } else {
                        let owner = crate::remote::auth::VerifiedLocalOwner::from_machine(&admission)?;
                        records.human_signer(&owner, &record)?
                    };
                    call.check_current()?;
                    Ok(BrokerBinding {
                        alias,
                        route: RemoteRoute {
                            forward: record.binding.forward,
                            address: record.binding.route,
                            host: record.binding.paired.host,
                        },
                        device: record.binding.paired,
                        signer,
                    })
                })
                .await
        })
    }
}

#[cfg(feature = "remote")]
fn refused(reason: &str) -> SeError {
    SeError::new(se_types::Detail::CapabilityInvalid(se_types::details::CapabilityInvalid {subject:"remote source broker".into(),reason:reason.into(),next_step:"Use the Owner-configured binding and current launched source session; never fall back to a human key or a broader target.".into()}))
}
