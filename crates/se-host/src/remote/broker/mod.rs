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
    pub(crate) mailbox: crate::return_mail::Mailboxes,
}
impl std::ops::Deref for RemoteBroker {
    type Target = se_remote::broker::RemoteBroker<Deadline>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl se_remote::broker::Budget for Deadline {
    fn remaining(&self) -> Result<std::time::Duration> {
        Deadline::remaining(self)
    }
    fn write_timeout(&self) -> std::time::Duration {
        crate::client::lease::WRITE_TIMEOUT
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
            mailbox: crate::return_mail::Mailboxes::default(),
            inner: se_remote::broker::RemoteBroker::with_resolver(
                source_host,
                connector,
                Arc::new(ProtectedResolver { records, blocking }),
            ),
        }
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
