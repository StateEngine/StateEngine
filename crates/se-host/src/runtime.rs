use crate::{
    CallContext, DrainReport, FaultReport, HostConfig, HostFuture, HostStatus, IpcEndpoint,
    NativeQueue, OpenContext, RestartRequest,
};
use se_types::{Generation, HostEpoch, Page, PageRequest, Read};
use std::sync::Arc;

pub struct PreparedRuntime<H> {
    pub host: H,
    pub epoch: HostEpoch,
    pub generation: Generation,
}
pub enum Integration {
    Standalone,
    Secode {
        epoch: HostEpoch,
        services: Arc<dyn NativeQueue>,
    },
}
#[derive(Clone, Debug)]
pub struct Adoption {
    pub session: crate::SessionIdentity,
    pub revision: se_store::Revision,
    pub outcome: AdoptionOutcome,
}
#[derive(Clone, Debug)]
pub enum AdoptionOutcome {
    Pending,
    Reattached,
    Held,
    Revoked,
    Exited,
    Unreadable(se_types::ErrorBody),
}
/// Generic store types preserve accepted se-store ownership and writer APIs.
/// No raw SQLite connection, second writer queue or fake drain receipt lives here.
pub trait RuntimeFactory: Send + Sync {
    type Store: se_store::HostStore;
    type Host: HostControl;
    fn configured(runtime: tokio::runtime::Handle, config: HostConfig) -> se_types::Result<Self>
    where
        Self: Sized;
    /// Preparation only: version/read compatibility, no writer or callbacks.
    fn prepare<'a>(&'a self, cx: OpenContext) -> HostFuture<'a, Read<PreparedRuntime<Self::Host>>>;
    /// Uses independently retained resource handles, never a poisoned host method.
    fn restart<'a>(
        &'a self,
        request: RestartRequest,
        cx: CallContext,
    ) -> HostFuture<'a, Read<PreparedRuntime<Self::Host>>>;
}
pub trait HostControl: Send + Sync {
    fn status(&self) -> HostStatus;
    fn wait_status<'a>(
        &'a self,
        after: crate::HostPhase,
        cx: CallContext,
    ) -> HostFuture<'a, HostStatus>;
    fn activate<'a>(
        &'a self,
        integration: Integration,
        cx: CallContext,
    ) -> HostFuture<'a, HostStatus>;
    fn poison<'a>(&'a self, fault: FaultReport, cx: CallContext) -> HostFuture<'a, HostStatus>;
    fn native_state_changed<'a>(
        &'a self,
        target: crate::MailTarget,
        cx: CallContext,
    ) -> HostFuture<'a, ()>;
    fn adoptions<'a>(
        &'a self,
        caller: &'a crate::VerifiedCaller,
        page: PageRequest,
        cx: CallContext,
    ) -> HostFuture<'a, Page<Adoption>>;
    fn drain<'a>(&'a self, cx: CallContext) -> HostFuture<'a, DrainReport>;
    fn close<'a>(&'a self, report: DrainReport, cx: CallContext) -> HostFuture<'a, DrainReport>;
}
pub trait RuntimeFilesystem: Send + Sync {
    /// Store RuntimeLease implementation is owned by this adapter, not SQL.
    type Lease: se_store::RuntimeLease;
    fn acquire_host<'a>(&'a self, cx: OpenContext) -> HostFuture<'a, Arc<Self::Lease>>;
    fn acquire_direct<'a>(&'a self, cx: OpenContext) -> HostFuture<'a, Arc<Self::Lease>>;
    fn endpoint<'a>(&'a self, cx: CallContext) -> HostFuture<'a, Read<crate::EndpointRecord>>;
    fn publish<'a>(
        &'a self,
        endpoint: crate::EndpointRecord,
        lease: Arc<Self::Lease>,
        cx: CallContext,
    ) -> HostFuture<'a, IpcEndpoint>;
    fn unpublish<'a>(
        &'a self,
        epoch: HostEpoch,
        lease: Arc<Self::Lease>,
        cx: CallContext,
    ) -> HostFuture<'a, ()>;
}
