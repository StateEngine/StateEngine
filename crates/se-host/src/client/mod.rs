//! Synchronous CLI/hook bootstrap and IPC client contract. This module and its
//! transitive declarations build with --no-default-features and no Tokio.
use crate::{EndpointRecord, IpcEndpoint, IpcEnvelope, OperationOutput};
use se_types::{Generation, HostEpoch, Read};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

pub struct ClientOptions {
    pub expected_generation: Option<Generation>,
    pub timeout: Duration,
    pub cancelled: Arc<AtomicBool>,
}
pub struct BlockingIpcClient {
    pub(crate) _private: (),
}
pub use lease::BlockingConnection;
/// Genuine OS backends: Unix sockets and Windows named pipes. Framing, MAC,
/// authority selection and result decoding remain one common blocking client.
pub trait BlockingTransport: Send + Sync {
    fn connect(
        &self,
        endpoint: &EndpointRecord,
        options: &ClientOptions,
    ) -> se_types::Result<BlockingConnection>;
    fn exchange(
        &self,
        connection: &mut BlockingConnection,
        call: IpcEnvelope,
        options: &ClientOptions,
    ) -> se_types::Result<OperationOutput>;
}
/// Genuine native filesystem backends. Async host wrappers admit bounded calls
/// to the supplied blocking pool; initial discovery never invents a generation.
pub trait RuntimeFilesystem: Send + Sync {
    type Lease: se_store::RuntimeLease;
    fn endpoint(&self, deadline: Instant) -> se_types::Result<Read<EndpointRecord>>;
    fn acquire_direct(&self, deadline: Instant) -> se_types::Result<Arc<Self::Lease>>;
    fn acquire_host(&self, deadline: Instant) -> se_types::Result<Arc<Self::Lease>>;
    fn publish(
        &self,
        endpoint: EndpointRecord,
        lease: Arc<Self::Lease>,
        deadline: Instant,
    ) -> se_types::Result<IpcEndpoint>;
    fn unpublish(
        &self,
        epoch: HostEpoch,
        lease: Arc<Self::Lease>,
        deadline: Instant,
    ) -> se_types::Result<()>;
}

pub mod auth;
pub mod endpoint;
pub mod lease;
pub mod wire;
