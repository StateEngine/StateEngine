use se_types::{Generation, HostEpoch, IdempotencyKey, Read};
use std::time::Duration;

/// Concrete implementations of section 10's HostFactory and Host. Their public
/// method signatures live only in the canonical linked API proposal, not here.
pub struct HostFactoryAdapter {
    pub(crate) _private: (),
}
pub struct HostAdapter {
    pub(crate) _private: (),
}
/// Concrete translation of section 10 HostServices, never a second input queue.
pub struct SecodeAdapter {
    pub(crate) _private: (),
}
pub struct HandoverCoordinator {
    pub(crate) _private: (),
}
pub struct LaunchCoordinator {
    pub(crate) _private: (),
}
pub struct ExitBridge {
    pub(crate) _private: (),
}
pub struct ReactorAdapter {
    pub(crate) _private: (),
}
#[cfg(feature = "runtime")]
pub type ConfigureFactory =
    fn(tokio::runtime::Handle, crate::HostConfig) -> se_types::Result<HostFactoryAdapter>;
pub struct PreparedRuntime {
    pub host: HostAdapter,
    pub epoch: HostEpoch,
    pub generation: Generation,
}
pub enum Integration {
    Standalone,
    Secode {
        epoch: HostEpoch,
        adapter: SecodeAdapter,
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
/// Host-local observations, not the durable store phase enum. Activated is
/// transient; no consumers run until the store commits FULL Finished.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoverPhase {
    SourceGated,
    Standby,
    Staged,
    BarrierCommitted,
    LeaseTransferred,
    Activated,
    Acknowledged,
    Finished,
    Aborted,
    Recovered,
    RecoveryPending,
}
#[derive(Clone, Debug)]
pub struct HandoverIntent {
    pub transfer: se_store::RecordId,
    pub source: HostEpoch,
    pub successor: HostEpoch,
    pub from: Generation,
    pub to: Generation,
    pub key: IdempotencyKey,
    pub expected: se_store::Revision,
    pub timeout: Duration,
    pub deadline_at: se_types::UnixMicros,
}
/// Native transfer nonce is private peer-binding material, never Debug output.
#[derive(Clone)]
pub struct HandoverState {
    pub intent: HandoverIntent,
    pub phase: HandoverPhase,
    pub native: Read<se_proc::TransferReceipt>,
    pub native_nonce: Option<[u8; 16]>,
    pub manifest_sha256: Option<se_types::Sha256>,
    pub frozen_at: Option<se_store::StorePosition>,
    pub recovery_owner: Option<se_types::EventId>,
    pub unresolved: Vec<se_types::ErrorBody>,
}

mod inventory;
pub use inventory::decode_owner_inventory;
