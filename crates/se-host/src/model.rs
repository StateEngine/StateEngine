use se_types::{AgentId, Generation, HostEpoch, NativePath, ProjectId, SessionId};
use std::{future::Future, num::NonZeroU32, pin::Pin, sync::Arc, time::Duration};

pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = se_types::Result<T>> + Send + 'a>>;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKind {
    Standalone,
    EmbeddedSecode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostPhase {
    Prepared,
    Activating,
    Ready,
    Recovering,
    Draining,
    Drained,
    Poisoned,
    Closed,
}
#[derive(Clone, Debug)]
pub struct HostConfig {
    pub home: NativePath,
    /// Trusted installed native helper; never resolved from provider input/PATH.
    pub helper_executable: NativePath,
    pub linux_delegation: se_proc::LinuxDelegation,
    pub kind: HostKind,
    pub limits: HostLimits,
    pub listener: ListenerConfig,
}
#[derive(Clone, Debug)]
pub struct HostLimits {
    pub sessions: NonZeroU32,
    pub active_connections: NonZeroU32,
    /// Separate, smaller admission for channels not yet authenticated.
    pub preauth_connections: NonZeroU32,
    pub parked_mail_waits: NonZeroU32,
    pub resident_queue_bytes: NonZeroU32,
    pub session_notice_ids: NonZeroU32,
    pub aggregate_notice_ids: NonZeroU32,
    pub response_bytes: NonZeroU32,
    /// Effective finite-work cap: 2..=8 shares jobs, while one keeps the legacy
    /// one-foreground/one-maintenance split. The supplied runtime's thread cap
    /// must be max(2, blocking_jobs); maintenance always has at most one job.
    pub blocking_jobs: NonZeroU32,
}
#[derive(Clone, Debug)]
pub enum ListenerConfig {
    Disabled,
    Loopback { port: u16 },
}
/// Concrete cancellation state; the linked API's Cancellation trait is canonical.
pub struct CancellationState {
    pub(crate) _private: (),
}
pub struct CallContext {
    pub generation: Generation,
    pub timeout: Duration,
    pub cancellation: Arc<CancellationState>,
}
pub struct OpenContext {
    pub expected_generation: Option<Generation>,
    pub timeout: Duration,
    pub cancellation: Arc<CancellationState>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIdentity {
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
}
pub struct VerifiedCaller {
    pub(crate) _private: (),
}
pub struct BoundSession {
    pub(crate) _private: (),
}
#[derive(Clone, Debug)]
pub struct HostStatus {
    pub epoch: HostEpoch,
    pub generation: Generation,
    pub phase: HostPhase,
    pub sessions: u32,
    pub pending_effects: u64,
    pub pending_notices: u64,
    pub blockers: Vec<se_types::ErrorBody>,
}
#[derive(Clone, Debug)]
pub struct DrainReport {
    pub epoch: HostEpoch,
    pub generation: Generation,
    pub writer_joined: bool,
    pub tasks_joined: bool,
    pub pending_effects: u64,
    pub pending_notices: u64,
}
pub struct RestartRequest {
    pub key: se_types::IdempotencyKey,
    pub reason: RestartReason,
}
#[derive(Clone, Debug)]
pub enum RestartReason {
    Drained(DrainReport),
    Poisoned { incident: String },
}
pub struct FaultReport {
    pub incident: String,
    pub stage: FaultStage,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultStage {
    Activation,
    Drain,
    Close,
    Migration,
    Admission,
    Session,
    Capture,
    Writer,
    Lease,
    Callback,
    Collector,
    Listener,
    NativeProcess,
}
