use se_types::{AgentId, Generation, HostEpoch, IdempotencyKey, NativePath, ProjectId, SessionId};
use std::{future::Future, num::NonZeroU32, pin::Pin, sync::Arc, time::Duration};

pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = se_types::Result<T>> + Send + 'a>>;
/// Instantiate Factory with the section-10 upstream dyn HostFactory. This does
/// not copy that permissive API into the proprietary crate or implement it.
pub type EmbeddedFactoryBuilder<Factory> = fn(tokio::runtime::Handle) -> Arc<Factory>;

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
    pub kind: HostKind,
    pub limits: HostLimits,
    pub listener: ListenerConfig,
}
#[derive(Clone, Debug)]
pub struct HostLimits {
    pub sessions: NonZeroU32,
    pub connections: NonZeroU32,
    pub resident_queue_bytes: NonZeroU32,
    pub session_notice_ids: NonZeroU32,
    pub aggregate_notice_ids: NonZeroU32,
    pub response_bytes: NonZeroU32,
    pub blocking_jobs: NonZeroU32,
}
#[derive(Clone, Debug)]
pub enum ListenerConfig {
    Disabled,
    Loopback { port: u16 },
}
pub trait Cancellation: Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
pub struct CallContext {
    pub generation: Generation,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}
pub struct OpenContext {
    pub expected_generation: Option<Generation>,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIdentity {
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
}
/// Issued only by the core admission adapter; never decoded from actor fields.
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
    pub generation: Generation,
    pub key: IdempotencyKey,
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
    Admission,
    Session,
    Capture,
    Writer,
    Callback,
    Listener,
    NativeProcess,
}
