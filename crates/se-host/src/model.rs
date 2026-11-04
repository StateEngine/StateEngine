use se_types::{AgentId, Generation, ProjectId, SessionId};
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
/// Concrete cancellation state; the linked API's Cancellation trait is canonical.
pub struct CancellationState {
    pub(crate) _private: (),
}
pub struct CallContext {
    pub generation: Generation,
    pub timeout: Duration,
    pub cancellation: Arc<CancellationState>,
}
impl CallContext {
    /// An ordinary bounded host call with an initially uncancelled context.
    pub fn new(generation: Generation, timeout: Duration) -> Self {
        Self {
            generation,
            timeout,
            cancellation: Arc::new(CancellationState { _private: () }),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIdentity {
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
}
