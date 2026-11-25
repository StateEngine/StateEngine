use crate::*;
pub use se_custody::{
    EnumerationExtent, LaunchReservation, LifecycleState, Population, ProcessRecord,
    RecoverySource, RemainingScope, ReservationParent, RootCheckpoint, RootWitness,
    ScopeCheckpoint, ScopeExitBasis, ScopeIdentity, ScopeObservation, StopWitness,
    TrackedObligations, UnwitnessedRelease,
};
use std::sync::Arc;

/// Native tracking was relinquished; this is deliberately not a StopWitness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleasedOwnership {
    pub release: UnwitnessedRelease,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedObservation {
    pub record: ProcessRecord,
    pub root: ProcessObservation,
    pub scope: ScopeObservation,
}
/// A dispatched signal is not an exit witness. An empty native scope needs no
/// signal, and must not be reported as a forced provider termination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopDispatch {
    Requested,
    NotNeeded,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopObservation {
    Complete(Box<StopWitness>),
    Bounded(Box<StopWitness>),
    Pending {
        root: Option<Box<ProcessObservation>>,
        scope: Box<ScopeObservation>,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitNoticeKind {
    LaunchChanged,
    LeaderChanged,
    ScopeChanged,
    MonitorFailed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExitNotice {
    pub lifecycle: LifecycleId,
    pub generation: GenerationId,
    pub sequence: u64,
    pub kind: ExitNoticeKind,
}
/// Nudge only; native state must be reread. No locks are held around a sink.
pub trait ExitSink: Send + Sync {
    fn notify(&self, notice: ExitNotice);
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryDisposition {
    ReattachLinuxScope,
    ReattachWindowsJob,
    VerifyExitedThenResume,
    InspectTrackedMacOs,
    ReconcileReservation,
    ReleaseExitedScope,
    /// Reconcile the committed human release; never acquire signal authority.
    ReleaseUncontainedOwnership,
    Historical,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPlan {
    pub source: RecoverySource,
    pub disposition: RecoveryDisposition,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArenaEntry {
    pub reservation: LaunchReservation,
    pub record: Option<ProcessRecord>,
    pub checkpoint: Option<ScopeCheckpoint>,
    pub root_checkpoint: Option<RootCheckpoint>,
    pub phase: LifecycleState,
    pub poisoned: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArenaSnapshot {
    pub entries: Vec<ArenaEntry>,
    pub complete: bool,
    pub revision: u64,
}

pub struct TransferEndpoint {
    pub peer: ProcessIdentity,
    pub transport: std::fs::File,
}
pub struct TransferStream {
    pub lifecycle: LifecycleId,
    pub role: StreamRole,
    pub file: std::fs::File,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamRole {
    Input,
    Output,
    Error,
    TerminalMaster,
}
pub struct TransferImport {
    pub(crate) _private: (),
}
// No Debug: the native transfer nonce stays out of ordinary diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct TransferReceipt {
    pub transfer: [u8; 16],
    pub source: HostInstanceId,
    pub successor: HostInstanceId,
    pub generation: GenerationId,
    pub peer: ProcessIdentity,
    pub resources_sha256: [u8; 32],
}

/// Safe host-supplied port to its existing reactor; no tokio dependency enters
/// se-proc. Windows jobs use the native single IOCP collector instead.
pub trait NativeReactor: Send + Sync {
    fn register(
        &self,
        source: std::fs::File,
        interest: NativeInterest,
        sink: Arc<dyn NativeReadiness>,
    ) -> ProcResult<Box<dyn NativeRegistration>>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeInterest {
    Readable,
    Priority,
}
pub trait NativeReadiness: Send + Sync {
    fn ready(&self);
}
pub trait NativeRegistration: Send {
    /// Re-arm after native state has consumed readiness. Level-ready exit and
    /// EOF descriptors must not produce repeated callbacks without this step.
    fn rearm(&self);
    /// Disable future sink calls. In-flight callbacks retain their Arc state
    /// until drained; cancellation must not block an async runtime thread.
    fn cancel(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferResourceKind {
    Job,
    RootPin,
    CgroupDirectory,
    StandardStream(StreamRole),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferResource {
    pub slot: u32,
    pub lifecycle: LifecycleId,
    pub kind: TransferResourceKind,
}
