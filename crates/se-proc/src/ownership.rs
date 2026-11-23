use crate::*;
pub use se_custody::{
    EnumerationExtent, LifecycleState, Population, ProcessRecord, RemainingScope, RootWitness,
    ScopeExitBasis, ScopeIdentity, ScopeObservation, StopWitness, TrackedObligations,
    UnwitnessedRelease,
};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc, time::Instant};

/// Host commits this before native scope creation, including its exact random
/// suffix, so a cold owner can account for pre-publication reservations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchReservation {
    pub format_version: u16,
    pub lifecycle: LifecycleId,
    pub host: HostInstanceId,
    pub owner: ProcessIdentity,
    pub generation: GenerationId,
    pub scope_nonce: [u8; 16],
    pub parent: ReservationParent,
    #[serde(with = "crate::checkpoint::decimal::u128")]
    pub created_at_unix_ns: u128,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReservationParent {
    Windows,
    Linux {
        #[serde(with = "crate::checkpoint::native_path")]
        path: PathBuf,
        #[serde(with = "crate::checkpoint::decimal::u64")]
        device: u64,
        #[serde(with = "crate::checkpoint::decimal::u64")]
        inode: u64,
        boot_id: [u8; 16],
    },
    /// Lazy manager lookup; exact unit derives from reservation host/nonce.
    LinuxUserManager,
    /// No delegated cgroup; helper/group identity is checkpointed before exec.
    LinuxTracked,
    MacOs,
}
/// Runtime owns all resources. This is a revocable reference, not a second
/// native owner; multiple same-generation references are legal.
pub struct OwnedProcess {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(crate) key: crate::runtime::Reference,
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    pub(crate) _private: (),
}
pub struct NativeProcessRuntime {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(crate) inner: Arc<crate::runtime::Arena>,
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    pub(crate) _private: (),
}
pub struct PreparedStop {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(crate) key: crate::runtime::Reference,
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(crate) deadline: Instant,
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(crate) nonce: u64,
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    pub(crate) _private: (),
}
pub struct StopTicket {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(crate) key: crate::runtime::Reference,
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(crate) attempt: u64,
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    pub(crate) _private: (),
}
pub struct PreparedLaunch {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(crate) key: crate::runtime::Reference,
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    pub(crate) _private: (),
}
pub struct LaunchTicket {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(crate) key: crate::runtime::Reference,
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    pub(crate) _private: (),
}
pub struct ExitWatch {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    pub(crate) _watch: Arc<crate::runtime::notify::Watch>,
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    pub(crate) _private: (),
}

pub struct LaunchSuccess {
    pub process: OwnedProcess,
    pub record: ProcessRecord,
    pub exec_observed: ProcessObservation,
}
pub struct LaunchFailure {
    pub error: ProcError,
    pub remaining: Option<OwnedProcess>,
    pub rollback: Option<StopObservation>,
}
pub enum LaunchStart {
    Pending {
        ticket: LaunchTicket,
        process: OwnedProcess,
    },
    Failed(Box<LaunchFailure>),
}
pub enum LaunchProgress {
    Pending,
    AwaitingExecCommit(Box<RootCheckpoint>),
    Started(Box<LaunchSuccess>),
    Failed(Box<LaunchFailure>),
}
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
pub struct StopAttempt {
    pub ticket: StopTicket,
    pub dispatch: ProcResult<StopDispatch>,
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
pub enum RecoverySource {
    Record(Box<ProcessRecord>),
    Reservation(Box<LaunchReservation>),
    Prepared(Box<ScopeCheckpoint>),
    RootPrepared(Box<RootCheckpoint>),
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
pub enum RecoveryOutcome {
    Recovered {
        process: OwnedProcess,
        record: Box<ProcessRecord>,
    },
    Exited(Box<StopWitness>),
    ReleasedOwnership(Box<ReleasedOwnership>),
    PendingScope {
        process: OwnedProcess,
        checkpoint: Box<ScopeCheckpoint>,
    },
    Unproved {
        source: Box<RecoverySource>,
        error: ProcError,
    },
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

/// All methods return after a bounded native step; no deadline-long wait or
/// provider handshake may occupy the host's shared blocking pool.
pub trait ProcessRuntime: Send + Sync {
    fn open(config: HostConfig) -> ProcResult<Self>
    where
        Self: Sized;
    fn capabilities(&self) -> ProcResult<PlatformCapabilities>;
    fn arena_snapshot(&self) -> ProcResult<ArenaSnapshot>;
    fn prepare_launch(
        &self,
        reservation: LaunchReservation,
        spec: LaunchSpec,
    ) -> ProcResult<PreparedScope>;
    /// Install provider child endpoints once, after native scope preparation.
    /// Rejection leaves the prepared scope owned and prevents vendor execution.
    fn bind_stdio(&self, prepared: &PreparedLaunch, child: StandardIo) -> ProcResult<()>;
    fn begin_launch(&self, prepared: PreparedLaunch) -> LaunchStart;
    fn poll_launch(&self, ticket: &LaunchTicket) -> ProcResult<LaunchProgress>;
    fn authorize_exec(&self, ticket: &LaunchTicket) -> ProcResult<()>;
    /// Host must commit Starting -> StopRequested before this consumes the token.
    fn cancel_launch(
        &self,
        ticket: LaunchTicket,
        prepared: PreparedStop,
    ) -> ProcResult<StopAttempt>;
    fn describe(&self, process: &OwnedProcess) -> ProcResult<ProcessRecord>;
    fn observe(&self, process: &OwnedProcess) -> ProcResult<OwnedObservation>;
    fn watch_exit(&self, process: &OwnedProcess, sink: Arc<dyn ExitSink>) -> ProcResult<ExitWatch>;
    fn re_adopt(
        &self,
        record: &ProcessRecord,
        from: GenerationId,
        to: GenerationId,
    ) -> ProcResult<OwnedProcess>;
    fn prepare_stop(
        &self,
        process: &OwnedProcess,
        generation: GenerationId,
        deadline: Instant,
    ) -> ProcResult<PreparedStop>;
    fn request_stop(&self, prepared: PreparedStop) -> ProcResult<StopAttempt>;
    fn witness_stop(&self, ticket: &StopTicket) -> ProcResult<StopObservation>;
    /// Natural exit, failed launch and graceful shutdown need no stop ticket.
    fn witness_exit(&self, process: &OwnedProcess) -> ProcResult<StopObservation>;
    fn release(&self, process: &OwnedProcess, witness: &StopWitness) -> ProcResult<()>;
    /// LinuxTracked/MacOsTracked only, after an ordinary stop could not be proved.
    /// Host CAS must originate in StopUnproved; other origins are illegal.
    /// No signal, job close or invented exit. The host first commits
    /// release.revision for this lifecycle/generation.
    /// Revoke all arena references and close tracking pins, not provider ports.
    fn release_uncontained(
        &self,
        process: &OwnedProcess,
        release: &UnwitnessedRelease,
    ) -> ProcResult<ReleasedOwnership>;
    fn plan_recovery(&self, source: RecoverySource) -> ProcResult<RecoveryPlan>;
    fn recover(&self, plan: RecoveryPlan, generation: GenerationId) -> ProcResult<RecoveryOutcome>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeCheckpoint {
    pub reservation: LaunchReservation,
    /// Resolved physical parent, or the explicitly selected tracked-group parent.
    pub parent: ReservationParent,
    pub scope: ScopeIdentity,
    pub guarantee: ContainmentGuarantee,
}
pub struct PreparedScope {
    /// Validated native argv digest, reused by pre-exec protected indices.
    pub argv_sha256: [u8; 32],
    pub prepared: PreparedLaunch,
    pub process: OwnedProcess,
    pub checkpoint: ScopeCheckpoint,
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

/// Before-exec root publication for macOS and terminal attach. The only
/// authorized pre-publication exec intent; final native image is independently
/// read (a script may execute an interpreter). Published records pin that image.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCheckpoint {
    pub scope: ScopeCheckpoint,
    pub pre_exec: ProcessIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_boot_session: Option<se_types::BootId>,
    #[serde(with = "crate::checkpoint::native_path")]
    pub intended_executable: PathBuf,
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
