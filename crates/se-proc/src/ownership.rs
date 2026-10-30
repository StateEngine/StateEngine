use crate::*;
use std::{path::PathBuf, sync::Arc, time::Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScopeIdentity {
    MacOsPrepared {
        nonce: [u8; 16],
    },
    WindowsJob {
        host: HostInstanceId,
        name: String,
    },
    LinuxCgroup {
        path: PathBuf,
        device: u64,
        inode: u64,
        boot_id: [u8; 16],
    },
    MacOsTracked {
        process_group: ProcessId,
        root: ProcessIdentity,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    Reserved,
    Starting,
    Running,
    LeaderExited,
    StopRequested,
    StopUnproved,
    Exited,
    Lost,
    Historical,
}
/// Store owns durable revision/state. This is the arena's last observed native
/// state, never a claim that its transition was committed to the store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRecord {
    pub format_version: u16,
    pub lifecycle: LifecycleId,
    pub host: HostInstanceId,
    pub owner: ProcessIdentity,
    pub generation: GenerationId,
    pub root: ProcessIdentity,
    pub scope: ScopeIdentity,
    pub guarantee: ContainmentGuarantee,
    pub entry: EntryMethod,
    pub state: LifecycleState,
    pub exit_status: Option<ExitStatus>,
    pub observed_at_unix_ns: u128,
    pub argv_sha256: [u8; 32],
}
/// Host commits this before native scope creation, including its exact random
/// suffix, so a cold owner can account for pre-publication reservations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchReservation {
    pub format_version: u16,
    pub lifecycle: LifecycleId,
    pub host: HostInstanceId,
    pub owner: ProcessIdentity,
    pub generation: GenerationId,
    pub scope_nonce: [u8; 16],
    pub parent: ReservationParent,
    pub created_at_unix_ns: u128,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReservationParent {
    Windows,
    Linux {
        path: PathBuf,
        device: u64,
        inode: u64,
        boot_id: [u8; 16],
    },
    MacOs,
}
/// Runtime owns all resources. This is a revocable reference, not a second
/// native owner; multiple same-generation references are legal.
pub struct OwnedProcess {
    pub(crate) _private: (),
}
pub struct NativeProcessRuntime {
    pub(crate) _private: (),
}
pub struct PreparedStop {
    pub(crate) _private: (),
}
pub struct StopTicket {
    pub(crate) _private: (),
}
pub struct PreparedLaunch {
    pub(crate) _private: (),
}
pub struct LaunchTicket {
    pub(crate) _private: (),
}
pub struct ExitWatch {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Population {
    Empty,
    Populated,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnumerationExtent {
    Complete,
    Partial {
        reason: String,
        omitted: Option<u32>,
    },
    NotRequested,
}
/// Labelled, best-effort diagnostic enumeration; never the authority to signal
/// a kernel scope. Empty known_live with Partial is not an empty scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemainingScope {
    pub population: Population,
    pub known_live: Vec<ProcessIdentity>,
    pub extent: EnumerationExtent,
    pub observed_at_unix_ns: u128,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeObservation {
    pub scope: ScopeIdentity,
    pub remaining: RemainingScope,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedObservation {
    pub record: ProcessRecord,
    pub root: ProcessObservation,
    pub scope: ScopeObservation,
}
pub struct StopAttempt {
    pub ticket: StopTicket,
    pub dispatch: ProcResult<()>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RootWitness {
    NoChildCreated,
    /// Empty exact scope after a crash between exec and root publication.
    UnpublishedScope,
    PinnedUnpublished {
        pid: ProcessId,
        status: ExitStatus,
    },
    Identified {
        expected: ProcessIdentity,
        evidence: ExitEvidence,
        status: ExitStatus,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopWitness {
    pub lifecycle: LifecycleId,
    pub root: RootWitness,
    pub scope: ScopeIdentity,
    pub scope_exit: ScopeObservation,
    pub observed_at_unix_ns: u128,
    pub guarantee: ContainmentGuarantee,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopObservation {
    Complete(Box<StopWitness>),
    Bounded(Box<StopWitness>),
    Pending {
        root: Option<Box<ProcessObservation>>,
        scope: ScopeObservation,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitNoticeKind {
    LaunchChanged,
    LeaderChanged,
    ScopeChanged,
    MonitorFailed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    VerifyExitedThenResume,
    InspectTrackedMacOs,
    ReconcileReservation,
    ReleaseExitedScope,
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
    fn prepare_launch(&self, reservation: LaunchReservation) -> ProcResult<PreparedScope>;
    fn begin_launch(&self, prepared: PreparedLaunch, spec: LaunchSpec) -> LaunchStart;
    fn poll_launch(&self, ticket: &LaunchTicket) -> ProcResult<LaunchProgress>;
    fn authorize_exec(&self, ticket: &LaunchTicket) -> ProcResult<()>;
    fn cancel_launch(&self, ticket: LaunchTicket) -> ProcResult<StopAttempt>;
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
    fn plan_recovery(&self, source: RecoverySource) -> ProcResult<RecoveryPlan>;
    fn recover(&self, plan: RecoveryPlan, generation: GenerationId) -> ProcResult<RecoveryOutcome>;
    fn begin_transfer(&self, request: TransferRequest) -> ProcResult<TransferOffer>;
    fn accept_transfer(
        &self,
        endpoint: TransferEndpoint,
        manifest: TransferManifest,
    ) -> ProcResult<ReceivedTransfer>;
    fn activate_transfer(&self, imported: TransferImport) -> ProcResult<TransferReceipt>;
    fn commit_transfer(&self, offer: TransferOffer, receipt: TransferReceipt) -> ProcResult<()>;
    fn abort_transfer(&self, offer: TransferOffer) -> ProcResult<()>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeCheckpoint {
    pub reservation: LaunchReservation,
    pub scope: ScopeIdentity,
    pub guarantee: ContainmentGuarantee,
}
pub struct PreparedScope {
    pub prepared: PreparedLaunch,
    pub process: OwnedProcess,
    pub checkpoint: ScopeCheckpoint,
}
pub struct TransferEndpoint {
    pub peer: ProcessIdentity,
    pub transport: std::fs::File,
}
pub struct TransferRequest {
    pub endpoint: TransferEndpoint,
    pub successor: HostInstanceId,
    pub generation: GenerationId,
    pub streams: Vec<TransferStream>,
    pub deadline: Instant,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferManifest {
    pub transfer: [u8; 16],
    pub source: HostInstanceId,
    pub successor: HostInstanceId,
    pub generation: GenerationId,
    pub records: Vec<ProcessRecord>,
    pub resources: Vec<TransferResource>,
}
pub struct TransferOffer {
    pub(crate) _private: (),
}
pub struct TransferImport {
    pub(crate) _private: (),
}
pub struct ReceivedTransfer {
    pub imported: TransferImport,
    pub records: Vec<ProcessRecord>,
    pub processes: Vec<OwnedProcess>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootCheckpoint {
    pub scope: ScopeCheckpoint,
    pub pre_exec: ProcessIdentity,
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
