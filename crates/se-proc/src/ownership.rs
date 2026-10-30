use crate::*;
use std::{path::PathBuf, sync::Arc, time::Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScopeIdentity {
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
/// Durable facts, not native handles, authority or a recipe to kill a bare PID.
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
    pub argv_sha256: [u8; 32],
}
/// Opaque host-arena reference; only se-proc will construct one. Dropping a
/// session's reference does not drop the arena's job/cgroup custody.
pub struct OwnedProcess {
    pub(crate) _private: (),
}
/// Future concrete native runtime. This revision intentionally has no backend
/// implementation or constructor body.
pub struct NativeProcessRuntime {
    pub(crate) _private: (),
}
/// Not serializable or cloneable. Host must commit its stop_requested CAS
/// outside se-proc before consuming this one-use prepared observation.
pub struct PreparedStop {
    pub(crate) _private: (),
}
pub struct StopTicket {
    pub(crate) _private: (),
}
/// Dropping unregisters and joins any in-flight callback before freeing state.
pub struct ExitWatch {
    pub(crate) _private: (),
}

pub struct LaunchSuccess {
    pub process: OwnedProcess,
    pub record: ProcessRecord,
    pub exec_observed: ProcessObservation,
}
/// Any post-creation failure retains custody and its cleanup obligation.
pub struct LaunchFailure {
    pub error: ProcError,
    pub remaining: Option<OwnedProcess>,
    pub rollback: Option<ScopeObservation>,
}
pub enum LaunchOutcome {
    Started(Box<LaunchSuccess>),
    Failed(LaunchFailure),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScopeObservation {
    Populated {
        observed_members: Option<u32>,
    },
    Empty {
        observed_at_unix_ns: u128,
    },
    /// A tracked tree cannot prove an escaped, unregistered descendant absent.
    Tracked {
        live: Vec<ProcessIdentity>,
        completeness: TrackedCompleteness,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackedCompleteness {
    SnapshotOnly,
    EscapedDescendantKnown,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedObservation {
    pub record: ProcessRecord,
    pub root: ProcessObservation,
    pub scope: ScopeObservation,
}
pub struct StopAttempt {
    pub ticket: StopTicket,
    /// Dispatch failure is retained alongside custody; it does not suppress
    /// an independent witness that the tree actually stopped.
    pub dispatch: ProcResult<()>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StopWitness {
    pub lifecycle: LifecycleId,
    pub root: ProcessIdentity,
    pub root_exit: ExitEvidence,
    pub scope: ScopeIdentity,
    pub scope_exit: ScopeObservation,
    pub observed_at_unix_ns: u128,
    pub guarantee: ContainmentGuarantee,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StopObservation {
    Complete(StopWitness),
    /// Only the explicitly requested tracked set exited; never a whole-scope
    /// removal witness when stronger containment was required.
    Bounded(StopWitness),
    Pending {
        root: ProcessObservation,
        scope: ScopeObservation,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitNotice {
    LeaderChanged,
    ScopeChanged,
    MonitorFailed,
}
/// Notifications are nudges; a successful callback is not an exit witness.
/// Implementations must not reenter se-proc or block the native monitor.
pub trait ExitSink: Send + Sync {
    fn notify(&self, lifecycle: LifecycleId, notice: ExitNotice);
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryDisposition {
    ReattachLinuxScope,
    /// Windows last-job-handle loss kills old instances. The host verifies
    /// their exit and resumes saved conversations in new lifecycles.
    VerifyExitedThenResume,
    InspectTrackedMacOs,
    Historical,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPlan {
    pub record: ProcessRecord,
    pub disposition: RecoveryDisposition,
}
pub enum RecoveryOutcome {
    Recovered {
        process: OwnedProcess,
        record: ProcessRecord,
    },
    Exited(StopWitness),
    Unproved {
        record: ProcessRecord,
        error: ProcError,
    },
}

/// The synchronous, host-private native backend. These are compile-only method
/// declarations, not product operations; the allowed public verbs stay in OPS.
/// One arena lives through all service generations in one host process.
pub trait ProcessRuntime: Send + Sync {
    fn open(config: HostConfig) -> ProcResult<Self>
    where
        Self: Sized;
    fn capabilities(&self) -> ProcResult<PlatformCapabilities>;
    /// Read-only diagnostic selector; never creates an OwnedProcess.
    fn read_process(&self, pid: ProcessId) -> ProcResult<ProcessRead>;
    fn launch(&self, spec: LaunchSpec) -> LaunchOutcome;
    fn describe(&self, process: &OwnedProcess) -> ProcResult<ProcessRecord>;
    fn observe(&self, process: &OwnedProcess) -> ProcResult<OwnedObservation>;
    fn watch_exit(&self, process: &OwnedProcess, sink: Arc<dyn ExitSink>) -> ProcResult<ExitWatch>;
    /// CAS within this arena invalidates older-generation session references.
    fn re_adopt(
        &self,
        record: &ProcessRecord,
        from: GenerationId,
        to: GenerationId,
    ) -> ProcResult<OwnedProcess>;
    /// No signal. Checks current identity, custody and service generation.
    fn prepare_stop(
        &self,
        process: &OwnedProcess,
        generation: GenerationId,
        deadline: Instant,
    ) -> ProcResult<PreparedStop>;
    /// Host has durably committed stop_requested; method rechecks again.
    fn request_stop(&self, prepared: PreparedStop) -> ProcResult<StopAttempt>;
    /// No signal. Called after dispatch/graceful stop, from outside the child.
    fn witness_stop(&self, ticket: &StopTicket) -> ProcResult<StopObservation>;
    /// Bounded native wait then the same outside reader; no success on timeout.
    fn wait_stopped(&self, ticket: &StopTicket, deadline: Instant) -> ProcResult<StopObservation>;
    /// Release only an empty, witnessed scope; active scopes stay in the arena.
    fn release(&self, process: &OwnedProcess, witness: &StopWitness) -> ProcResult<()>;
    /// Plan after full host loss; Windows never opens a name as live authority.
    fn plan_recovery(&self, record: &ProcessRecord) -> ProcResult<RecoveryPlan>;
    /// Host checks authorization/store CAS first; no cross-host Windows attach.
    fn recover(&self, plan: RecoveryPlan, generation: GenerationId) -> ProcResult<RecoveryOutcome>;
}
