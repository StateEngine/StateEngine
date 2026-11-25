use crate::*;
use std::{sync::Arc, time::Instant};

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
pub struct StopAttempt {
    pub ticket: StopTicket,
    pub dispatch: ProcResult<StopDispatch>,
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

pub struct PreparedScope {
    /// Validated native argv digest, reused by pre-exec protected indices.
    pub argv_sha256: [u8; 32],
    pub prepared: PreparedLaunch,
    pub process: OwnedProcess,
    pub checkpoint: ScopeCheckpoint,
}
