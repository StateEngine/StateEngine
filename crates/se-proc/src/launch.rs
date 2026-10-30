use crate::{GenerationId, HostInstanceId, LifecycleId, MachineId, ProcError};
use std::{ffi::OsString, fs::File, path::PathBuf, time::Instant};

pub struct HostConfig {
    pub machine: MachineId,
    pub instance: HostInstanceId,
    /// Installed native se image for short-lived authenticated attach entry.
    pub helper_executable: PathBuf,
    pub linux_delegation: LinuxDelegation,
    pub limits: ResourceLimits,
    #[cfg(unix)]
    pub reactor: std::sync::Arc<dyn crate::NativeReactor>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinuxDelegation {
    /// Probe current delegation, then ask the user manager on first launch.
    AutoUserManager,
    /// Use current scope only; never search an arbitrary ancestor.
    CurrentScope,
    ExplicitRoot(PathBuf),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    pub max_lifecycles: u32,
    pub max_diagnostic_members: u32,
    pub max_observation_bytes: u64,
    /// Provider-buffer budget already charged to section 80; not extra custody RSS.
    #[cfg(windows)]
    pub max_stdio_buffer_bytes: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchMode {
    Headless,
    Window,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainmentRequirement {
    /// Default: prefer a kernel scope; Linux without delegation reports Uncontained.
    BestAvailable,
    /// Explicit strict request; failure never silently weakens this contract.
    KernelScope,
    /// Explicit lower guarantee, never silently selected by a failed strict launch.
    TrackedTree,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkPolicy {
    Allow,
    Offline,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WritePolicy {
    ReadOnly {
        scratch: PathBuf,
    },
    Workspace {
        roots: Vec<PathBuf>,
        scratch: PathBuf,
    },
    /// Host validates a saved, named opt-in. This does not waive containment.
    NamedUnrestricted {
        profile: String,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchPolicy {
    pub containment: ContainmentRequirement,
    pub writes: WritePolicy,
    pub network: NetworkPolicy,
    /// Off by default; optional restrictions never define alpha custody.
    pub hardening: OptionalHardening,
}
/// Environment is constructed by the host: no ambient inheritance inside se-proc.
/// No Debug/Clone: values may contain provider credentials.
pub struct Environment {
    pub entries: Vec<(OsString, OsString)>,
}
/// Headless None means null. Window None means its new console stream.
/// Only explicit supplied streams are inherited from the caller.
pub struct StandardIo {
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
}
pub struct LaunchSpec {
    pub lifecycle: LifecycleId,
    pub generation: GenerationId,
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub cwd: PathBuf,
    pub environment: Environment,
    pub stdio: StandardIo,
    pub mode: LaunchMode,
    pub window: Option<WindowSpec>,
    pub policy: LaunchPolicy,
    /// Native creation/setup/exec deadline, distinct from provider readiness.
    pub deadline: Instant,
    pub notifications: std::sync::Arc<dyn crate::ExitSink>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryMethod {
    WindowsJobList,
    LinuxClone3,
    LinuxPreExecMigration {
        clone3_errno: i32,
    },
    MacOsSpawn,
    LinuxProcessGroup,
    /// Authenticated helper enters the selected scope before vendor exec.
    TerminalAttach,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainmentGuarantee {
    /// Windows may explicitly permit detached descendants outside this scope.
    KernelScope { explicit_breakaway: bool },
    /// Linux fallback still owns/tracks a process group; it is not containment.
    Uncontained { reason: UncontainedReason },
    TrackedTree {
        atomic_signal: bool,
        escape_prevented: bool,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UncontainedReason {
    NoUserManager,
    NoDelegation,
    CgroupV2Absent,
    CgroupUnreadable,
    ScopeCreateFailed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Capability {
    Supported,
    Unavailable { error: Box<ProcError> },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformCapabilities {
    pub headless: Capability,
    pub window: Capability,
    pub kernel_scope: Capability,
    pub tracked_tree: Capability,
    pub kernel_exit_notification: Capability,
    pub safe_forced_stop: Capability,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OptionalHardening {
    Off,
    Required { profile: String },
}
/// Native detached bootstrap is host-private runtime.up plumbing, not an
/// unowned process.start operation or a way to detach an agent silently.
pub struct RuntimeLaunchSpec {
    /// Persisted machine identity, never a fresh random identity per bootstrap.
    pub machine: MachineId,
    pub startup_nonce: [u8; 16],
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Environment,
    pub deadline: Instant,
}
/// An exact child pin retained until runtime.lock/endpoint readiness is proved.
pub struct RuntimeChild {
    pub(crate) _private: (),
}
pub struct RuntimeLaunch {
    pub detachment: RuntimeDetachment,
    pub child: RuntimeChild,
    pub identity: crate::ProcessIdentity,
}
/// Safe compile-only associated functions; no foreign symbols or unsafe API.
/// Each child pin stays with its host startup slot until commit or witnessed exit.
pub trait NativeProcessApi: Send + Sync {
    fn read_process(
        machine: MachineId,
        pid: crate::ProcessId,
    ) -> crate::ProcResult<crate::ProcessRead>;
    fn spawn_runtime(spec: RuntimeLaunchSpec) -> Result<RuntimeLaunch, Box<RuntimeSpawnFailure>>;
    fn commit_runtime(
        child: RuntimeChild,
        proof: RuntimeReadyProof,
    ) -> Result<RuntimeReady, Box<RuntimeCommitFailure>>;
    fn abort_runtime(child: &mut RuntimeChild) -> crate::ProcResult<()>;
    fn witness_runtime(child: &RuntimeChild) -> crate::ProcResult<RuntimeExitObservation>;
    fn release_runtime(
        child: &mut RuntimeChild,
        witness: &RuntimeExitWitness,
    ) -> crate::ProcResult<()>;
}
/// Data plus an authenticated peer connection, checked against the pinned child.
pub struct RuntimeReadyProof {
    pub startup_nonce: [u8; 16],
    pub owner: crate::ProcessIdentity,
    pub host: HostInstanceId,
    pub endpoint: File,
}
pub struct RuntimeReady {
    pub detachment: RuntimeDetachment,
    pub identity: crate::ProcessIdentity,
    pub host: HostInstanceId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeDetachment {
    WindowsBreakaway,
    UserManagerUnit,
    /// A new session does not escape an inherited external cgroup.
    SessionOnly {
        inherited_cgroup: bool,
    },
}
/// A partial native creation must return its exact cleanup pin, not discard it.
pub struct RuntimeSpawnFailure {
    pub error: ProcError,
    pub remaining: Option<RuntimeChild>,
}
pub struct RuntimeCommitFailure {
    pub error: ProcError,
    pub child: RuntimeChild,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeExitObservation {
    Pending { identity: crate::ProcessIdentity },
    Exited(Box<RuntimeExitWitness>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeExitWitness {
    pub identity: crate::ProcessIdentity,
    pub evidence: crate::ExitEvidence,
    pub status: crate::ExitStatus,
    pub observed_at_unix_ns: u128,
}

/// Unix window launch obtains a controlling PTY; Windows allocates a console.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowSpec {
    WindowsConsole,
    UnixTerminal {
        executable: PathBuf,
        adapter: TerminalAdapter,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminalAdapter {
    Xterm,
    Konsole,
    GnomeTerminal,
    MacOsTerminal,
}
