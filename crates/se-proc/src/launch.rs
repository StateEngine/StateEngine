use crate::{GenerationId, HostInstanceId, LifecycleId, MachineId};
use std::{ffi::OsString, fs::File, path::PathBuf, time::Instant};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostConfig {
    pub machine: MachineId,
    pub instance: HostInstanceId,
    pub linux_delegation: LinuxDelegation,
    pub limits: ResourceLimits,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinuxDelegation {
    /// Inspect the host's current unified hierarchy, never an arbitrary ancestor.
    CurrentScope,
    ExplicitRoot(PathBuf),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    pub max_lifecycles: u32,
    pub max_scope_members: u32,
    pub max_observation_bytes: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchMode {
    Headless,
    Window,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainmentRequirement {
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
}
/// Environment is constructed by the host: no ambient inheritance inside se-proc.
/// No Debug/Clone: values may contain provider credentials.
pub struct Environment {
    pub entries: Vec<(OsString, OsString)>,
}
/// Each supplied file is duplicated into a designated standard stream only.
/// Absent streams are opened on the platform null device, not inherited.
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
    pub policy: LaunchPolicy,
    /// Native creation/setup/exec deadline, distinct from provider readiness.
    pub deadline: Instant,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryMethod {
    WindowsJobList,
    LinuxClone3,
    LinuxPreExecMigration { clone3_errno: i32 },
    MacOsSpawn,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainmentGuarantee {
    /// Windows may explicitly permit detached descendants outside this scope.
    KernelScope { explicit_breakaway: bool },
    TrackedTree {
        atomic_signal: bool,
        escape_prevented: bool,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    Supported,
    Unavailable { code: crate::ProcErrorCode },
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
