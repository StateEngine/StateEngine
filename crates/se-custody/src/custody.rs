//! Durable process and scope evidence shared with the native runtime.
use crate::*;
use serde::{Deserialize, Serialize};
use std::{num::NonZeroU64, path::PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum UncontainedReason {
    NoUserManager,
    NoDelegation,
    CgroupV2Absent,
    CgroupUnreadable,
    ScopeCreateFailed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ScopeIdentity {
    LinuxPrepared {
        nonce: [u8; 16],
    },
    LinuxTracked {
        process_group: ProcessId,
        root: ProcessIdentity,
    },
    MacOsPrepared {
        nonce: [u8; 16],
    },
    WindowsJob {
        host: HostInstanceId,
        name: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        persistent: bool,
    },
    LinuxCgroup {
        #[serde(with = "crate::checkpoint::native_path")]
        path: PathBuf,
        #[serde(with = "crate::checkpoint::decimal::u64")]
        device: u64,
        #[serde(with = "crate::checkpoint::decimal::u64")]
        inode: u64,
        boot_id: [u8; 16],
    },
    MacOsTracked {
        process_group: ProcessId,
        root: ProcessIdentity,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
/// Retained original instances, including known escapes, that a cold owner
/// must account for before claiming the tracked scope exited.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackedObligations {
    pub members: Vec<ProcessIdentity>,
    pub escaped: bool,
}
/// Store owns durable revision/state. This is the arena's last observed native
/// state, never a claim that its transition was committed to the store.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessRecord {
    pub format_version: u16,
    pub lifecycle: LifecycleId,
    pub host: HostInstanceId,
    pub owner: ProcessIdentity,
    pub generation: GenerationId,
    pub root: ProcessIdentity,
    /// A Darwin boot-session UUID survives wall-clock corrections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos_boot_session: Option<se_types::BootId>,
    pub scope: ScopeIdentity,
    /// Older records have no tracking history; absence grants no cold exit proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracked_obligations: Option<TrackedObligations>,
    pub guarantee: ContainmentGuarantee,
    pub entry: EntryMethod,
    pub state: LifecycleState,
    /// Human-released custody stays StopUnproved, never a fabricated Exited.
    /// The host excludes this durable marker from live admission and recovery.
    pub ownership_release: Option<UnwitnessedRelease>,
    pub exit_status: Option<ExitStatus>,
    #[serde(with = "crate::checkpoint::decimal::u128")]
    pub observed_at_unix_ns: u128,
    pub argv_sha256: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Population {
    Empty,
    Populated,
    Unknown,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemainingScope {
    pub population: Population,
    pub known_live: Vec<ProcessIdentity>,
    pub extent: EnumerationExtent,
    #[serde(with = "crate::checkpoint::decimal::u128")]
    pub observed_at_unix_ns: u128,
}
/// Host supplies this only after an ordinary stop yielded durable StopUnproved
/// and owner-human admission committed the release CAS from that state alone.
/// Revision is the resulting nonzero per-lifecycle revision, not an event seq.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnwitnessedRelease {
    pub lifecycle: LifecycleId,
    pub generation: GenerationId,
    pub revision: NonZeroU64,
    pub scope: ScopeIdentity,
    pub remaining: RemainingScope,
    #[serde(with = "crate::checkpoint::decimal::u128")]
    pub released_at_unix_ns: u128,
}
/// Native basis for an empty scope; absence alone cannot construct a witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ScopeExitBasis {
    ObservedEmpty,
    /// Linux only: the still-pinned original cgroup object was removed.
    RemovedPinnedLinuxCgroup,
    /// The same machine is running a different native boot.
    Reboot,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeObservation {
    pub scope: ScopeIdentity,
    pub remaining: RemainingScope,
    /// Some only with a proved empty scope; retained in the durable exit witness.
    pub exit_basis: Option<ScopeExitBasis>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        evidence: Box<ExitEvidence>,
        status: ExitStatus,
    },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopWitness {
    pub lifecycle: LifecycleId,
    pub root: RootWitness,
    pub scope: ScopeIdentity,
    pub scope_exit: ScopeObservation,
    #[serde(with = "crate::checkpoint::decimal::u128")]
    pub observed_at_unix_ns: u128,
    pub guarantee: ContainmentGuarantee,
}
impl StopWitness {
    pub fn ended_by_reboot(&self) -> bool {
        self.scope_exit.exit_basis == Some(ScopeExitBasis::Reboot)
    }
}
