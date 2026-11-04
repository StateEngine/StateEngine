use crate::{
    Actor, CursorRecord, Expected, ImportCheckpoint, ImportCounts, RecordId, Revision,
    RuntimeHandoverRecord, RuntimeRecoveredTransfer, Scope, StoreId,
};
use se_types::{
    AgentId, DecisionId, EventId, Generation, HostEpoch, HumanId, IdempotencyKey, LifecycleId,
    MessageId, NativePath, ProcessInstance, ProjectId, SessionId,
};

mod body;
pub use body::{EventBody, EventKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Door {
    Cli,
    Mcp,
    Hook,
    Host,
    Import,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Provider {
    Claude,
    Codex,
    SeCode,
}
/// The surface chosen by the session's actual launch/bind path, never a liveness fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionSurface {
    Headless,
    Window,
    #[serde(rename = "secode")]
    SeCode,
}
impl SessionSurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Headless => "headless",
            Self::Window => "window",
            Self::SeCode => "secode",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PermissionProfile {
    ReadOnly,
    WorkspaceWrite,
    NamedFullBypass,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Profile {
    pub provider: Provider,
    pub model: Option<String>,
    pub permission: PermissionProfile,
    pub named_profile: String,
    pub effort: Option<String>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Root {
    pub path: NativePath,
    pub canonical_key: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PrincipalKind {
    Human,
    Agent,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Consent {
    Capture,
    Suppressed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum DecisionKind {
    Note,
    Decision,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ProcessState {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    Bell,
    Packet,
    IntegrationWrite,
    AgentLaunch,
    AgentStop,
    RuntimeStart,
    RuntimeStop,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOutcome {
    Witnessed,
    Failed,
    Abandoned,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationState {
    Installed,
    Removed,
    Conflict,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum GrantKey {
    AgentCanCreate(AgentId),
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SourceEvidence {
    /// File-backed transcripts have a path; native event capture has none.
    pub path: Option<NativePath>,
    pub incarnation: Vec<u8>,
    pub offset: u64,
    pub length: u64,
    pub sha256: Option<[u8; 32]>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProcessIdentityRecord {
    pub record: LifecycleId,
    pub principal: Actor,
    pub session: Option<SessionId>,
    pub root_identity: RootIdentityState,
    pub instance: RecordedIdentity,
    pub custody: NativeCustody,
    pub containment: ContainmentFact,
}
/// Durable native checkpoint fact, not a claim about current PID liveness.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum RootIdentityState {
    NoChildCreated,
    Unpublished,
    Identified,
    Unknown,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum RecordedIdentity {
    Present(ProcessInstance),
    Absent { reason: String },
    Unreadable { cause: String },
}
/// Versioned se-proc reservation/scope/root/process/exit codec; never an OS handle.
/// Includes ProcessRecord.ownership_release with its generation/entity-counter binding.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NativeCustody {
    pub format_version: u16,
    pub record: Vec<u8>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ContainmentFact {
    NotLaunched,
    Unknown {
        reason: String,
    },
    Contained {
        kind: ContainmentKind,
        observed_at_us: i64,
    },
    Uncontained {
        cause: ContainmentCause,
        observed_at_us: i64,
        probe: Option<EventId>,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ContainmentKind {
    Cgroup,
    Job,
    ProcessGroup,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ContainmentCause {
    NoUserManager,
    NoDelegation,
    CgroupV2Absent,
    CgroupUnreadable,
    ScopeCreateFailed,
}
/// Metadata from the same owned staging pass; never caller-path metadata.
pub trait StagedTextValue {
    fn byte_length(&self) -> u64;
    fn sha256(&self) -> [u8; 32];
}
pub use crate::staging::StagedText;
pub enum InputText {
    Inline(String),
    Staged(StagedText),
}
#[derive(Clone)]
pub enum StoredText {
    Present(String),
    Erased { erasure: RecordId },
}
#[derive(Clone)]
pub struct LegacyBytes {
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}
#[derive(Clone, Debug)]
pub struct EventHeader {
    pub event: EventId,
    pub scope: Scope,
    pub actor: Actor,
    pub session: Option<SessionId>,
    pub origin: StoreId,
    pub door: Door,
    pub occurred_at_us: i64,
    pub cause: Option<EventId>,
    pub supersedes: Option<EventId>,
}
pub struct NewEvent {
    pub header: EventHeader,
    pub body: EventBody<InputText>,
}
#[derive(Clone)]
pub struct StoredEvent {
    pub header: EventHeader,
    pub revision: Revision,
    pub position: crate::StorePosition,
    pub recorded_at_us: i64,
    pub recorded_incarnation: u64,
    pub writer: crate::WriterMode,
    pub durability: crate::CommitDurability,
    pub body: EventBody<StoredText>,
    pub erased_fields: Vec<(crate::EraseField, RecordId)>,
}
/// Closed effect intent: safe references, never shell code, secret environment or arbitrary SQL.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectIntent {
    MailNotice(Box<crate::mail::MailNotice>),
    Mail {
        message: MessageId,
        recipient: Actor,
    },
    Packet {
        session: SessionId,
        cursor: RecordId,
    },
    Integration {
        integration: RecordId,
        plan_sha256: [u8; 32],
    },
    Process {
        process: LifecycleId,
        plan_sha256: [u8; 32],
    },
    Runtime {
        generation: u64,
    },
}
pub struct AtomicBatch {
    pub expected_incarnation: u64,
    pub admission: crate::Admission,
    pub request: Option<crate::RequestIdentity>,
    pub events: Vec<NewEvent>,
    pub import_checkpoint: Option<ImportCheckpoint>,
}
