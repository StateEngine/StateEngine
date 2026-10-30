use crate::{
    Actor, CursorRecord, Expected, ImportCheckpoint, ImportCounts, RecordId, Revision,
    RuntimeHandoverRecord, RuntimeRecoveredTransfer, Scope, StoreId,
};
use se_types::{
    AgentId, DecisionId, EventId, Generation, HostEpoch, HumanId, IdempotencyKey, LifecycleId,
    MessageId, NativePath, ProcessInstance, ProjectId, SessionId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Door {
    Cli,
    Mcp,
    Hook,
    Host,
    Import,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    Claude,
    Codex,
    SeCode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionProfile {
    ReadOnly,
    WorkspaceWrite,
    NamedFullBypass,
}
#[derive(Clone, Debug)]
pub struct Profile {
    pub provider: Provider,
    pub model: Option<String>,
    pub permission: PermissionProfile,
    pub named_profile: String,
    pub effort: Option<String>,
}
#[derive(Clone, Debug)]
pub struct Root {
    pub path: NativePath,
    pub canonical_key: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    Human,
    Agent,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Consent {
    Capture,
    Suppressed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionKind {
    Note,
    Decision,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectKind {
    Bell,
    Packet,
    IntegrationWrite,
    AgentLaunch,
    AgentStop,
    RuntimeStart,
    RuntimeStop,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectOutcome {
    Witnessed,
    Failed,
    Abandoned,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntegrationState {
    Installed,
    Removed,
    Conflict,
}
#[derive(Clone, Debug)]
pub enum ConfigKey {
    DefaultProject,
    DaemonAutostart,
    McpPort,
    ClaudeCommand,
    ClaudeModel,
    ClaudePermission,
    CodexCommand,
    CodexModel,
    CodexPermission,
    AtlasEnabled,
    AgentCanCreate(AgentId),
}
#[derive(Clone, Debug)]
pub enum GrantKey {
    AgentCanCreate(AgentId),
}
#[derive(Clone, Debug)]
pub enum ConfigValue {
    Bool(bool),
    Integer(i64),
    Text(String),
    Project(ProjectId),
    Permission(PermissionProfile),
}
#[derive(Clone, Debug)]
pub struct SourceEvidence {
    pub path: NativePath,
    pub incarnation: Vec<u8>,
    pub offset: u64,
    pub length: u64,
    pub sha256: Option<[u8; 32]>,
}
#[derive(Clone, Debug)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootIdentityState {
    NoChildCreated,
    Unpublished,
    Identified,
    Unknown,
}
#[derive(Clone, Debug)]
pub enum RecordedIdentity {
    Present(ProcessInstance),
    Absent { reason: String },
    Unreadable { cause: String },
}
/// Versioned se-proc reservation/scope/root/process/exit codec; never an OS handle.
#[derive(Clone, Debug)]
pub struct NativeCustody {
    pub format_version: u16,
    pub record: Vec<u8>,
}
#[derive(Clone, Debug)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainmentKind {
    Cgroup,
    Job,
    ProcessGroup,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
/// Created only by the future staging implementation from a bounded owned stream.
/// No public arbitrary-path constructor; not a credential or an event payload by itself.
#[derive(Debug)]
pub struct StagedText {
    _private: (),
}
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
    pub recorded_at_us: i64,
    pub recorded_incarnation: u64,
    pub writer: crate::WriterMode,
    pub durability: crate::CommitDurability,
    pub body: EventBody<StoredText>,
    pub erased_fields: Vec<(crate::EraseField, RecordId)>,
}
/// Closed version-1 persisted kind catalogue. Body text is supplied by T once.
#[derive(Clone)]
pub enum EventBody<T> {
    ProjectRegistered {
        project: ProjectId,
        name: String,
        roots: Vec<Root>,
        owner: HumanId,
        expected: Expected,
    },
    ProjectUpdated {
        project: ProjectId,
        name: String,
        roots: Vec<Root>,
        expected: Expected,
    },
    ProjectRemoved {
        project: ProjectId,
        expected: Expected,
        witnesses: Vec<EventId>,
        preserved: Vec<String>,
    },
    PrincipalRegistered {
        principal: Actor,
        kind: PrincipalKind,
        owner: HumanId,
        created_by: Option<Actor>,
        name: String,
        role: String,
        expected: Expected,
    },
    PrincipalRenamed {
        principal: Actor,
        name: String,
        expected: Expected,
    },
    AliasImported {
        alias: String,
        principal: Actor,
        source: EventId,
        expected: Expected,
    },
    ProfileSaved {
        agent: AgentId,
        profile: Profile,
        expected: Expected,
    },
    GrantRecorded {
        principal: Actor,
        key: GrantKey,
        active: bool,
        expected: Expected,
    },
    ConfigSet {
        key: ConfigKey,
        value: ConfigValue,
        expected: Expected,
    },
    SessionPrepared {
        session: SessionId,
        agent: AgentId,
        provider: Provider,
        native_ref: String,
        consent: Consent,
        generation: u64,
        expected: Expected,
    },
    SessionActivated {
        session: SessionId,
        expected: Expected,
        incumbent: Option<(SessionId, Revision)>,
        process: Option<LifecycleId>,
        containment: ContainmentFact,
        witnesses: Vec<EventId>,
    },
    SessionEnded {
        session: SessionId,
        expected: Expected,
        reason: T,
        final_turn: Option<EventId>,
        final_cursor: Option<EventId>,
    },
    SessionRevoked {
        session: SessionId,
        expected: Expected,
        reason: T,
    },
    CredentialIssued {
        credential: RecordId,
        session: SessionId,
        purpose: String,
        secret_sha256: [u8; 32],
        expires_at_us: i64,
        activation_deadline_us: i64,
        expected: Expected,
    },
    CredentialActivated {
        credential: RecordId,
        session: SessionId,
        expected: Expected,
        first_request: RecordId,
    },
    CredentialRevoked {
        credential: RecordId,
        expected: Expected,
        reason: T,
    },
    MessageSent {
        message: MessageId,
        recipient: Actor,
        kind: String,
        body: T,
        refs: Vec<EventId>,
        reply_to: Option<MessageId>,
    },
    MessageDelivered {
        message: MessageId,
        recipient: Actor,
        evidence: EventId,
    },
    MessageRead {
        message: MessageId,
        recipient: Actor,
    },
    MessageDismissed {
        message: MessageId,
        recipient: Actor,
    },
    MessageSuperseded {
        message: MessageId,
        replacement: MessageId,
        expected: Expected,
    },
    DecisionProposed {
        decision: DecisionId,
        key: String,
        statement: T,
        prior: Option<DecisionId>,
        kind: DecisionKind,
    },
    DecisionRatified {
        decision: DecisionId,
        expected: Expected,
        approval: EventId,
    },
    DecisionRejected {
        decision: DecisionId,
        expected: Expected,
        reason: T,
    },
    DecisionRetracted {
        decision: DecisionId,
        expected: Expected,
        reason: T,
    },
    DecisionSuperseded {
        prior: DecisionId,
        replacement: DecisionId,
        prior_expected: Revision,
        replacement_expected: Revision,
        approval: EventId,
    },
    TurnCaptured {
        turn: RecordId,
        agent: AgentId,
        session: SessionId,
        provider: Provider,
        vendor_ref: String,
        role: Role,
        text: T,
        evidence: SourceEvidence,
    },
    CaptureSource {
        source: RecordId,
        session: SessionId,
        consent: Consent,
        native_ref: String,
        incarnation: Vec<u8>,
        expected: Expected,
    },
    CaptureProgress {
        source: RecordId,
        expected: Expected,
        incarnation: Vec<u8>,
        old_offset: u64,
        new_offset: u64,
        last_turn: RecordId,
    },
    CaptureFailed {
        source: RecordId,
        session: SessionId,
        from_offset: u64,
        to_offset: u64,
        code: se_types::Code,
        cause: String,
        retry: se_types::Retry,
    },
    CaptureSuppressed {
        source: RecordId,
        session: SessionId,
        expected: Expected,
        reason: String,
        from_offset: u64,
        to_offset: u64,
        count: u64,
    },
    ProcessRegistered {
        identity: Box<ProcessIdentityRecord>,
        initial: ProcessState,
    },
    ProcessTransition {
        process: LifecycleId,
        identity: Box<ProcessIdentityRecord>,
        expected: Expected,
        from: ProcessState,
        to: ProcessState,
        observation: EventId,
        outcome: String,
        containment: ContainmentFact,
    },
    WorkingStateSet {
        agent: AgentId,
        text: T,
        expected: Expected,
    },
    CursorRecorded {
        cursor: Box<CursorRecord>,
    },
    CursorAcknowledged {
        cursor: RecordId,
        expected: Revision,
        evidence: EventId,
    },
    EffectRequested {
        principal: Option<Actor>,
        effect: RecordId,
        kind: EffectKind,
        intent: EffectIntent,
        cause: EventId,
        request_key: IdempotencyKey,
    },
    EffectOffered {
        effect: RecordId,
        principal: Actor,
        attempt: RecordId,
        evidence: EventId,
    },
    EffectSettled {
        effect: RecordId,
        expected: Expected,
        outcome: EffectOutcome,
        evidence: Vec<EventId>,
        failure: Option<String>,
        attempts: u32,
    },
    IntegrationRecorded {
        integration: RecordId,
        path: NativePath,
        key: String,
        marker: String,
        prior_sha256: Option<[u8; 32]>,
        written_sha256: Option<[u8; 32]>,
        state: IntegrationState,
        witness: EventId,
        expected: Expected,
    },
    /// Initial or checked cold owner admission, never an implicit handover abort.
    RuntimeOwnerEstablished {
        epoch: HostEpoch,
        generation: Generation,
        expected_owner_generation: Option<Generation>,
        expected: Expected,
        witnesses: Vec<EventId>,
        recovered: Option<Box<RuntimeRecoveredTransfer>>,
    },
    RuntimeHandoverRecorded {
        record: Box<RuntimeHandoverRecord>,
        expected: Expected,
        witnesses: Vec<EventId>,
    },
    BackupRecorded {
        generation: RecordId,
        through: Revision,
        bytes: u64,
        sha256: [u8; 32],
        schema_version: u32,
        witness: EventId,
    },
    ImportStarted {
        import: RecordId,
        source: NativePath,
        source_sha256: [u8; 32],
        format: String,
        policy_version: u32,
    },
    ImportProgress {
        checkpoint: ImportCheckpoint,
        counts: ImportCounts,
    },
    ImportFinished {
        import: RecordId,
        expected: Expected,
        counts: ImportCounts,
        complete: bool,
        omissions: Vec<RecordId>,
    },
    ImportUnreadable {
        import: RecordId,
        family: crate::ImportFamily,
        evidence: SourceEvidence,
        code: String,
    },
    LegacyRetained {
        import: RecordId,
        family: crate::ImportFamily,
        format_version: u32,
        legacy_id: String,
        mapped_id: RecordId,
        source: SourceEvidence,
        bytes: Option<LegacyBytes>,
    },
    TurnErased {
        target: EventId,
        erasure: RecordId,
        original_bytes: u64,
        by: HumanId,
    },
    MessageErased {
        target: EventId,
        erasure: RecordId,
        original_bytes: u64,
        by: HumanId,
    },
    ErasureRequested {
        erasure: RecordId,
        targets: Vec<crate::EraseTarget>,
        residuals: Vec<crate::ResidualCopy>,
    },
    ErasureCompleted {
        erasure: RecordId,
        manifest_sha256: [u8; 32],
        incarnation: u64,
        witnesses: Vec<EventId>,
    },
    RecoveryRecorded {
        recovery: RecordId,
        source: Option<StoreId>,
        source_artifact: SourceEvidence,
        target: StoreId,
        backup: RecordId,
        restored_through: crate::Revision,
        loss: crate::RestoreLoss,
        schema_version: u32,
        witnesses: Vec<EventId>,
    },
}
/// Closed effect intent: safe references, never shell code, secret environment or arbitrary SQL.
#[derive(Clone, Debug)]
pub enum EffectIntent {
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
    pub admission: crate::Admission,
    pub request: Option<crate::RequestIdentity>,
    pub events: Vec<NewEvent>,
    pub import_checkpoint: Option<ImportCheckpoint>,
}
