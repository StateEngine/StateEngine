//! Wire values contain measured facts; family envelopes are supplied by the operation sum type.
use crate::{
    commit::MessageKind,
    config_policy::{Provider, ResolvedProfile},
};
use schemars::JsonSchema;
use se_types::{
    AgentId, EventId, HumanId, IdempotencyKey, MessageId, Page, ProjectId, Read, SessionId,
};
use serde::{Deserialize, Serialize};

/// Host measurements for the exact completed request, outside its immutable
/// semantic receipt. There is no diagnostics object on a direct write.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutputDiagnostics {
    pub write_timings: ReceiptWriteTimings,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiptWriteTimings {
    pub queue_ms: f64,
    pub transaction_ms: f64,
    pub commit_call_ms: f64,
    pub checkpoint_ms: f64,
    pub durability: WriteDurability,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WriteDurability {
    Full,
    Normal,
}
impl ReceiptWriteTimings {
    pub fn validate(&self) -> se_types::Result<()> {
        if [
            self.queue_ms,
            self.transaction_ms,
            self.commit_call_ms,
            self.checkpoint_ms,
        ]
        .iter()
        .any(|value| !value.is_finite() || *value < 0.0)
        {
            return Err(se_types::SeError::invalid(
                "write timings",
                "four finite non-negative measured millisecond values",
            ));
        }
        Ok(())
    }
    pub fn from_store(timings: &se_store::WriteTimings) -> Self {
        Self {
            queue_ms: timings.queue.as_secs_f64() * 1000.0,
            transaction_ms: timings.transaction.as_secs_f64() * 1000.0,
            commit_call_ms: timings.commit_sync.as_secs_f64() * 1000.0,
            checkpoint_ms: timings.checkpoint.as_secs_f64() * 1000.0,
            durability: match timings.durability {
                se_store::CommitDurability::Full => WriteDurability::Full,
                se_store::CommitDurability::Normal => WriteDurability::Normal,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Named<I> {
    pub id: I,
    pub name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct NextStep {
    pub text: String,
    pub command: String,
    pub argv: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Build {
    pub commit: Option<String>,
    pub provenance: Provenance,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Provenance {
    Observed,
    Unknown,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct VersionOutput {
    pub version: String,
    pub build: Build,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct HelpOutput {
    pub path: Vec<String>,
    pub usage: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OpSchema {
    pub name: String,
    pub metadata: serde_json::Value,
    pub input: serde_json::Value,
    pub output: serde_json::Value,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SchemaCatalogue {
    pub api: String,
    pub build: Build,
    pub ops: Vec<OpSchema>,
    pub families: Vec<String>,
    pub errors: Vec<serde_json::Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProjectView {
    pub id: ProjectId,
    pub name: String,
    pub root: String,
    pub registered_at: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OwnerView {
    pub human_id: HumanId,
    pub os_user: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct GitView {
    pub head: Option<String>,
    pub branch: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RepositoryView {
    pub root: String,
    pub git: Option<GitView>,
    pub files_touched: u32,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum InitOutcome {
    Created,
    Adopted,
    AlreadyPresent,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum IdentityOutcome {
    Created,
    Existing,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct InitialAgent {
    pub id: AgentId,
    pub name: String,
    pub outcome: IdentityOutcome,
    pub provider: Provider,
    pub model: Option<String>,
    pub permission_profile: ResolvedProfile,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct InitProfile {
    pub schema: String,
    pub project: ProjectId,
    pub repo_root: String,
    pub registry_root: String,
    pub keys_dir: String,
    pub human_id: HumanId,
    pub agent_id: AgentId,
    pub native_server_port: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct InitOutput {
    pub idempotency_key: IdempotencyKey,
    pub outcome: InitOutcome,
    pub project: ProjectView,
    pub repo: RepositoryView,
    pub owner: OwnerView,
    pub home: String,
    pub agent: InitialAgent,
    pub profile: InitProfile,
    pub integrations: Vec<IntegrationEffect>,
    pub changed: Vec<String>,
    pub next: NextStep,
    pub launch: Option<LaunchOutput>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProcessView {
    pub pid: u32,
    pub started_at: String,
    pub exe: String,
    pub machine_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Witness {
    pub state: WitnessState,
    pub method: String,
    pub observed_at: String,
    pub detail: Option<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WitnessState {
    Witnessed,
    Unknown,
    Failed,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum FileOutcome {
    Written,
    Removed,
    Unchanged,
    AlreadyAbsent,
    ConflictKept,
    Unreadable,
    Pending,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct FileEffect {
    pub path: String,
    pub outcome: FileOutcome,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DirectoryOutcome {
    Removed,
    AlreadyAbsent,
    NotEmptyPreserved,
    Unreadable,
    Unsafe,
    Pending,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DirectoryEffect {
    pub path: String,
    pub outcome: DirectoryOutcome,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct IntegrationEffect {
    pub path: String,
    pub entry: String,
    #[serde(rename = "outcome")]
    pub action: FileOutcome,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SessionView {
    pub state: String,
    pub session_id: Option<SessionId>,
    pub launch_id: Option<se_types::LaunchId>,
    pub surface: String,
    pub process: Option<ProcessView>,
    pub since: Option<String>,
    pub observed_at: Option<String>,
    pub containment: Option<String>,
    pub containment_cause: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConversationView {
    pub id: Option<String>,
    pub state: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResumeCommand {
    pub ready: bool,
    pub mode: String,
    pub reason: Option<String>,
    pub command: Option<String>,
    pub argv: Option<Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentRow {
    pub id: AgentId,
    pub name: String,
    pub role: Option<String>,
    pub provider: Provider,
    pub model: Option<String>,
    pub profile: String,
    pub session: SessionView,
    pub conversation: ConversationView,
    pub resume: ResumeCommand,
    pub unread: Option<u64>,
    pub last_activity_at: Option<String>,
}
/// Public configuration readback. A present JSON value retains its setting type;
/// absence and a failed read must not become a successful null value.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConfigValueOutput {
    pub key: String,
    pub value: Read<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}
impl ConfigValueOutput {
    pub fn into_envelope(self) -> super::Envelope<Self> {
        super::Envelope::new(
            crate::registry::Family {
                name: "se.config-value",
                major: 1,
            },
            self,
        )
    }
}
/// Single-agent readback reuses the status/list row without flattening Read.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AgentStatusOutput {
    pub agent: Read<AgentRow>,
}
impl AgentStatusOutput {
    pub fn into_envelope(self) -> super::Envelope<Self> {
        super::Envelope::new(
            crate::registry::Family {
                name: "se.agent-status",
                major: 1,
            },
            self,
        )
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum SetupState {
    Configured,
    NotSetUp,
    Unreadable,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SetupView {
    pub state: SetupState,
    pub home: String,
    pub reason: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ResourceSample {
    pub self_voluntary_switches: u64,
    pub self_involuntary_switches: Option<u64>,
    pub cpu_user_us: u64,
    pub cpu_system_us: u64,
    pub rss_bytes: u64,
    pub sampled_at: String,
    pub method: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeView {
    pub state: String,
    pub host: Option<String>,
    pub process: Option<ProcessView>,
    pub generation: Option<u64>,
    pub endpoint: Option<String>,
    pub version: Option<String>,
    pub observed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceSample>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RemovalView {
    pub project: Named<ProjectId>,
    pub root: String,
    pub removed_at: String,
    pub event_id: EventId,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PrincipalView {
    pub project: Named<ProjectId>,
    pub agent: Named<AgentId>,
    pub session_id: SessionId,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct InboxCounts {
    pub owner_unread: Option<u64>,
    pub self_unread: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecisionCounts {
    pub pending: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CaptureView {
    pub state: String,
    pub last_turn_at: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AtlasView {
    pub state: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PendingFact {
    pub what: String,
    pub since: Option<String>,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProjectSummary {
    pub id: ProjectId,
    pub name: String,
    pub root: String,
    pub agents_running: u64,
    pub owner_unread: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StatusOutput {
    pub scope: String,
    pub generated_at: String,
    pub version: String,
    pub setup: SetupView,
    pub runtime: RuntimeView,
    pub project: Read<ProjectView>,
    pub removal: Option<RemovalView>,
    pub principal: Option<PrincipalView>,
    pub agents: Option<Page<AgentRow>>,
    pub inbox: InboxCounts,
    pub decisions: DecisionCounts,
    pub capture: CaptureView,
    pub atlas: AtlasView,
    pub pending: Vec<PendingFact>,
    pub projects: Option<Page<ProjectSummary>>,
    pub next: NextStep,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum Writer {
    Direct,
    Host { host_generation: String },
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CommitState {
    Committed,
    Replayed,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ActorRef {
    pub kind: String,
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BodyDigest {
    pub bytes: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct Delivery {
    pub state: String,
    pub at: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessageOutput {
    pub state: CommitState,
    pub message_id: MessageId,
    pub event_id: EventId,
    pub recorded_at: String,
    pub project: Named<ProjectId>,
    pub from: ActorRef,
    pub to: ActorRef,
    pub kind: MessageKind,
    pub reply_to: Option<MessageId>,
    pub refs: Vec<EventId>,
    pub idempotency_key: IdempotencyKey,
    pub body: BodyDigest,
    pub delivery: Delivery,
    pub writer: Writer,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct WorkingStateValue {
    pub text: String,
    pub revision: u64,
    #[serde(rename = "updated_at")]
    pub recorded_at: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct WorkingStateOutput {
    pub agent: Named<AgentId>,
    pub value: Read<WorkingStateValue>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct WorkingStateReceipt {
    pub agent: Named<AgentId>,
    pub state: CommitState,
    pub revision: u64,
    pub current_revision: u64,
    pub event_id: EventId,
    pub idempotency_key: IdempotencyKey,
    pub writer: Writer,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessageBody {
    pub text: String,
    pub complete: bool,
    pub bytes: u64,
    pub command: Option<String>,
    pub argv: Option<Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessageRow {
    pub id: MessageId,
    pub event_id: EventId,
    pub from: ActorRef,
    pub to: ActorRef,
    pub kind: MessageKind,
    pub sent_at: String,
    pub reply_to: Option<MessageId>,
    pub refs: Vec<EventId>,
    pub delivery: Delivery,
    pub disposition: Delivery,
    pub body: MessageBody,
    pub unreadable: Option<UnreadableRow>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct UnreadableRow {
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessageFilter {
    pub to: Option<ActorRef>,
    pub from: Option<ActorRef>,
    pub kind: Option<MessageKind>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessagePageView {
    pub op: String,
    pub recipient: Option<ActorRef>,
    pub disposition: String,
    pub r#box: String,
    pub filter: MessageFilter,
    pub inspection: bool,
    pub full: bool,
    pub scope: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct MessagePage {
    pub view: MessagePageView,
    pub consistency: String,
    #[serde(flatten)]
    pub page: Page<MessageRow>,
    pub unread_total: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct StopFact {
    pub target: String,
    pub complete: bool,
    pub witness: Witness,
    pub resume: ResumeCommand,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeStart {
    pub state: String,
    pub process: ProcessView,
    pub generation: u64,
    pub endpoint: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeStop {
    pub complete: bool,
    pub stops: Vec<StopFact>,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PathEffect {
    pub scope: String,
    pub before_entries: Vec<String>,
    pub after_entries: Vec<String>,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RevocationEffect {
    pub session: SessionId,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct UninstallOutput {
    pub idempotency_key: IdempotencyKey,
    pub complete: bool,
    pub install_files: Vec<FileEffect>,
    pub directories: Vec<DirectoryEffect>,
    pub integrations: Vec<IntegrationEffect>,
    pub stops: Vec<StopFact>,
    pub revocations: Vec<RevocationEffect>,
    pub path: PathEffect,
    pub preserved: Vec<String>,
    pub recovery: Vec<RecoveryDirectoryEffect>,
}
/// Native no-follow inventory of replacement recovery siblings. A filename
/// prefix alone never grants deletion or restoration authority.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RecoveryDirectoryEffect {
    pub directory: String,
    pub copies: Read<Vec<RecoveryCopy>>,
    /// Same finite held-parent scan: exact installer temps with native ownership
    /// and no-follow custody. Unknown/unreadable scans cannot complete uninstall.
    pub temporary_files: Read<Vec<FileEffect>>,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RecoveryCopy {
    pub path: String,
    /// Set only after native identity/digest/security proof and outside readback
    /// restore this copy to an exact target in the original uninstall plan.
    pub restored_to: Option<String>,
    pub witness: Witness,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct LaunchOutput {
    pub schema: String,
    pub agent: Named<AgentId>,
    pub process: ProcessView,
    pub session_id: SessionId,
    pub provider: Provider,
    pub model: Option<String>,
    pub permission_profile: ResolvedProfile,
    pub conversation_id: String,
}
