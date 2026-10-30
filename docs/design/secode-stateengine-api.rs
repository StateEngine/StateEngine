// SPDX-License-Identifier: MIT OR Apache-2.0
//! Proposal for Alpha's MIT/Apache secode-stateengine-api crate, not an engine API.
//! Standalone trait/data declarations: deliberately no dependency on se-types.
//! Checked independently as a crate root for design review, not published or wired.
//! Closed Rust API: adding/removing/changing any public field, enum variant,
//! trait method or its meaning requires a Cargo/API major version change.
//! No blocking or joining in Drop; resources close through explicit async calls.
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiFailure {
    NotIncluded,
    Usage,
    Refused,
    Unauthorized,
    Unknown,
    Unreadable,
    Conflict,
    Incomplete,
    Unavailable,
    Cancelled,
    EnginePanicked,
    GenerationPoisoned,
    Internal,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiCommand {
    Tool {
        name: String,
        args: serde_json::Value,
    },
    Manual,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiRemedy {
    pub text: String,
    pub command: Option<ApiCommand>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiRetry {
    Never,
    AfterMillis(u64),
    AfterRefresh,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiError {
    pub kind: ApiFailure,
    pub code: String,
    pub message: String,
    pub remedy: ApiRemedy,
    pub retry: ApiRetry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostSessionId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEventId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostPendingId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSessionId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyKey(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoticeId(pub String);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cursor(pub String);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Generation(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostGeneration(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sequence(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixMicros(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256(pub [u8; 32]);
pub type NativePath = PathBuf;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StartIdentity {
    Windows {
        creation_filetime: u64,
    },
    Linux {
        start_ticks: u64,
    },
    Macos {
        start_seconds: u64,
        start_micros: u32,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessInstance {
    pub machine: String,
    pub boot: String,
    pub pid: u32,
    pub started: StartIdentity,
    pub executable: PathBuf,
    pub argv_sha256: Sha256,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEpoch {
    pub owner: ProcessInstance,
    pub generation: HostGeneration,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Source {
    Store {
        store: StoreId,
        project: Option<ProjectId>,
    },
    Host {
        epoch: HostEpoch,
    },
    Configuration {
        location: String,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Read<T> {
    Present {
        value: T,
    },
    Absent {
        checked: String,
    },
    Unreadable {
        source: String,
        reason: String,
        error: Option<ApiError>,
    },
    Unknown {
        what: String,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OmissionReason {
    Limit,
    Budget,
    Unreadable,
    SourceIncomplete,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Omission {
    None,
    Known { count: u64, reason: OmissionReason },
    Unknown { reason: OmissionReason },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    Exhausted,
    ItemLimit,
    ByteLimit,
    Unreadable,
    Cancelled,
    Deadline,
    Unsupported,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Window {
    pub source: Source,
    pub from: Sequence,
    pub to: Sequence,
    pub start_cursor: Option<Cursor>,
    pub end_cursor: Option<Cursor>,
    pub returned: u64,
    pub limit: u32,
    pub bytes: u64,
    pub max_bytes: u32,
    pub omitted_before: Omission,
    pub omitted_after: Omission,
    pub unreadable: u64,
    pub stop_reason: StopReason,
    pub complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub window: Window,
    pub next: Option<Cursor>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageRequest {
    pub after: Option<Cursor>,
    pub limit: u32,
    pub max_bytes: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRef {
    pub id: EventId,
    pub sequence: Sequence,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectStatus {
    NotRequired,
    Pending,
    Witnessed { witness: EventRef },
    Failed { error: ApiError },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commit<T> {
    pub event: EventRef,
    pub idempotency_key: IdempotencyKey,
    pub value: T,
    pub effects: EffectStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingReason {
    Queued,
    AwaitingWitness,
    Recovering,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Receipt<T> {
    Committed {
        commit: Commit<T>,
    },
    Replayed {
        original: Commit<T>,
    },
    Refused {
        error: ApiError,
    },
    Pending {
        cause: PendingReason,
        event: Option<EventRef>,
        idempotency_key: IdempotencyKey,
    },
}
use serde_json::Value;
use std::{
    future::Future,
    num::{NonZeroU32, NonZeroU64},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

pub type HostFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiVersion {
    pub major: u16,
    pub minor: u16,
}
pub const API_VERSION: ApiVersion = ApiVersion { major: 1, minor: 0 };

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreVersion {
    pub application_id: u32,
    pub schema: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostKind {
    EmbeddedSecode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Feature {
    NativeMail,
    LocalListener,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Negotiated {
    pub api: ApiVersion,
    pub store: StoreVersion,
    pub generation: Generation,
    pub features: Vec<Feature>,
    pub limits: Limits,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    pub page_items: NonZeroU32,
    pub payload_bytes: NonZeroU32,
    pub notice_ids: NonZeroU32,
}
#[derive(Clone, Debug)]
pub struct HostConfig {
    pub state_home: NativePath,
    pub api: ApiVersion,
    pub kind: HostKind,
    pub features: Vec<Feature>,
    pub limits: Limits,
}
pub trait Cancellation: Send + Sync + std::fmt::Debug {
    fn is_cancelled(&self) -> bool;
    fn cancelled(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
#[derive(Clone, Debug)]
pub struct OpenOptions {
    pub expected_generation: Option<Generation>,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}
#[derive(Clone, Debug)]
pub struct CallOptions {
    pub generation: Generation,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}
#[derive(Clone, Debug)]
pub struct ServiceOptions {
    pub generation: Generation,
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}

// Protected byte buffers have no Debug, Clone or Deserialize.
pub struct SessionCapability(pub Vec<u8>);
pub struct LaunchCredential(pub Vec<u8>);
/// Trusted SE Code control-plane authority, never decoded from model/tool input.
#[derive(Clone, Copy, Debug)]
pub struct OwnerAuthority;
/// Engine-issued grant; every call revalidates its identity, revision and generation.
pub struct BoundSession {
    pub grant: Vec<u8>,
    pub identity: SessionIdentity,
    pub generation: Generation,
    pub binding_revision: Sequence,
}
pub enum Authority {
    Owner(OwnerAuthority),
    Session(BoundSession),
    Anonymous,
}
pub enum BindingAuthority {
    Owner(OwnerAuthority),
    Launch(LaunchCredential),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIdentity {
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Harness {
    ClaudeCode,
    CodexAppServer,
    Secode,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelIdentity {
    pub provider: String,
    pub model: String,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectInfo {
    pub id: ProjectId,
    pub name: String,
    pub root: NativePath,
    pub revision: Sequence,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreInfo {
    pub id: StoreId,
    pub version: StoreVersion,
    pub head: Sequence,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingRequest {
    pub project: ProjectId,
    pub agent: AgentId,
    pub harness: Harness,
    pub model: ModelIdentity,
    pub conversation: ProviderSessionId,
    pub target: Option<HostSessionTarget>,
    pub expected_binding_revision: Option<Sequence>,
    pub capture_consent: bool,
    pub idempotency_key: IdempotencyKey,
}
pub struct IssuedSession {
    pub identity: SessionIdentity,
    pub generation: Generation,
    pub binding_revision: Sequence,
    pub capability: SessionCapability,
    pub receipt: Receipt<SessionIdentity>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndReason {
    UserStopped,
    SessionEnded,
    Replaced,
    Removed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeRequest {
    pub session: SessionId,
    pub reason: EndReason,
    pub key: IdempotencyKey,
}

#[derive(Clone, Debug)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
}
#[derive(Clone, Debug)]
pub struct ToolCall {
    pub name: String,
    pub arguments: Value,
    pub idempotency_key: Option<IdempotencyKey>,
}
#[derive(Clone, Debug)]
pub struct ToolOutput {
    pub schema: String,
    pub content: Value,
    pub window: Option<Window>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuityRequest {
    pub page: PageRequest,
    pub acknowledge_packet: Option<Sha256>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedText {
    pub text: String,
    pub utf8_bytes: u64,
    pub complete: bool,
    pub omitted_bytes: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub digest: Sha256,
    pub content: BoundedText,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextDisplayIdentity {
    pub agent: AgentId,
    pub display_name: Option<String>,
    pub role: Option<String>,
    pub neutral: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuitySummary {
    pub rows: u64,
    pub latest_at: Option<UnixMicros>,
}
/// Linked DTO; an explicitly versioned adapter retains legacy context fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionContext {
    pub schema: String,
    pub identity: SessionIdentity,
    pub display_identity: ContextDisplayIdentity,
    pub generated_at: UnixMicros,
    pub source_cli: String,
    pub harness: Harness,
    pub model: ModelIdentity,
    pub conversation: ProviderSessionId,
    pub packet: Read<Packet>,
    pub model_input: BoundedText,
    pub continuity: Window,
    pub continuity_summary: ContinuitySummary,
    pub warnings: Vec<String>,
    pub failures: Vec<ApiError>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnRole {
    User,
    Assistant,
    Tool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnNesting {
    pub parent_session: Option<ProviderSessionId>,
    pub nested_agent: Option<AgentId>,
    pub depth: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedTurn {
    pub conversation: ProviderSessionId,
    pub vendor_turn: String,
    pub vendor_event: Option<String>,
    pub machine_id: Option<String>,
    pub source_ref: Option<String>,
    pub source_cli: String,
    pub nesting: Option<TurnNesting>,
    pub role: TurnRole,
    pub occurred_at: UnixMicros,
    pub content: BoundedText,
    pub source_sha256: Sha256,
    pub idempotency_key: IdempotencyKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostSessionTarget {
    pub epoch: HostEpoch,
    pub session: HostSessionId,
    pub binding: SessionIdentity,
    pub binding_fingerprint: Sha256,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEventRef {
    pub id: HostEventId,
    pub sequence: NonZeroU64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldReason {
    HumanStop,
    Takeover,
    Revocation,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HoldReceipt {
    pub target: HostSessionTarget,
    pub committed: HostEventRef,
    pub retained_pending: u64,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterruptReceipt {
    pub target: HostSessionTarget,
    pub requested: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionActivity {
    Idle,
    Executing,
    Interrupting,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActiveSession {
    pub target: HostSessionTarget,
    pub activity: SessionActivity,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetStatus {
    Eligible,
    Held,
    Revoked,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdoptBinding {
    pub previous: HostSessionTarget,
    pub current_epoch: HostEpoch,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingObservation {
    pub target: HostSessionTarget,
    pub status: TargetStatus,
    pub last_transition: HostEventRef,
    pub activity: Read<SessionActivity>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetTransition {
    Select {
        target: HostSessionTarget,
        superseded: Vec<HostSessionTarget>,
    },
    Revoke {
        target: HostSessionTarget,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetReceipt {
    pub target: HostSessionTarget,
    pub committed: HostEventRef,
    pub status: TargetStatus,
}
/// Contains IDs only: the model obtains bodies using the bound read operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailNotice {
    pub id: NoticeId,
    pub target: HostSessionTarget,
    pub messages: Vec<MessageId>,
    pub through: Cursor,
    pub dedupe_sha256: Sha256,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Admission {
    pub committed_in: HostEpoch,
    pub notice: NoticeId,
    pub target: HostSessionTarget,
    pub pending: HostPendingId,
    pub admitted_sequence: NonZeroU64,
    pub dedupe_sha256: Sha256,
    pub committed: HostEventRef,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoticeAdmission {
    Admitted(Admission),
    Replayed(Admission),
    Held(HoldReceipt),
    Refused(ApiError),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdoptionState {
    Pending,
    Reattached,
    Held,
    Revoked,
    Absent,
    Unreadable(ApiError),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Adoption {
    pub identity: SessionIdentity,
    pub binding_revision: Sequence,
    pub state: AdoptionState,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Readiness {
    Prepared,
    Ready,
    Recovering { adoptions: Box<Page<Adoption>> },
}
pub struct OpenedHost {
    pub host: Arc<dyn Host>,
    pub negotiated: Negotiated,
    pub store: StoreInfo,
    pub readiness: Readiness,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainReceipt {
    pub generation: Generation,
    pub pending_notices: u64,
    pub unresolved_effects: u64,
    pub writer_flushed: bool,
}

/// The implementation/factory is configured with the embedding host's runtime.
/// No Tokio dependency or runtime creation belongs to this permissive API crate.
pub enum HostIntegration {
    Secode {
        epoch: HostEpoch,
        services: Arc<dyn HostServices>,
    },
}

pub trait HostFactory: Send + Sync {
    /// Cold open is preparation only: no writer, native mutation or callbacks.
    fn open<'a>(
        &'a self,
        config: HostConfig,
        options: OpenOptions,
    ) -> HostFuture<'a, Read<OpenedHost>>;
    /// Independent supervisor closes the old generation, then prepares a fresh one.
    fn restart<'a>(
        &'a self,
        reason: RestartReason,
        key: IdempotencyKey,
        options: CallOptions,
    ) -> HostFuture<'a, Read<OpenedHost>>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestartReason {
    Drained { receipt: DrainReceipt },
    Poisoned { incident: String },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationHealth {
    Prepared,
    Activating,
    Ready,
    Recovering,
    Draining,
    Drained,
    Poisoned,
    Closed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultReport {
    pub incident: String,
}

pub trait Host: Send + Sync {
    fn poison<'a>(
        &'a self,
        report: FaultReport,
        options: CallOptions,
    ) -> HostFuture<'a, GenerationHealth>;

    /// Non-blocking snapshots; no I/O or wait for worker threads.
    fn negotiated(&self) -> Negotiated;
    fn health(&self) -> GenerationHealth;
    fn wait_health<'a>(
        &'a self,
        after: GenerationHealth,
        options: CallOptions,
    ) -> HostFuture<'a, GenerationHealth>;
    /// Caller registers this handle/generation before this first mutating call.
    fn activate<'a>(
        &'a self,
        integration: HostIntegration,
        options: CallOptions,
    ) -> HostFuture<'a, Readiness>;
    fn verify_capability<'a>(
        &'a self,
        capability: &'a SessionCapability,
        options: CallOptions,
    ) -> HostFuture<'a, BoundSession>;
    fn open_project<'a>(
        &'a self,
        authority: &'a OwnerAuthority,
        project: ProjectId,
        options: CallOptions,
    ) -> HostFuture<'a, Read<ProjectInfo>>;
    fn bind_session<'a>(
        &'a self,
        authority: &'a BindingAuthority,
        request: BindingRequest,
        options: CallOptions,
    ) -> HostFuture<'a, IssuedSession>;
    fn revoke_session<'a>(
        &'a self,
        authority: &'a Authority,
        request: RevokeRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Receipt<SessionIdentity>>;
    fn tools<'a>(
        &'a self,
        session: &'a BoundSession,
        page: PageRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Page<ToolDefinition>>;
    fn call_tool<'a>(
        &'a self,
        session: &'a BoundSession,
        call: ToolCall,
        options: CallOptions,
    ) -> HostFuture<'a, ToolOutput>;
    fn continuity<'a>(
        &'a self,
        session: &'a BoundSession,
        request: ContinuityRequest,
        options: CallOptions,
    ) -> HostFuture<'a, SessionContext>;
    fn capture_turn<'a>(
        &'a self,
        session: &'a BoundSession,
        turn: CapturedTurn,
        options: CallOptions,
    ) -> HostFuture<'a, Receipt<EventRef>>;
    /// Nudge only: re-read eligibility/debt; cannot acknowledge admission or clear holds.
    fn native_state_changed<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: CallOptions,
    ) -> HostFuture<'a, ()>;
    fn adoption_status<'a>(
        &'a self,
        authority: &'a OwnerAuthority,
        page: PageRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Page<Adoption>>;
    fn drain<'a>(&'a self, options: CallOptions) -> HostFuture<'a, DrainReceipt>;
    fn close<'a>(
        &'a self,
        drained: DrainReceipt,
        options: CallOptions,
    ) -> HostFuture<'a, DrainReceipt>;
}
/// SE Code owns admission and promotion of its one input queue.
/// StateEngine owns message bodies, recipient read/dismiss markers and debt.
pub trait HostServices: Send + Sync {
    fn hold<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        reason: HoldReason,
        key: IdempotencyKey,
        options: ServiceOptions,
    ) -> HostFuture<'a, HoldReceipt>;
    fn interrupt<'a>(
        &'a self,
        held: &'a HoldReceipt,
        options: ServiceOptions,
    ) -> HostFuture<'a, InterruptReceipt>;
    /// Point observation; Present(None) proves no active execution at this read.
    fn active_session<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<Option<ActiveSession>>>;
    /// Diagnostic pages cannot be combined into an absence proof.
    fn active_sessions<'a>(
        &'a self,
        epoch: &'a HostEpoch,
        page: PageRequest,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<Page<ActiveSession>>>;
    fn idle<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<SessionActivity>>;
    fn binding_state<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<BindingObservation>>;
    fn adopt_binding<'a>(
        &'a self,
        request: AdoptBinding,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<BindingObservation>>;
    fn update_mail_target<'a>(
        &'a self,
        transition: TargetTransition,
        key: IdempotencyKey,
        options: ServiceOptions,
    ) -> HostFuture<'a, TargetReceipt>;
    fn deliver_notice<'a>(
        &'a self,
        notice: &'a MailNotice,
        options: ServiceOptions,
    ) -> HostFuture<'a, NoticeAdmission>;
    fn notice_status<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        notice: &'a NoticeId,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<NoticeAdmission>>;
}
