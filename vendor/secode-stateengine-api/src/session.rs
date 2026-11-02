// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    AgentId, ApiError, Cursor, Generation, HostSessionTarget, IdempotencyKey, NativePath,
    PageRequest, ProjectId, ProviderSessionId, Read, Receipt, Revision, SessionId, Sha256, StoreId,
    StoreVersion, UnixMicros, Window,
};
use serde_json::Value;

// Protected byte buffers have no Debug, Clone or Deserialize.
#[allow(
    missing_debug_implementations,
    reason = "protected grants and opaque runtime callbacks intentionally have no Debug surface"
)]
pub struct SessionCapability(pub Vec<u8>);
#[allow(
    missing_debug_implementations,
    reason = "protected grants and opaque runtime callbacks intentionally have no Debug surface"
)]
pub struct LaunchCredential(pub Vec<u8>);
/// Trusted SE Code control-plane authority, never decoded from model/tool input.
#[derive(Clone, Copy, Debug)]
pub struct OwnerAuthority;
/// Engine-issued grant; every call revalidates its identity, revision and generation.
#[allow(
    missing_debug_implementations,
    reason = "protected grants and opaque runtime callbacks intentionally have no Debug surface"
)]
pub struct BoundSession {
    pub grant: Vec<u8>,
    pub identity: SessionIdentity,
    pub generation: Generation,
    pub binding_revision: Revision,
}
#[allow(
    missing_debug_implementations,
    reason = "protected grants and opaque runtime callbacks intentionally have no Debug surface"
)]
pub enum Authority {
    Owner(OwnerAuthority),
    Session(BoundSession),
    Anonymous,
}
#[allow(
    missing_debug_implementations,
    reason = "protected grants and opaque runtime callbacks intentionally have no Debug surface"
)]
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
    pub revision: Revision,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreInfo {
    pub id: StoreId,
    pub version: StoreVersion,
    pub head: Option<Cursor>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingRequest {
    pub project: ProjectId,
    pub agent: AgentId,
    pub harness: Harness,
    pub model: ModelIdentity,
    pub conversation: ProviderSessionId,
    pub target: Option<HostSessionTarget>,
    pub expected_binding_revision: Option<Revision>,
    pub capture_consent: bool,
    pub idempotency_key: IdempotencyKey,
}
#[allow(
    missing_debug_implementations,
    reason = "protected grants and opaque runtime callbacks intentionally have no Debug surface"
)]
pub struct IssuedSession {
    pub identity: SessionIdentity,
    pub generation: Generation,
    pub binding_revision: Revision,
    pub session: BoundSession,
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
/// Registry-checked request identity; only capture/markers admit NaturalKey.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestIdentity {
    ReadOnly,
    Mutation(IdempotencyKey),
    NaturalKey,
}
#[derive(Clone, Debug)]
pub struct ToolCall {
    pub name: String,
    pub arguments: Value,
    pub identity: RequestIdentity,
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
