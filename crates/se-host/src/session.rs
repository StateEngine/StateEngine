use crate::SessionIdentity;
use se_types::{
    Body, Cursor, EventId, IdempotencyKey, MessageId, NativePath, NoticeId, ProviderSessionId,
    Sha256,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessKind {
    ClaudeCode,
    CodexAppServer,
    Secode,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhase {
    Prepared,
    Starting,
    Active,
    Holding,
    Held,
    Ending,
    Ended,
    Revoked,
    RecoveryPending,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activity {
    Idle,
    Executing,
    Interrupting,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldReason {
    HumanStop,
    Takeover,
    Revocation,
}
/// Provider notice only. SE Code uses the canonical linked MailNotice and
/// NoticeAdmission types; this DTO does not translate a native queue receipt.
#[derive(Clone, Debug)]
pub struct ProviderNotice {
    pub id: NoticeId,
    pub identity: SessionIdentity,
    pub messages: Vec<MessageId>,
    pub through: Cursor,
    pub digest: Sha256,
}
pub struct SessionLease {
    pub(crate) _private: (),
}
pub struct SessionCoordinator {
    pub(crate) _private: (),
}
pub struct TakeoverRequest {
    pub agent: se_types::AgentId,
    pub expected: se_store::Revision,
    pub key: IdempotencyKey,
    pub profile: se_store::Profile,
    pub new_conversation: bool,
}
pub struct TakeoverTicket {
    pub(crate) _private: (),
}
#[derive(Clone, Debug)]
pub struct TakeoverReport {
    pub successor: SessionIdentity,
    pub predecessor: Option<SessionIdentity>,
    pub activation: EventId,
}
/// Created at trusted bind, never from a hook's claimed transcript_path.
#[derive(Clone, Debug)]
pub struct TranscriptPin {
    pub identity: SessionIdentity,
    pub conversation: ProviderSessionId,
    pub path: NativePath,
    pub file_identity: Sha256,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureRole {
    User,
    Assistant,
    Tool,
}
pub struct CaptureInput {
    pub conversation: ProviderSessionId,
    pub vendor_turn: String,
    pub role: CaptureRole,
    pub text: Body,
    pub source_digest: Sha256,
    pub key: IdempotencyKey,
}
