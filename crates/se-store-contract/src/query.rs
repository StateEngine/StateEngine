use crate::*;
use se_types::{AgentId, EventId, MessageId, Page, ProjectId, Read, SessionId};
#[derive(Clone, Debug)]
pub struct MessageQuery {
    pub recipient: Option<Actor>,
    pub sender: Option<Actor>,
    pub kind: Option<String>,
    pub unread_only: bool,
    pub full_body: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryFamily {
    Identity,
    Sessions,
    Messages,
    Decisions,
    Turns,
    Processes,
    WorkingState,
    Cursors,
    Effects,
    Import,
    Recovery,
}
#[derive(Clone, Copy, Debug, Default)]
pub enum TranscriptFilter {
    #[default]
    All,
    Chat,
    Metadata,
}
#[derive(Clone, Debug)]
pub struct HistoryQuery {
    pub agent: Option<AgentId>,
    pub session: Option<SessionId>,
    /// Empty means every authorized kind; codec rejects unknown exact names.
    pub kinds: Vec<EventKind>,
    pub families: Vec<HistoryFamily>,
    pub transcript: TranscriptFilter,
    pub since: Option<StorePosition>,
}
#[derive(Clone, Debug)]
pub struct SearchQuery {
    pub text: String,
    pub history: HistoryQuery,
}
/// Internal storage record, not a frozen CLI/MCP wire DTO.
#[derive(Clone)]
pub struct MessageRecord {
    pub message: MessageId,
    pub event: EventId,
    pub revision: Revision,
    pub sent: StorePosition,
    pub sender: Actor,
    pub recipient: Actor,
    pub work: Option<se_types::WorkAddressing>,
    pub kind: String,
    pub body: StoredText,
    pub refs: Vec<EventId>,
    pub reply_to: Option<MessageId>,
    pub delivered: Option<StorePosition>,
    pub read: Option<StorePosition>,
    pub dismissed: Option<StorePosition>,
    pub superseded_by: Option<MessageId>,
    pub body_complete: bool,
    pub quiet: bool,
    pub notifications: Vec<NotificationRecord>,
}
/// Advisory wake observations; none imply accepted input or a read marker.
#[derive(Clone, Debug)]
pub struct NotificationRecord {
    pub recipient: Actor,
    pub state: String,
    pub event: Option<EventId>,
    pub recorded_at_us: Option<i64>,
    pub code: Option<String>,
}
#[derive(Clone, Debug)]
pub struct CredentialRecord {
    pub credential: RecordId,
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
    pub purpose: String,
    pub expires_at_us: i64,
    pub activation_deadline_us: i64,
    pub state: CredentialState,
    pub revision: Revision,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialState {
    Prepared,
    Active,
    Revoked,
}
#[derive(Clone)]
pub struct SearchHit {
    pub event: EventId,
    pub revision: Revision,
    pub snippet: StoredText,
    pub body_complete: bool,
}

/// Text search omits intentionally erased candidates separately from unreadable
/// omissions in the page window. Erasure is not a failed read or a match.
#[derive(Clone)]
pub struct SearchPage {
    pub page: Page<SearchHit>,
    pub erased: u64,
}
impl SearchPage {
    pub fn items(&self) -> &[SearchHit] {
        self.page.items()
    }
    pub fn window(&self) -> &se_types::Window {
        self.page.window()
    }
    pub fn next(&self) -> Option<&se_types::Cursor> {
        self.page.next()
    }
}
/// Current-head record; body is reconstructed from the owning immutable event.
#[derive(Clone)]
pub struct ProjectionRecord {
    pub revision: Revision,
    pub original: Option<Box<StoredEvent>>,
    pub current: StoredEvent,
}
/// A cursor as issued, its head revision, and the acknowledgment that marked
/// it read, if any. Issuance alone is never acknowledgment.
#[derive(Clone, Debug)]
pub struct CursorHead {
    pub record: CursorRecord,
    pub revision: Revision,
    pub acknowledged: Option<CursorAck>,
}
/// The `cursor.acknowledged` event and the consumer evidence it cited.
#[derive(Clone, Debug)]
pub struct CursorAck {
    pub event: EventId,
    pub evidence: EventId,
}
/// A control target's principal, profile, live (prepared/active) sessions and
/// unreleased processes, oldest first. A prepared session counts until it is
/// revoked, so launch failure must revoke its preparation; more than the
/// bound refuses ReadIncomplete instead of omitting one.
/// Never continuity, mail or turns.
#[derive(Clone)]
pub struct ControlTarget {
    pub principal: ProjectionRecord,
    pub profile: Read<ProjectionRecord>,
    pub sessions: Vec<ProjectionRecord>,
    pub processes: Vec<ProjectionRecord>,
    /// Newest session in any state, ended or revoked included.
    pub latest_session: Read<ProjectionRecord>,
    /// Newest session a launch auto-resume may select. A revoked
    /// preparation that never activated (the launch failed before first
    /// use) never shadows an older resumable session.
    pub resume_session: Read<ProjectionRecord>,
    /// Newest process in any state, exited or ownership-released included.
    pub latest_process: Read<ProjectionRecord>,
    /// Every registered root this project moved away from, newest move
    /// first. Move roots are project identity, not private history: the
    /// launch plan needs them to find a resumed provider transcript, which
    /// stays under the slug of the root where it was written.
    pub moved_from_roots: Vec<se_types::NativePath>,
}
/// Exact retained registration selector; active project lists remain separate.
#[derive(Clone, Debug)]
pub enum RemovedProjectQuery {
    Name(String),
    Root(se_types::NativePath),
}
