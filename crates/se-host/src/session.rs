use crate::{BoundSession, CallContext, HostFuture, SessionIdentity, VerifiedCaller};
use se_types::{
    Body, Cursor, EventId, Generation, HostEpoch, HostEventId, HostPendingId, HostSessionId,
    IdempotencyKey, LifecycleId, MessageId, NoticeId, Page, PageRequest, ProviderSessionId, Read,
    Secret, Sequence, Sha256,
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MailTarget {
    pub epoch: HostEpoch,
    pub native_session: HostSessionId,
    pub binding: SessionIdentity,
    pub fingerprint: Sha256,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldReason {
    HumanStop,
    Takeover,
    Revocation,
}
#[derive(Clone, Debug)]
pub struct HoldWitness {
    pub target: MailTarget,
    pub native_event: HostEventId,
    pub key: IdempotencyKey,
    pub retained_pending: u64,
    pub native_sequence: Sequence,
}
#[derive(Clone, Debug)]
pub struct InterruptReport {
    pub target: MailTarget,
    pub requested: bool,
}
#[derive(Clone, Debug)]
pub struct ActiveExecution {
    pub target: MailTarget,
    pub activity: Activity,
}
#[derive(Clone, Debug)]
pub enum BindingEligibility {
    Eligible,
    Held(HoldReason),
    Revoked,
}
#[derive(Clone, Debug)]
pub struct BindingState {
    pub target: MailTarget,
    pub eligibility: BindingEligibility,
    pub activity: Read<Option<Activity>>,
    pub revision: Sequence,
}
#[derive(Clone, Debug)]
pub struct MailNotice {
    pub id: NoticeId,
    pub target: MailTarget,
    pub messages: Vec<MessageId>,
    pub through: Cursor,
    pub digest: Sha256,
}
#[derive(Clone, Debug)]
pub struct NativeAdmission {
    pub epoch: HostEpoch,
    pub notice: NoticeId,
    pub target: MailTarget,
    pub pending: HostPendingId,
    pub digest: Sha256,
    pub committed: HostEventId,
    pub admitted_sequence: Sequence,
    pub committed_sequence: Sequence,
}
#[derive(Clone, Debug)]
pub enum NoticeOutcome {
    Admitted(NativeAdmission),
    Replayed(NativeAdmission),
    Held(HoldWitness),
    Refused(se_types::ErrorBody),
}
/// Narrow proprietary adapter to section 10 HostServices, not a second native
/// queue. All observations include the exact native target and current G.
pub trait NativeQueue: Send + Sync {
    fn hold<'a>(
        &'a self,
        target: &'a MailTarget,
        reason: HoldReason,
        key: IdempotencyKey,
        cx: CallContext,
    ) -> HostFuture<'a, HoldWitness>;
    fn interrupt<'a>(
        &'a self,
        held: &'a HoldWitness,
        cx: CallContext,
    ) -> HostFuture<'a, InterruptReport>;
    fn active<'a>(
        &'a self,
        target: &'a MailTarget,
        cx: CallContext,
    ) -> HostFuture<'a, Read<Option<ActiveExecution>>>;
    fn binding<'a>(
        &'a self,
        target: &'a MailTarget,
        cx: CallContext,
    ) -> HostFuture<'a, Read<BindingState>>;
    fn select<'a>(
        &'a self,
        target: MailTarget,
        superseded: Vec<MailTarget>,
        key: IdempotencyKey,
        cx: CallContext,
    ) -> HostFuture<'a, BindingState>;
    fn revoke<'a>(
        &'a self,
        target: MailTarget,
        key: IdempotencyKey,
        cx: CallContext,
    ) -> HostFuture<'a, BindingState>;
    fn adopt<'a>(
        &'a self,
        prior: MailTarget,
        epoch: HostEpoch,
        key: IdempotencyKey,
        cx: CallContext,
    ) -> HostFuture<'a, Read<BindingState>>;
    fn offer<'a>(
        &'a self,
        notice: &'a MailNotice,
        cx: CallContext,
    ) -> HostFuture<'a, NoticeOutcome>;
    fn notice<'a>(
        &'a self,
        target: &'a MailTarget,
        id: &'a NoticeId,
        cx: CallContext,
    ) -> HostFuture<'a, Read<NoticeOutcome>>;
}
pub struct SessionLease {
    pub(crate) _private: (),
}
pub struct SessionGrant {
    pub identity: SessionIdentity,
    pub generation: Generation,
    pub revision: se_store::Revision,
    pub capability: Secret,
}
#[derive(Clone, Debug)]
pub struct SessionView {
    pub identity: SessionIdentity,
    pub generation: Generation,
    pub phase: SessionPhase,
    pub activity: Read<Activity>,
    pub conversation: Read<ProviderSessionId>,
    pub lifecycle: Read<LifecycleId>,
    pub target: Read<MailTarget>,
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
    pub hold: Option<HoldWitness>,
}
pub trait SessionControl: Send + Sync {
    fn inspect<'a>(
        &'a self,
        caller: &'a VerifiedCaller,
        session: &'a se_types::SessionId,
        cx: CallContext,
    ) -> HostFuture<'a, Read<SessionView>>;
    fn list<'a>(
        &'a self,
        caller: &'a VerifiedCaller,
        page: PageRequest,
        cx: CallContext,
    ) -> HostFuture<'a, Page<SessionView>>;
    fn prepare_takeover<'a>(
        &'a self,
        caller: &'a VerifiedCaller,
        request: TakeoverRequest,
        cx: CallContext,
    ) -> HostFuture<'a, TakeoverTicket>;
    fn finish_takeover<'a>(
        &'a self,
        ticket: TakeoverTicket,
        cx: CallContext,
    ) -> HostFuture<'a, TakeoverReport>;
    fn fail_takeover<'a>(&'a self, ticket: TakeoverTicket, cx: CallContext) -> HostFuture<'a, ()>;
    fn acknowledge<'a>(
        &'a self,
        session: &'a BoundSession,
        message: MessageId,
        key: IdempotencyKey,
        cx: CallContext,
    ) -> HostFuture<'a, se_types::Receipt<MessageId>>;
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
