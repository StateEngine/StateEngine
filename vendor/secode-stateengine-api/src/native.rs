// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    ApiError, Cursor, Generation, Host, HostEpoch, HostEventId, HostPendingId, HostSessionId,
    IdempotencyKey, MessageId, Negotiated, NoticeId, Page, Read, Revision, SessionIdentity, Sha256,
    StoreInfo, TransferId,
};
use std::num::NonZeroU64;
use std::sync::Arc;

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
    WaitingForSecode { transfer: TransferId },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Adoption {
    pub identity: SessionIdentity,
    pub binding_revision: Revision,
    pub state: AdoptionState,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Readiness {
    Prepared,
    Ready,
    Recovering { adoptions: Box<Page<Adoption>> },
}
#[allow(
    missing_debug_implementations,
    reason = "protected grants and opaque runtime callbacks intentionally have no Debug surface"
)]
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
