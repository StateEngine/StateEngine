//! Store batch validation and finite mail read ports.
use crate::{error::*, *};
pub use se_store_contract::mail::*;
use se_types::{AgentId, Page, SessionId};
pub(crate) fn validate_offer_batch(batch: &AtomicBatch) -> StoreResult<()> {
    for event in &batch.events {
        if let EventBody::EffectOffered {
            effect,
            attempt,
            evidence: OfferEvidence::Observed(observation),
            ..
        } = &event.body
        {
            observation.validate()?;
            if batch.events.len() != 1
                || batch.request.as_ref().map(|r| &r.key) != Some(&offer_key(*effect, *attempt)?)
            {
                return Err(invalid(
                    "one observed mail offer requires its deterministic original effect/attempt request key",
                ));
            }
        }
    }
    Ok(())
}
/// The core mail planner adds this bound to Snapshot; ordinary readers and
/// pre-existing Snapshot implementations need no new capability.
pub trait MailSnapshot: Snapshot {
    /// Actual current read/dismiss evidence for this recipient's exact message.
    fn mail_resolution(
        &mut self,
        message: se_types::MessageId,
        recipient: AgentId,
    ) -> StoreResult<se_types::Read<StoredEvent>>;
    /// Matching accepted input across the checked session interval, bounded by
    /// the supplied deadline. An interrupted scan is ReadIncomplete, never Absent.
    fn mail_input(
        &mut self,
        recipient: AgentId,
        session: SessionId,
        after: StorePosition,
        text_sha256: [u8; 32],
        deadline: std::time::Duration,
    ) -> StoreResult<se_types::Read<StoredEvent>>;

    /// Indexed, unread and undelivered recipient mail. Delivered-but-unread
    /// notices retain settlement debt without hiding a newer pending message.
    fn mail_pending(
        &mut self,
        recipient: AgentId,
        budget: ReadBudget,
    ) -> StoreResult<Page<MessageRecord>>;

    /// Read only a committed recipient read or dismiss
    /// concerning this verified recipient, without broad event visibility.
    fn mail_disposition(
        &mut self,
        event: se_types::EventId,
        recipient: AgentId,
    ) -> StoreResult<se_types::Read<StoredEvent>>;
    /// Recreate a checked-through cursor under the verified recipient's read
    /// scope. Owner maintenance may reserve, but cannot mint an agent cursor
    /// under the owner's unrelated principal binding.
    fn mail_cursor(&self, through: &MailThrough) -> StoreResult<se_types::Cursor>;
    fn mail_notices(
        &mut self,
        recipient: AgentId,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>>;
}
