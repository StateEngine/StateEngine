//! Immutable mail-notice intent, separate from legacy single-message bells.
//! This stores references and debt; provider promotion remains host work.
use crate::{error::*, *};
use se_types::{AgentId, HostEpoch, MessageId, Page, SessionId, StoreId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailThrough {
    pub store: StoreId,
    pub incarnation: u64,
    pub sequence: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailNotice {
    pub version: u16,
    pub notice_id: RecordId,
    pub target_agent: AgentId,
    pub session: SessionId,
    pub epoch: HostEpoch,
    pub generation: u64,
    pub fingerprint: [u8; 32],
    pub ids: Vec<MessageId>,
    pub through: MailThrough,
    pub digest: [u8; 32],
}
/// Preserve legacy committed-event evidence as its original JSON string.
/// New Bell offers store the host's actual observation, never a self witness.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OfferEvidence {
    Committed(se_types::EventId),
    Observed(Box<OfferObservation>),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferObservation {
    pub version: u16,
    pub notice_id: RecordId,
    pub target_agent: AgentId,
    pub session: SessionId,
    pub epoch: HostEpoch,
    pub generation: u64,
    pub fingerprint: [u8; 32],
    pub observed_at_us: i64,
    pub digest: [u8; 32],
    pub report: OfferReport,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OfferReport {
    TransportWritten {
        transport: MailTransport,
        bytes: u64,
    },
    VendorReported {
        provider: Provider,
        event_id: String,
    },
    NativeAdmitted {
        event_id: String,
        sequence: u64,
    },
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailTransport {
    ClaudeMod,
    CodexAppServer,
    LocalHttp,
    Stdio,
}
impl OfferObservation {
    pub fn validate(&self) -> StoreResult<()> {
        if self.version != 1 || self.generation == 0 || self.observed_at_us < 0 {
            return Err(invalid(
                "mail offer observation requires version 1, positive generation and nonnegative time",
            ));
        }
        let valid = match &self.report {
            OfferReport::TransportWritten { bytes, .. } => (1..=8192).contains(bytes),
            OfferReport::VendorReported { event_id, .. } => id(event_id),
            OfferReport::NativeAdmitted { event_id, sequence } => id(event_id) && *sequence > 0,
        };
        if !valid {
            return Err(invalid(
                "bounded nonempty transport/vendor/native offer evidence required",
            ));
        }
        Ok(())
    }
}
fn id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}
pub fn offer_key(effect: RecordId, attempt: RecordId) -> StoreResult<se_types::IdempotencyKey> {
    let mut hash = Sha256::new();
    hash.update(b"stateengine.mail-offer/v1");
    hash.update(effect.as_bytes());
    hash.update(attempt.as_bytes());
    se_types::IdempotencyKey::new(format!(
        "mail.offer.{}",
        se_types::hex_lower(&hash.finalize())
    ))
    .map_err(invalid)
}
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
impl MailNotice {
    /// One canonical descriptor shared by the planner and persisted validator.
    /// No body or transport evidence is part of a reserved notice.
    pub fn expected_digest(&self) -> StoreResult<[u8; 32]> {
        let bytes = serde_json::to_vec(&(
            "stateengine.mail-notice/v1",
            self.version,
            self.notice_id,
            &self.target_agent,
            &self.session,
            &self.epoch,
            self.generation,
            self.fingerprint,
            &self.ids,
            &self.through,
        ))
        .map_err(invalid)?;
        Ok(Sha256::digest(bytes).into())
    }
    pub fn validate(&self) -> StoreResult<()> {
        if self.version != 1
            || self.generation == 0
            || self.through.incarnation == 0
            || self.through.sequence == 0
            || self.through.sequence > i64::MAX as u64
            || self.ids.is_empty()
            || self.ids.len() > 32
        {
            return Err(invalid(
                "version-1 mail notice requires positive bounds and 1..32 IDs",
            ));
        }
        let distinct: std::collections::BTreeSet<_> = self.ids.iter().collect();
        if distinct.len() != self.ids.len() || self.expected_digest()? != self.digest {
            return Err(invalid(
                "mail notice has duplicate IDs or a different digest",
            ));
        }
        if serde_json::to_vec(self).map_err(invalid)?.len() > 8192 {
            return Err(fail(
                StoreErrorCode::BodyTooLarge,
                "mail notice exceeds 8 KiB",
            ));
        }
        Ok(())
    }
}
/// The core mail planner adds this bound to Snapshot; ordinary readers and
/// pre-existing Snapshot implementations need no new capability.
pub trait MailSnapshot: Snapshot {
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
