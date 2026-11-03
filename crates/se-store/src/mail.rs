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
    fn mail_notices(
        &mut self,
        recipient: AgentId,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>>;
}
