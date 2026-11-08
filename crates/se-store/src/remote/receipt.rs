//! Exact remote-send readback, without granting an ordinary local snapshot.
use super::*;
use se_types::remote::*;
pub struct RemoteMessageReceipt {
    pub message: se_types::MessageId,
    pub attribution: RemoteAttribution,
    pub delivery: RemoteDeliveryState,
}
impl ReadPhase {
    pub fn remote_send_receipt(
        &self,
        grant: &RemoteGrantId,
        revision: Revision,
        target: &RemoteTarget,
        receipt: &CommitReceipt,
        now: i64,
    ) -> StoreResult<RemoteMessageReceipt> {
        ready(&self.info)?;
        let current = read::grant(&self.db, grant)?.ok_or_else(denied)?;
        if current.store != self.info.id
            || current.state != GrantState::Active
            || current.expires_at_us <= now
            || current.authority_revision != revision
            || !current.scope.allows(RemoteVerb::Send, target)
            || receipt.events.len() != 2
            || receipt.events.first() != Some(&receipt.primary_event)
            || !receipt.first.belongs(&self.info)
            || !receipt.last.belongs(&self.info)
        {
            return Err(denied());
        }
        let project =
            crate::identity::key(&self.db, "project", target.project.as_str(), &[0], false)?;
        let mut namespace = vec![1];
        namespace.extend_from_slice(&project);
        let mut events = Vec::with_capacity(2);
        for event in &receipt.events {
            let key = crate::identity::key(&self.db, "event", event.as_str(), &namespace, false)?;
            let seq: Option<i64> = self
                .db
                .query_row(
                    "SELECT seq FROM events WHERE event_id=?1 AND project_id=?2",
                    rusqlite::params![key, project],
                    |r| r.get(0),
                )
                .optional()
                .map_err(sql)?;
            events.push(crate::read::load_event(
                &self.db,
                seq.ok_or_else(denied)?,
                &self.info,
            )?);
        }
        let EventBody::MessageSent {
            message, recipient, ..
        } = &events[0].body
        else {
            return Err(denied());
        };
        let EventBody::RemoteMessageAttributed { record } = &events[1].body else {
            return Err(denied());
        };
        if record.message != *message
            || record.target != *target
            || record.grant != *grant
            || record.authority_revision != revision
            || record.principal != current.principal
            || *recipient != Actor::Agent(target.agent.clone())
            || events[0].header.actor != Actor::Remote(current.principal)
        {
            return Err(denied());
        }
        let seq = i64::try_from(events[0].position.sequence()).map_err(invalid)?;
        let (delivered, read, dismissed): (Option<i64>, Option<i64>, Option<i64>) = self
            .db
            .query_row(
                "SELECT delivered_seq,read_seq,dismissed_seq FROM marks WHERE message_seq=?",
                [seq],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(sql)?;
        let delivery = if read.is_some() {
            RemoteDeliveryState::Read
        } else if dismissed.is_some() {
            RemoteDeliveryState::Unknown
        } else if delivered.is_some() {
            RemoteDeliveryState::Delivered
        } else {
            RemoteDeliveryState::Pending
        };
        Ok(RemoteMessageReceipt {
            message: message.clone(),
            attribution: record.attribution.clone(),
            delivery,
        })
    }
}
