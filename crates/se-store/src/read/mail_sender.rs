//! Message-bound provenance, never a remote-principal-wide Owner promotion.
use super::*;
use se_types::remote::{RemoteAttribution, RemoteVerb};

fn inconsistent() -> Box<StoreError> {
    fail(
        StoreErrorCode::ProjectionInconsistent,
        "remote mail provenance differs from its committed message or grant",
    )
}

impl SqliteSnapshot {
    pub(super) fn read_return_sender(
        &mut self,
        id: se_types::MessageId,
    ) -> StoreResult<Option<se_types::remote::RemoteAgentAddress>> {
        if self.info.schema_version < 12 {
            return Ok(None);
        }
        let message = self.message(id)?;
        crate::return_mail::sender(&self.db, &self.scope.admission, &message)
    }
    pub(super) fn read_remote_message_attribution(
        &mut self,
        id: se_types::MessageId,
    ) -> StoreResult<Option<RemoteAttribution>> {
        // Admit the actual message through ordinary project/recipient visibility
        // before the private attribution lookup; it exposes no grant inventory.
        let message = match self.message(id)? {
            Read::Present { value } => value,
            Read::Absent { checked } => {
                return Err(fail(StoreErrorCode::ReferenceMissing, checked));
            }
            Read::Unreadable { reason, .. } => {
                return Err(fail(StoreErrorCode::Unreadable, reason));
            }
            Read::Unknown { what } => {
                return Err(fail(StoreErrorCode::Unreadable, what));
            }
        };
        let Actor::Remote(principal) = &message.sender else {
            return Ok(None);
        };
        let Scope::Project(project) = &self.scope.admission.scope else {
            return Err(inconsistent());
        };
        if self.info.schema_version < 7 {
            return Err(inconsistent());
        }
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let m = key(&self.db, "message", message.message.as_str(), &scope, false)?;
        let seq: Option<i64> = self
            .db
            .query_row(
                "SELECT event_seq FROM remote_message_attribution WHERE project_id=? AND message_id=?",
                rusqlite::params![p, m],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| self.read_sql(error))?;
        // This private event is not an ordinary self-visible event. Its only
        // result is provenance for the already admitted exact message above.
        let event = load_event(&self.db, seq.ok_or_else(inconsistent)?, &self.info)?;
        let EventBody::RemoteMessageAttributed { record } = event.body else {
            return Err(inconsistent());
        };
        if event.header.scope != self.scope.admission.scope
            || event.header.actor != message.sender
            || event.header.session.is_some()
            || record.message != message.message
            || record.principal != *principal
            || record.target.project != *project
            || message.recipient != Actor::Agent(record.target.agent.clone())
            || message.work.is_some()
        {
            return Err(inconsistent());
        }
        let grant = crate::remote::grant_at(&self.db, &record.grant)?.ok_or_else(inconsistent)?;
        let stamp = &record.attribution;
        if grant.principal != *principal
            || grant.store != self.info.id
            || grant.authority_revision.value < record.authority_revision.value
            || !grant.scope.allows(RemoteVerb::Send, &record.target)
            || stamp.host != grant.host
            || stamp.store != grant.store
            || stamp.principal != grant.principal
            || stamp.grant != grant.grant
            || stamp.device != grant.device
            || stamp.authority_revision != record.authority_revision.value.get()
            || !grant.subject.admits_source(stamp.source.as_ref())
        {
            return Err(inconsistent());
        }
        // The writer validated revision, lease and subject when this message
        // committed. Expiry/revocation fences future sends, not that admission.
        Ok(Some(stamp.clone()))
    }
}

impl SqliteSnapshot {
    pub(super) fn read_remote_reply_recipient(
        &mut self,
        original: se_types::MessageId,
        selector: &str,
    ) -> StoreResult<Option<Actor>> {
        if let Some(address) = self.read_return_sender(original.clone())? {
            if address.selector() != selector {
                return Ok(None);
            }
            let message = match self.message(original)? {
                Read::Present { value } => value,
                _ => {
                    return Err(fail(
                        StoreErrorCode::Unreadable,
                        "original return mail is unreadable",
                    ));
                }
            };
            if self.scope.admission.actor != message.recipient
                || self.scope.admission.session.is_none()
            {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "only the original recipient agent can continue this conversation; use its current session and original received message ID",
                ));
            }
            crate::remote::admit_address(&self.db, &address)?;
            return Ok(Some(message.sender));
        }
        let attribution = self.read_remote_message_attribution(original.clone())?;
        let Some(attribution) = attribution else {
            return Ok(None);
        };
        let Some(source) = attribution.source.as_ref() else {
            return Ok(None);
        };
        if source.address().selector() != selector {
            return Ok(None);
        }
        let record = match self.message(original)? {
            Read::Present { value } => value,
            _ => {
                return Err(fail(
                    StoreErrorCode::Unreadable,
                    "the original remote message is unreadable",
                ));
            }
        };
        if self.scope.admission.actor != record.recipient || self.scope.admission.session.is_none()
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "only the original recipient agent can reply to this source; use its current session and the original message ID",
            ));
        }
        crate::remote::admit_source(&self.db, Some(source))?;
        Ok(Some(Actor::Remote(attribution.principal)))
    }
}
