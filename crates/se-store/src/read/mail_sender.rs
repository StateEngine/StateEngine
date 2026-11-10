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
