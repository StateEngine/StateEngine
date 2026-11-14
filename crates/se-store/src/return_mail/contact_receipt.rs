//! Recover a contact only from an actual retained remote-send operation.
use super::*;
use se_types::{Read, remote::*};

pub struct ContactReceiptQuery<'a> {
    pub grant: &'a RemoteGrantId,
    pub revision: Revision,
    pub original_grant: &'a RemoteGrantId,
    pub target: &'a RemoteTarget,
    pub source: &'a RemoteSourceSession,
    pub request_key: &'a se_types::IdempotencyKey,
    pub now: i64,
}

impl ReadPhase {
    pub fn remote_contact_receipt(
        &self,
        query: ContactReceiptQuery<'_>,
    ) -> StoreResult<Read<(se_types::MessageId, se_types::EventId)>> {
        ready(&self.info)?;
        let current = grant_at(&self.db, query.grant)?.ok_or_else(denied)?;
        let original = grant_at(&self.db, query.original_grant)?.ok_or_else(denied)?;
        if current.state != GrantState::Active
            || current.authority_revision != query.revision
            || current.expires_at_us <= query.now
            || !current.subject.admits_source(Some(query.source))
            || !original.subject.admits_source(Some(query.source))
            || !current.scope.allows(RemoteVerb::Send, query.target)
            || !original.scope.allows(RemoteVerb::Send, query.target)
            || original.store != self.info.id
            || original.host != current.host
        {
            return Err(denied());
        }
        super::admit_source(&self.db, Some(query.source))?;
        let scope = crate::identity::scope_key(
            &self.db,
            &Scope::Project(query.target.project.clone()),
            false,
        )?;
        let operation: Option<(Vec<u8>,bool)> = self.db.query_row(
            "SELECT operation_id,erased FROM operations WHERE scope_key=? AND actor_id=? AND request_key=?",
            rusqlite::params![scope,key(original.principal.as_str())?,query.request_key.as_str()],|r|Ok((r.get(0)?,r.get(1)?)),
        ).optional().map_err(sql)?;
        let Some((operation, erased)) = operation else {
            return Ok(Read::Absent {
                checked: "this exact source send has no committed operation on this pin".into(),
            });
        };
        if erased {
            return Err(fail(
                StoreErrorCode::Unreadable,
                "the original send receipt was erased; restore retained history before recovering this reply contact",
            ));
        }
        let receipt = crate::transaction::receipt(
            &self.db,
            &operation,
            &self.info,
            Some(query.request_key.clone()),
        )?;
        if receipt.events.len() != 2 {
            return Err(denied());
        }
        let first = crate::read::load_event(
            &self.db,
            i64::try_from(receipt.first.sequence()).map_err(invalid)?,
            &self.info,
        )?;
        let last = crate::read::load_event(
            &self.db,
            i64::try_from(receipt.last.sequence()).map_err(invalid)?,
            &self.info,
        )?;
        let (
            EventBody::MessageSent {
                message, recipient, ..
            },
            EventBody::RemoteMessageAttributed { record },
        ) = (&first.body, &last.body)
        else {
            return Err(denied());
        };
        if record.grant != *query.original_grant
            || record.target != *query.target
            || record.message != *message
            || record
                .attribution
                .source
                .as_ref()
                .map(RemoteSourceSession::address)
                != Some(query.source.address())
            || *recipient != Actor::Agent(query.target.agent.clone())
            || first.header.actor != Actor::Remote(original.principal)
            || first.header.scope != Scope::Project(query.target.project.clone())
            || first.header.session.is_some()
        {
            return Err(denied());
        }
        Ok(Read::Present {
            value: (message.clone(), first.header.event),
        })
    }
}
