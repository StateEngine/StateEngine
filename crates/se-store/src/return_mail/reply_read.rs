//! One source address and exact destination contact per finite return page.
use super::*;
use se_types::remote::{RemoteReplyMessage, RemoteSourceSession, RemoteVerb};

pub struct ReplyPage {
    pub messages: Vec<(RemoteReplyMessage, StorePosition)>,
    pub more: bool,
}

pub struct ReplyQuery<'a> {
    pub grant_id: &'a se_types::RemoteGrantId,
    pub revision: Revision,
    pub source: &'a RemoteSourceSession,
    pub target: &'a se_types::remote::RemoteTarget,
    pub after: Option<&'a StorePosition>,
    pub limit: u16,
    pub now: i64,
}
impl ReadPhase {
    pub fn remote_replies(&self, query: ReplyQuery<'_>) -> StoreResult<ReplyPage> {
        let ReplyQuery {
            grant_id,
            revision,
            source,
            target,
            after,
            limit,
            now,
        } = query;
        ready(&self.info)?;
        if self.info.schema_version < 12
            || !(1..=20).contains(&limit)
            || after.is_some_and(|p| !p.belongs(&self.info))
        {
            return Err(invalid(
                "return-mail schema, page bound or cursor binding differs",
            ));
        }
        let grant = grant_at(&self.db, grant_id)?.ok_or_else(denied)?;
        if grant.state != GrantState::Active
            || grant.authority_revision != revision
            || grant.expires_at_us <= now
            || !grant.subject.admits_source(Some(source))
            || !grant.scope.allows(RemoteVerb::Send, target)
        {
            return Err(denied());
        }
        super::admit_source(&self.db, Some(source))?;
        let mut q = self.db.prepare("SELECT event_seq,original_message_id FROM remote_reply_outbox WHERE source_address=? AND sender_target=? AND direction='pull' AND event_seq>? ORDER BY event_seq LIMIT ?").map_err(sql)?;
        let rows = q
            .query_map(
                rusqlite::params![
                    encode(&source.address())?,
                    encode(target)?,
                    i64::try_from(after.map_or(0, StorePosition::sequence)).map_err(invalid)?,
                    i64::from(limit) + 1
                ],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        let more = rows.len() > usize::from(limit);
        let mut messages = Vec::new();
        for (seq, original) in rows.into_iter().take(usize::from(limit)) {
            let event = crate::read::load_event(&self.db, seq, &self.info)?;
            let EventBody::MessageSent {
                message,
                body: StoredText::Present(body),
                kind,
                quiet,
                ..
            } = event.body
            else {
                return Err(fail(
                    StoreErrorCode::Unreadable,
                    "a queued remote reply body is erased or unreadable; restore retained mail before advancing its cursor",
                ));
            };
            if event.header.scope != Scope::Project(target.project.clone())
                || event.header.actor != Actor::Agent(target.agent.clone())
            {
                return Err(invalid(
                    "queued reply differs from its authenticated recipient",
                ));
            }
            messages.push((
                RemoteReplyMessage {
                    message,
                    original: se_types::MessageId::from_bytes(
                        original
                            .try_into()
                            .map_err(|_| invalid("original remote message UUID"))?,
                    )
                    .map_err(invalid)?,
                    sender: se_types::remote::RemoteAgentAddress {
                        host: grant.host,
                        project: target.project.clone(),
                        agent: target.agent.clone(),
                    },
                    body: body.try_into().map_err(invalid)?,
                    kind,
                    quiet,
                    occurred_at_us: event.header.occurred_at_us,
                },
                StorePosition::new_internal(
                    self.info.id.clone(),
                    self.info.incarnation,
                    u64::try_from(seq).map_err(invalid)?,
                )?,
            ));
        }
        Ok(ReplyPage { messages, more })
    }
}
