//! Outgoing replies reuse the saved source connection and their native mail IDs.
use super::*;
use se_types::remote::{RemoteAgentAddress, RemoteTarget};

pub struct OutgoingReply {
    pub message: se_types::MessageId,
    pub original: se_types::MessageId,
    pub body: se_types::Body,
    pub kind: String,
    pub quiet: bool,
}
impl ReadPhase {
    pub fn remote_outgoing_replies(
        &self,
        source: &RemoteAgentAddress,
        peer: &RemoteAgentAddress,
        limit: u16,
    ) -> StoreResult<Vec<OutgoingReply>> {
        ready(&self.info)?;
        if self.info.schema_version < 12 || !(1..=20).contains(&limit) {
            return Err(invalid("outgoing remote reply schema or page limit"));
        }
        super::admit_address(&self.db, peer)?;
        let sender = RemoteTarget {
            project: source.project.clone(),
            agent: source.agent.clone(),
        };
        let mut q=self.db.prepare("SELECT o.event_seq,o.original_message_id FROM remote_reply_outbox o WHERE source_address=? AND sender_target=? AND direction='push' AND NOT EXISTS(SELECT 1 FROM remote_reply_push_delivery d WHERE d.event_seq=o.event_seq) ORDER BY o.event_seq LIMIT ?").map_err(sql)?;
        let rows = q
            .query_map(
                rusqlite::params![encode(peer)?, encode(&sender)?, i64::from(limit)],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        rows.into_iter().map(|(seq,original)| {
            let event=crate::read::load_event(&self.db,seq,&self.info)?;
            if event.header.scope != Scope::Project(source.project.clone()) || event.header.actor != Actor::Agent(source.agent.clone()) { return Err(denied()); }
            let EventBody::MessageSent { message,body:StoredText::Present(body),kind,quiet,.. }=event.body else {
                return Err(fail(StoreErrorCode::Unreadable,"an outgoing remote reply body is erased or unreadable; its delivery remains unresolved"));
            };
            Ok(OutgoingReply { message,original:se_types::MessageId::from_bytes(original.try_into().map_err(|_|invalid("outgoing remote reply UUID"))?).map_err(invalid)?,body:body.try_into().map_err(invalid)?,kind,quiet })
        }).collect()
    }
}

pub(super) fn delivered(c: &Connection, record: &MailContact, seq: i64) -> StoreResult<()> {
    let Some(local) = &record.local_reply else {
        return Ok(());
    };
    if record.request_key.as_str() != format!("remote-reply-{local}") {
        return Err(denied());
    }
    let peer = RemoteAgentAddress {
        host: record.peer,
        project: record.target.project.clone(),
        agent: record.target.agent.clone(),
    };
    let sender = RemoteTarget {
        project: record.source.project.clone(),
        agent: record.source.agent.clone(),
    };
    let project = crate::identity::key(c, "project", record.source.project.as_str(), &[0], false)?;
    let event:Option<i64>=c.query_row("SELECT event_seq FROM remote_reply_outbox WHERE project_id=? AND message_id=? AND source_address=? AND sender_target=? AND direction='push'",
        rusqlite::params![project,key(local.as_str())?,encode(&peer)?,encode(&sender)?],|r|r.get(0)).optional().map_err(sql)?;
    c.execute("INSERT INTO remote_reply_push_delivery(event_seq,peer_message_id,record_seq) VALUES(?,?,?) ON CONFLICT(event_seq) DO NOTHING",
        rusqlite::params![event.ok_or_else(denied)?,key(record.original.as_str())?,seq]).map_err(sql)?;
    // Any older machine-grant attempt for this same immutable source mail now
    // has a witnessed completion. Stable destination event IDs fence late writes.
    c.execute("DELETE FROM remote_contact_pending WHERE source_address=? AND peer_host=? AND target=? AND json_extract(facts,'$.local_reply')=?",
        rusqlite::params![encode(&record.source)?,encode(&record.peer)?,encode(&record.target)?,local.as_str()]).map_err(sql)?;
    Ok(())
}
