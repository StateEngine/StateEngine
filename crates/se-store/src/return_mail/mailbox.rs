//! Native source-side contact and received-mail projections share the writer.
use super::*;
use se_types::remote::{RemoteAgentAddress, RemoteHostId, RemoteTarget};

pub(super) fn contact(
    c: &Connection,
    source: &RemoteAgentAddress,
    peer: RemoteHostId,
    target: &RemoteTarget,
    original: &se_types::MessageId,
) -> StoreResult<Option<MailContact>> {
    let facts: Option<String> = c.query_row(
        "SELECT facts FROM remote_mail_contacts WHERE source_address=? AND peer_host=? AND target=? AND original_message_id=?",
        rusqlite::params![encode(source)?,encode(&peer)?,encode(target)?,key(original.as_str())?],
        |r| r.get(0),
    ).optional().map_err(sql)?;
    facts.map(decode).transpose()
}

pub(crate) fn apply_mailbox(
    c: &Connection,
    h: &EventHeader,
    change: MailboxChange,
    seq: i64,
) -> StoreResult<()> {
    if crate::connection::info(c)?.schema_version < 12 || h.door != Door::Host {
        return Err(denied());
    }
    match change {
        MailboxChange::Pending { record } => {
            if h.scope != Scope::Project(record.source.project.clone())
                || h.actor != Actor::Agent(record.source.agent.clone())
                || h.session.is_none()
                || record.alias.is_empty()
                || record.alias.len() > 64
                || record.alias.chars().any(char::is_control)
            {
                return Err(denied());
            }
            c.execute("INSERT INTO remote_contact_pending(source_address,peer_host,target,request_key,original_grant,facts,event_seq) VALUES(?,?,?,?,?,?,?)",
                rusqlite::params![encode(&record.source)?,encode(&record.peer)?,encode(&record.target)?,record.request_key.as_str(),key(record.original_grant.as_str())?,encode(&record)?,seq]).map_err(sql)?;
            c.execute("INSERT OR IGNORE INTO remote_mail_catalog(source_address,peer_host,target,first_seq) VALUES(?,?,?,?)",
                rusqlite::params![encode(&record.source)?,encode(&record.peer)?,encode(&record.target)?,seq]).map_err(sql)?;
        }
        MailboxChange::Contact { record } => apply_contact(c, h, record, seq)?,

        MailboxChange::Received { record } => {
            super::admit_address(c, &record.sender)?;
            let target = RemoteTarget {
                project: record.sender.project.clone(),
                agent: record.sender.agent.clone(),
            };
            let contact = contact(
                c,
                &record.source,
                record.sender.host,
                &target,
                &record.original,
            )?
            .ok_or_else(denied)?;
            if h.scope != Scope::Project(record.source.project.clone())
                || h.actor != Actor::Remote(record.principal.clone())
                || h.session.is_some()
                || contact.principal != record.principal
            {
                return Err(denied());
            }
            let scope = crate::identity::scope_key(c, &h.scope, false)?;
            let p = crate::connection::project_id(c, &h.scope, false)?;
            let message =
                crate::identity::key(c, "message", record.message.as_str(), &scope, false)?;
            c.execute("INSERT INTO remote_return_attribution(project_id,message_id,peer_host,peer_message_id,source_address,facts,event_seq) VALUES(?,?,?,?,?,?,?)",
                rusqlite::params![p,message,encode(&record.sender.host)?,key(record.peer_message.as_str())?,encode(&record.source)?,encode(&record)?,seq]).map_err(sql)?;
            c.execute(
                "INSERT OR IGNORE INTO remote_source_contacts(address,first_seq) VALUES(?,?)",
                rusqlite::params![encode(&record.sender)?, seq],
            )
            .map_err(sql)?;
        }
        MailboxChange::Checkpoint {
            source,
            peer,
            target,
            grant,
            cursor,
        } => {
            let known: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM remote_mail_contacts WHERE source_address=? AND peer_host=? AND target=? AND principal_id=?)",
                rusqlite::params![encode(&source)?,encode(&peer)?,encode(&target)?,key(h.actor.wire())?],|r|r.get(0)).map_err(sql)?;
            if !known
                || !matches!(h.actor, Actor::Remote(_))
                || h.scope != Scope::Project(source.project.clone())
                || h.session.is_some()
            {
                return Err(denied());
            }
            c.execute("INSERT INTO remote_return_cursors(source_address,peer_host,target,grant_id,cursor,event_seq) VALUES(?,?,?,?,?,?) ON CONFLICT(source_address,peer_host,target,grant_id) DO UPDATE SET cursor=excluded.cursor,event_seq=excluded.event_seq",
                rusqlite::params![encode(&source)?,encode(&peer)?,encode(&target)?,key(grant.as_str())?,cursor.as_str(),seq]).map_err(sql)?;
        }
    }
    Ok(())
}

impl ReadPhase {
    pub fn remote_mail_alias(
        &self,
        source: &RemoteAgentAddress,
        peer: RemoteHostId,
        target: &RemoteTarget,
    ) -> StoreResult<Option<String>> {
        self.db.query_row("SELECT json_extract(facts,'$.alias') FROM (SELECT facts,event_seq FROM remote_mail_routes WHERE source_address=?1 AND peer_host=?2 AND target=?3 UNION ALL SELECT facts,event_seq FROM remote_contact_pending WHERE source_address=?1 AND peer_host=?2 AND target=?3) ORDER BY event_seq DESC LIMIT 1",
            rusqlite::params![encode(source)?,encode(&peer)?,encode(target)?],|r|r.get(0)).optional().map_err(sql)
    }
    pub fn has_remote_mail_contacts(&self) -> StoreResult<bool> {
        if self.info.schema_version < 12 {
            return Ok(false);
        }
        self.db
            .query_row(
            "SELECT EXISTS(SELECT 1 FROM remote_mail_contacts) OR EXISTS(SELECT 1 FROM remote_contact_pending)",
                [],
                |r| r.get(0),
            )
            .map_err(sql)
    }

    pub fn remote_mail_contact(
        &self,
        source: &RemoteAgentAddress,
        peer: RemoteHostId,
        target: &RemoteTarget,
        original: &se_types::MessageId,
    ) -> StoreResult<Option<MailContact>> {
        ready(&self.info)?;
        contact(&self.db, source, peer, target, original)
    }

    pub fn remote_return_seen(
        &self,
        source: &RemoteAgentAddress,
        peer: RemoteHostId,
        message: &se_types::MessageId,
    ) -> StoreResult<bool> {
        self.db.query_row("SELECT EXISTS(SELECT 1 FROM remote_return_attribution WHERE source_address=? AND peer_host=? AND peer_message_id=?)",
            rusqlite::params![encode(source)?,encode(&peer)?,key(message.as_str())?],|r|r.get(0)).map_err(sql)
    }

    pub fn remote_return_cursor(
        &self,
        source: &RemoteAgentAddress,
        peer: RemoteHostId,
        target: &RemoteTarget,
        grant: &se_types::RemoteGrantId,
    ) -> StoreResult<Option<se_types::Cursor>> {
        let text: Option<String> = self.db.query_row("SELECT cursor FROM remote_return_cursors WHERE source_address=? AND peer_host=? AND target=? AND grant_id=?",
            rusqlite::params![encode(source)?,encode(&peer)?,encode(target)?,key(grant.as_str())?],|r|r.get(0)).optional().map_err(sql)?;
        text.map(|text| se_types::Cursor::new(text).map_err(invalid))
            .transpose()
    }
}

fn apply_contact(
    c: &Connection,
    h: &EventHeader,
    record: MailContact,
    seq: i64,
) -> StoreResult<()> {
    let pending: bool=c.query_row("SELECT EXISTS(SELECT 1 FROM remote_contact_pending WHERE source_address=? AND peer_host=? AND target=? AND request_key=? AND original_grant=?)",
                rusqlite::params![encode(&record.source)?,encode(&record.peer)?,encode(&record.target)?,record.request_key.as_str(),key(record.original_grant.as_str())?],|r|r.get(0)).map_err(sql)?;
    if !pending {
        return Err(denied());
    }
    if h.scope != Scope::Project(record.source.project.clone())
        || h.actor != Actor::Agent(record.source.agent.clone())
        || h.session.is_none()
        || record.alias.is_empty()
        || record.alias.len() > 64
        || record.alias.chars().any(char::is_control)
    {
        return Err(denied());
    }
    let old: Option<Vec<u8>> = c.query_row(
                "SELECT principal_id FROM remote_mail_routes WHERE source_address=? AND peer_host=? AND target=?",
                rusqlite::params![encode(&record.source)?,encode(&record.peer)?,encode(&record.target)?], |r|r.get(0),
            ).optional().map_err(sql)?;
    let principal = key(record.principal.as_str())?;
    if old.is_some_and(|id| id != principal) {
        return Err(invalid(
            "contact principal changed; reread the original contact route",
        ));
    }
    c.execute("INSERT INTO remote_mail_contacts(source_address,peer_host,target,original_message_id,principal_id,facts,event_seq) VALUES(?,?,?,?,?,?,?) ON CONFLICT(source_address,peer_host,target,original_message_id) DO UPDATE SET facts=excluded.facts,event_seq=excluded.event_seq",
                rusqlite::params![encode(&record.source)?,encode(&record.peer)?,encode(&record.target)?,key(record.original.as_str())?,principal,encode(&record)?,seq]).map_err(sql)?;
    c.execute("INSERT INTO remote_mail_routes(source_address,peer_host,target,principal_id,facts,event_seq) VALUES(?,?,?,?,?,?) ON CONFLICT(source_address,peer_host,target) DO UPDATE SET facts=excluded.facts,event_seq=excluded.event_seq",
                rusqlite::params![encode(&record.source)?,encode(&record.peer)?,encode(&record.target)?,principal,encode(&record)?,seq]).map_err(sql)?;
    c.execute("DELETE FROM remote_contact_pending WHERE source_address=? AND peer_host=? AND target=? AND request_key=? AND original_grant=?",
                rusqlite::params![encode(&record.source)?,encode(&record.peer)?,encode(&record.target)?,record.request_key.as_str(),key(record.original_grant.as_str())?]).map_err(sql)?;
    super::push::delivered(c, &record, seq)?;

    Ok(())
}
