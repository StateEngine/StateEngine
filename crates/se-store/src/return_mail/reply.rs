//! Ordinary agent mail becomes a return only through an authenticated contact.
use super::*;
use se_types::remote::{RemoteAgentAddress, RemoteTarget};

pub(crate) struct ReplyRoute {
    address: RemoteAgentAddress,
    target: RemoteTarget,
    original: Vec<u8>,
    push: bool,
}

pub(crate) fn reply_route(
    c: &Connection,
    header: &EventHeader,
    recipient: &Actor,
    reply_to: Option<&se_types::MessageId>,
) -> StoreResult<Option<ReplyRoute>> {
    let Actor::Remote(principal) = recipient else {
        return Ok(None);
    };
    let (Scope::Project(project), Actor::Agent(agent), Some(_), Some(original)) =
        (&header.scope, &header.actor, &header.session, reply_to)
    else {
        return Err(reply_denied());
    };
    if crate::connection::info(c)?.schema_version < 12 || header.door == Door::Import {
        return Err(reply_denied());
    }
    let p = crate::identity::key(c, "project", project.as_str(), &[0], false)?;
    let scope = crate::identity::scope_key(c, &header.scope, false)?;
    let m = crate::identity::key(c, "message", original.as_str(), &scope, false)?;
    let returned: Option<String> = c
        .query_row(
            "SELECT facts FROM remote_return_attribution WHERE project_id=? AND message_id=?",
            rusqlite::params![p, m],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    if let Some(returned) = returned {
        let record: ReturnAttribution = decode(returned)?;
        if record.message != *original
            || record.principal != *principal
            || record.source.project != *project
            || record.source.agent != *agent
        {
            return Err(reply_denied());
        }
        super::admit_address(c, &record.sender)?;
        return Ok(Some(ReplyRoute {
            address: record.sender,
            target: RemoteTarget {
                project: project.clone(),
                agent: agent.clone(),
            },
            original: key(record.peer_message.as_str())?,
            push: true,
        }));
    }
    let facts: Option<String> = c
        .query_row(
            "SELECT facts FROM remote_message_attribution WHERE project_id=? AND message_id=?",
            rusqlite::params![p, m],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    let record: MessageAttribution = decode(facts.ok_or_else(reply_denied)?)?;
    if record.message != *original
        || record.principal != *principal
        || record.target.project != *project
        || record.target.agent != *agent
    {
        return Err(reply_denied());
    }
    let source = record
        .attribution
        .source
        .as_ref()
        .ok_or_else(reply_denied)?;
    super::admit_source(c, Some(source))?;
    Ok(Some(ReplyRoute {
        address: source.address(),
        target: record.target,
        original: m,
        push: false,
    }))
}

pub(crate) fn enqueue_reply(
    c: &Connection,
    route: Option<ReplyRoute>,
    project: &[u8],
    message: &[u8],
    seq: i64,
) -> StoreResult<()> {
    if let Some(route) = route {
        c.execute("INSERT INTO remote_reply_outbox(event_seq,project_id,message_id,source_address,sender_target,original_message_id,direction) VALUES(?,?,?,?,?,?,?)",
            rusqlite::params![seq,project,message,encode(&route.address)?,encode(&route.target)?,route.original,if route.push { "push" } else { "pull" }]).map_err(sql)?;
    }
    Ok(())
}

fn reply_denied() -> Box<StoreError> {
    fail(
        StoreErrorCode::ScopeMismatch,
        "remote replies require this recipient agent's authenticated original sender and message ID; the destination Owner can allow revoked sources with se remote permissions --local in a terminal on the destination",
    )
}

pub(crate) fn validate_incoming_reply(
    c: &Connection,
    record: &MessageAttribution,
    original: &se_types::MessageId,
) -> StoreResult<()> {
    let source = record
        .attribution
        .source
        .as_ref()
        .ok_or_else(reply_denied)?;
    let p = crate::identity::key(c, "project", record.target.project.as_str(), &[0], false)?;
    let scope =
        crate::identity::scope_key(c, &Scope::Project(record.target.project.clone()), false)?;
    let message = crate::identity::key(c, "message", original.as_str(), &scope, false)?;
    let known:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM remote_reply_outbox WHERE project_id=? AND message_id=? AND source_address=? AND sender_target=? AND direction='pull')",
        rusqlite::params![p,message,encode(&source.address())?,encode(&record.target)?],|r|r.get(0)).map_err(sql)?;
    if !known {
        return Err(reply_denied());
    }
    Ok(())
}
