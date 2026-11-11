//! Every remote message rechecks its grant and exact target within BEGIN IMMEDIATE.
use super::*;
use se_types::remote::RemoteVerb;

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(crate) fn validate_batch(
    c: &Connection,
    batch: &AtomicBatch,
    info: &StoreInfo,
    now: i64,
) -> StoreResult<()> {
    let Actor::Remote(principal) = &batch.admission.actor else {
        if batch
            .events
            .iter()
            .any(|e| matches!(e.body, EventBody::RemoteMessageAttributed { .. }))
        {
            return Err(denied());
        }
        return Ok(());
    };
    ready(info)?;
    if batch.admission.session.is_some() || batch.request.is_none() {
        return Err(denied());
    }
    if batch.events.len() == 1 {
        if let EventBody::RemoteSecurity {
            transition:
                SecurityTransition::Renew {
                    grant,
                    authority_revision,
                    ..
                },
        } = &batch.events[0].body
        {
            let g = read::grant(c, grant)?.ok_or_else(denied)?;
            if &g.principal == principal
                && g.state == GrantState::Active
                && g.authority_revision == *authority_revision
                && g.expires_at_us > now
            {
                return Ok(());
            }
        }
        return Err(denied());
    }
    if batch.events.len() != 2 {
        return Err(denied());
    }
    let attr = batch
        .events
        .iter()
        .find_map(|e| match &e.body {
            EventBody::RemoteMessageAttributed { record } => Some(record),
            _ => None,
        })
        .ok_or_else(denied)?;
    let g = read::grant(c, &attr.grant)?.ok_or_else(denied)?;
    let stamp = &attr.attribution;
    if &attr.principal != principal
        || g.principal != *principal
        || g.store != info.id
        || g.state != GrantState::Active
        || g.expires_at_us <= now
        || g.authority_revision != attr.authority_revision
        || batch.admission.scope != Scope::Project(attr.target.project.clone())
        || !g.scope.verbs.contains(&RemoteVerb::Send)
        || !g.scope.allows(RemoteVerb::Send, &attr.target)
        || stamp.host != g.host
        || stamp.store != g.store
        || stamp.principal != g.principal
        || stamp.grant != g.grant
        || stamp.device != g.device
        || stamp.authority_revision != g.authority_revision.value.get()
        || !g.subject.admits_source(stamp.source.as_ref())
    {
        return Err(denied());
    }
    let message = batch
        .events
        .iter()
        .find_map(|e| match &e.body {
            EventBody::MessageSent {
                message,
                recipient,
                body,
                refs,
                reply_to,
                ..
            } => Some((message, recipient, body, refs, reply_to)),
            _ => None,
        })
        .ok_or_else(denied)?;
    if message.0 != &attr.message
        || message.1 != &Actor::Agent(attr.target.agent.clone())
        || !message.3.is_empty()
        || message.4.is_some()
    {
        return Err(denied());
    }
    match message.2 {
        InputText::Inline(body)
            if !body.is_empty() && body.len() <= se_types::MESSAGE_BODY_MAX_BYTES => {}
        _ => return Err(denied()),
    }
    let p = crate::identity::key(c, "project", attr.target.project.as_str(), &[0], false)?;
    let active: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects WHERE project_id=? AND state='active')",
            [&p],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !active {
        return Err(denied());
    }
    Ok(())
}
/// Only a new send requires the target session still to be active. A retained
/// keyed outcome remains resolvable after ordinary session completion, after
/// current grant, source, target, scope and intent checks have succeeded.
pub(crate) fn validate_new_batch(c: &Connection, batch: &AtomicBatch) -> StoreResult<()> {
    if !matches!(batch.admission.actor, Actor::Remote(_)) {
        return Ok(());
    }
    let Some(attr) = batch.events.iter().find_map(|e| match &e.body {
        EventBody::RemoteMessageAttributed { record } => Some(record),
        _ => None,
    }) else {
        return Ok(());
    };
    let p = crate::identity::key(c, "project", attr.target.project.as_str(), &[0], false)?;
    let mut namespace = vec![1];
    namespace.extend_from_slice(&p);
    let agent = crate::identity::key(c, "agent", attr.target.agent.as_str(), &namespace, false)?;
    let session = crate::identity::key(
        c,
        "session",
        attr.expected_session.as_str(),
        &namespace,
        false,
    )?;
    let active:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND agent_id=? AND session_id=? AND state='active')",rusqlite::params![p,agent,session],|r|r.get(0)).map_err(sql)?;
    if !active {
        return Err(denied());
    }
    Ok(())
}
