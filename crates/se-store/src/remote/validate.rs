//! Every remote message rechecks its grant and exact target within BEGIN IMMEDIATE.
use super::*;
use se_types::remote::RemoteVerb;

/// Produced only after this transaction validates a closed batch admitted by
/// launch consent: a native launch reservation, or a delegated worker's creation.
pub(crate) struct LaunchAuthority(Admitted);
enum Admitted {
    Launch,
    Delegate,
}
impl LaunchAuthority {
    /// A validated native launch reservation (session and process events).
    pub(crate) fn launches(&self) -> bool {
        matches!(self.0, Admitted::Launch)
    }
    /// A validated worker creation, whose creator is its anchor agent.
    pub(crate) fn delegates(&self) -> bool {
        matches!(self.0, Admitted::Delegate)
    }
}

pub(crate) fn validate_batch(
    c: &Connection,
    batch: &AtomicBatch,
    info: &StoreInfo,
    now: i64,
) -> StoreResult<Option<LaunchAuthority>> {
    if crate::return_mail::validate_returns(c, batch)? {
        return Ok(None);
    }
    if super::validate_launch(c, batch, info, now)? {
        return Ok(Some(LaunchAuthority(Admitted::Launch)));
    }
    if super::validate_delegate(c, batch, info, now)? {
        return Ok(Some(LaunchAuthority(Admitted::Delegate)));
    }
    let Actor::Remote(principal) = &batch.admission.actor else {
        if batch
            .events
            .iter()
            .any(|e| matches!(e.body, EventBody::RemoteMessageAttributed { .. }))
        {
            return Err(denied());
        }
        return Ok(None);
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
                return Ok(None);
            }
        }
        return Err(denied());
    }
    if batch.events.len() != 2 {
        return Err(denied());
    }
    let attr = attributed_record(batch)?;
    send_grant_matches(c, batch, attr, principal, info, now)?;
    let sent = sent_message(batch)?;
    pair_consistent(c, attr, &sent)?;
    Ok(None)
}

fn attributed_record(batch: &AtomicBatch) -> StoreResult<&MessageAttribution> {
    batch
        .events
        .iter()
        .find_map(|e| match &e.body {
            EventBody::RemoteMessageAttributed { record } => Some(record),
            _ => None,
        })
        .ok_or_else(denied)
}

fn send_grant_matches(
    c: &Connection,
    batch: &AtomicBatch,
    attr: &MessageAttribution,
    principal: &se_types::remote::RemotePrincipalId,
    info: &StoreInfo,
    now: i64,
) -> StoreResult<()> {
    let g = read::grant(c, &attr.grant)?.ok_or_else(denied)?;
    let stamp = &attr.attribution;
    super::admit_source(c, stamp.source.as_ref())?;
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
    Ok(())
}

struct SentMessage<'a> {
    message: &'a se_types::MessageId,
    recipient: &'a Actor,
    body: &'a InputText,
    refs: &'a Vec<se_types::EventId>,
    reply_to: &'a Option<se_types::MessageId>,
}

fn sent_message(batch: &AtomicBatch) -> StoreResult<SentMessage<'_>> {
    batch
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
            } => Some(SentMessage {
                message,
                recipient,
                body,
                refs,
                reply_to,
            }),
            _ => None,
        })
        .ok_or_else(denied)
}

fn pair_consistent(
    c: &Connection,
    attr: &MessageAttribution,
    sent: &SentMessage<'_>,
) -> StoreResult<()> {
    if sent.message != &attr.message
        || sent.recipient != &Actor::Agent(attr.target.agent.clone())
        || !sent.refs.is_empty()
    {
        return Err(denied());
    }
    match (&attr.expected_session, sent.reply_to) {
        (Some(_), None) => (),
        (None, Some(original)) => crate::return_mail::validate_incoming_reply(c, attr, original)?,
        _ => return Err(denied()),
    }
    match sent.body {
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
    let Some(expected_session) = &attr.expected_session else {
        return Ok(());
    };
    let p = crate::identity::key(c, "project", attr.target.project.as_str(), &[0], false)?;
    let mut namespace = vec![1];
    namespace.extend_from_slice(&p);
    let agent = crate::identity::key(c, "agent", attr.target.agent.as_str(), &namespace, false)?;
    let session = crate::identity::key(c, "session", expected_session.as_str(), &namespace, false)?;
    let active:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND agent_id=? AND session_id=? AND state='active')",rusqlite::params![p,agent,session],|r|r.get(0)).map_err(sql)?;
    if !active {
        return Err(denied());
    }
    Ok(())
}
