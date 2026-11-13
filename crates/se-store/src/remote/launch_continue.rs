//! An admitted lifecycle can finish or close after future-launch consent changes.
use super::*;

pub(super) fn validate(c: &Connection, batch: &AtomicBatch) -> StoreResult<bool> {
    let (Actor::Remote(principal), Scope::Project(project)) =
        (&batch.admission.actor, &batch.admission.scope)
    else {
        return Ok(false);
    };
    if batch.admission.session.is_some() || batch.request.is_none() {
        return Err(denied());
    }
    // Other closed remote operations retain their own validators.
    if batch.events.iter().any(|e| {
        !matches!(
            e.body,
            EventBody::SessionActivated { .. }
                | EventBody::SessionEnded { .. }
                | EventBody::SessionRevoked { .. }
                | EventBody::ProcessTransition { .. }
                | EventBody::CredentialActivated { .. }
                | EventBody::CredentialRevoked { .. }
                | EventBody::CaptureSource { .. }
        )
    }) {
        return Ok(false);
    }
    for event in &batch.events {
        if event.header.door != Door::Host {
            return Err(denied());
        }
        let owned=match &event.body {
            EventBody::SessionActivated {session,process,incumbent,..}=> {
                incumbent.is_none() && session_owned(c,principal,project,session)? && match process {Some(id)=>session_process_owned(c,principal,project,session,id)?,None=>false}
            },
            EventBody::SessionEnded {session,..}|EventBody::SessionRevoked {session,..}|EventBody::CredentialActivated {session,..}|EventBody::CaptureSource {session,..}=>session_owned(c,principal,project,session)?,
            EventBody::ProcessTransition {process,identity,..}=> {
                if let (Some(session),Actor::Agent(agent))=(&identity.session,&identity.principal) {
                    identity.record==*process && session_process_owned(c,principal,project,session,process)? && agent_owned(c,principal,project,session,agent)?
                } else { false }
            },
            EventBody::CredentialRevoked {credential,..}=> {
                c.query_row("SELECT EXISTS(SELECT 1 FROM credentials k JOIN remote_launch_attribution a ON a.project_id=k.project_id AND a.session_id=k.session_id JOIN remote_grants g ON g.grant_id=a.grant_id WHERE k.credential_id=? AND g.principal_id=? AND a.project_id=?)",
                    rusqlite::params![credential.as_bytes().as_slice(),key(principal.as_str())?,crate::identity::key(c,"project",project.as_str(),&[0],false)?],|r|r.get(0)).map_err(sql)?
            },
            _=>false,
        };
        if !owned {
            return Err(denied());
        }
    }
    Ok(!batch.events.is_empty())
}

pub(super) fn session_owned(
    c: &Connection,
    principal: &se_types::RemotePrincipalId,
    project: &se_types::ProjectId,
    session: &se_types::SessionId,
) -> StoreResult<bool> {
    c.query_row("SELECT EXISTS(SELECT 1 FROM remote_launch_attribution a JOIN remote_grants g ON g.grant_id=a.grant_id WHERE g.principal_id=? AND a.project_id=? AND a.session_id=?)",
        rusqlite::params![key(principal.as_str())?,crate::identity::key(c,"project",project.as_str(),&[0],false)?,key(session.as_str())?],|r|r.get(0)).map_err(sql)
}
fn session_process_owned(
    c: &Connection,
    principal: &se_types::RemotePrincipalId,
    project: &se_types::ProjectId,
    session: &se_types::SessionId,
    lifecycle: &se_types::LifecycleId,
) -> StoreResult<bool> {
    c.query_row("SELECT EXISTS(SELECT 1 FROM remote_launch_attribution a JOIN remote_grants g ON g.grant_id=a.grant_id WHERE g.principal_id=? AND a.project_id=? AND a.session_id=? AND a.lifecycle_id=?)",
        rusqlite::params![key(principal.as_str())?,crate::identity::key(c,"project",project.as_str(),&[0],false)?,key(session.as_str())?,key(lifecycle.as_str())?],|r|r.get(0)).map_err(sql)
}
fn agent_owned(
    c: &Connection,
    principal: &se_types::RemotePrincipalId,
    project: &se_types::ProjectId,
    session: &se_types::SessionId,
    agent: &se_types::AgentId,
) -> StoreResult<bool> {
    let scope = crate::identity::scope_key(c, &Scope::Project(project.clone()), false)?;
    let a = crate::identity::key(c, "agent", agent.as_str(), &scope, false)?;
    c.query_row("SELECT EXISTS(SELECT 1 FROM remote_launch_attribution a JOIN remote_grants g ON g.grant_id=a.grant_id WHERE g.principal_id=? AND a.project_id=? AND a.session_id=? AND a.agent_id=?)",
        rusqlite::params![key(principal.as_str())?,crate::identity::key(c,"project",project.as_str(),&[0],false)?,key(session.as_str())?,a],|r|r.get(0)).map_err(sql)
}
