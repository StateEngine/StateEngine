//! Strict caller authorization for `IpcRequest::Subscribe`.
//! Owner sees scoped project(s); `Session` and `ExternalSession` callers are
//! pinned to their exact authenticated `(project_id, agent_id, session_id)` and
//! can never widen scope across projects or agents.
use super::{EventStreamKind, SubscribeRequest};
use crate::{
    PeerProof, PresentedAuthority,
    external::EXTERNAL_SESSION_CAPABILITY,
    runtime::admission::{AdmissionContext, ConnectionGrant, SESSION_CAPABILITY},
};
use se_core::store_error::store_error;
use se_store::{Actor, Scope};
use se_types::{AgentId, HumanId, ProjectId, Result, SeError, Secret, SessionId};
use std::sync::Arc;

/// Authenticated, scope-pinned subscription ready for `events::stream::serve`.
pub(crate) struct AdmittedSubscribe {
    pub(crate) principal: SubscribePrincipal,
    pub(crate) project_filter: Option<ProjectId>,
    pub(crate) agent_filter: Option<AgentId>,
    pub(crate) after_cursor: Option<String>,
    pub(crate) filter: Option<Vec<EventStreamKind>>,
    pub(crate) max_batch_bytes: u32,
}

pub(crate) enum SubscribePrincipal {
    Owner {
        human: HumanId,
    },
    Session {
        secret: Arc<Secret>,
        purpose: &'static str,
        project: ProjectId,
        agent: AgentId,
        session: SessionId,
        credential: se_store::RecordId,
    },
}

pub(crate) struct SubscribeIngress<'a> {
    pub(crate) peer: &'a PeerProof,
    pub(crate) connection: &'a PresentedAuthority,
    pub(crate) override_authority: Option<&'a PresentedAuthority>,
    pub(crate) grant: &'a ConnectionGrant,
    pub(crate) presence: Option<&'a crate::client::presence::OwnerPresence>,
    pub(crate) negotiated_max_bytes: u32,
}

pub(crate) fn admit_subscribe(
    context: &AdmissionContext,
    ingress: SubscribeIngress<'_>,
    request: SubscribeRequest,
) -> Result<AdmittedSubscribe> {
    let SubscribeIngress {
        peer,
        connection,
        override_authority,
        grant,
        presence,
        negotiated_max_bytes,
    } = ingress;
    request.validate()?;
    if matches!(
        connection,
        PresentedAuthority::ExternalSession(_) | PresentedAuthority::ExternalClaim(_)
    ) && override_authority.is_some()
    {
        return Err(SeError::invalid(
            "external seat connection",
            "one immutable seat per connection without in-band identity switching",
        ));
    }
    let max_batch_bytes = request
        .max_batch_bytes
        .map_or(negotiated_max_bytes, |req| req.min(negotiated_max_bytes));
    if max_batch_bytes < super::MIN_BATCH_BYTES {
        return Err(SeError::invalid(
            "events.subscribe max_batch_bytes",
            &format!(
                "an effective byte limit of at least {} (negotiated {})",
                super::MIN_BATCH_BYTES,
                negotiated_max_bytes
            ),
        ));
    }
    let filter = request.filter.map(|mut kinds| {
        kinds.sort();
        kinds.dedup();
        kinds
    });
    let mut phase = context.reads.read_phase().map_err(|e| store_error(&e))?;
    let res = (|| {
        context.check_generation(&phase)?;
        let effective = override_authority.unwrap_or(connection);
        match effective {
            PresentedAuthority::OwnerProof { .. } => {
                let (admission, _) = context.caller(
                    &mut phase,
                    peer,
                    connection,
                    override_authority,
                    grant,
                    presence,
                )?;
                let Actor::Human(human) = admission.actor else {
                    return Err(SeError::invalid(
                        "events.subscribe",
                        "an authenticated Owner or active session credential",
                    ));
                };
                Ok(AdmittedSubscribe {
                    principal: SubscribePrincipal::Owner { human },
                    project_filter: request.project_id,
                    agent_filter: request.agent_id,
                    after_cursor: request.after_cursor,
                    filter,
                    max_batch_bytes,
                })
            }
            PresentedAuthority::Session(secret) => admit_session_subscribe(
                context,
                &phase,
                secret,
                SESSION_CAPABILITY,
                request.project_id,
                request.agent_id,
                request.after_cursor,
                filter,
                max_batch_bytes,
            ),
            PresentedAuthority::ExternalSession(secret) => admit_session_subscribe(
                context,
                &phase,
                secret,
                EXTERNAL_SESSION_CAPABILITY,
                request.project_id,
                request.agent_id,
                request.after_cursor,
                filter,
                max_batch_bytes,
            ),
            _ => Err(SeError::invalid(
                "events.subscribe authority",
                "an authenticated Owner, managed session, or approved external seat capability",
            )),
        }
    })();
    crate::runtime::executor::close_read(res, phase.close())
}

#[allow(clippy::too_many_arguments)]
fn admit_session_subscribe(
    context: &AdmissionContext,
    phase: &se_store::ReadPhase,
    secret: &Secret,
    purpose: &'static str,
    requested_project: Option<ProjectId>,
    requested_agent: Option<AgentId>,
    after_cursor: Option<String>,
    filter: Option<Vec<EventStreamKind>>,
    max_batch_bytes: u32,
) -> Result<AdmittedSubscribe> {
    let secret = Arc::new(Secret::new(secret.expose().to_vec())?);
    let admission = if purpose == EXTERNAL_SESSION_CAPABILITY {
        context.external_session(phase, &secret)?
    } else {
        context.verify_session(phase, &secret)?
    };
    let Scope::Project(bound_project) = admission.scope else {
        return Err(SeError::invalid(
            "events.subscribe scope",
            "a project-scoped active session",
        ));
    };
    let Actor::Agent(bound_agent) = admission.actor else {
        return Err(SeError::invalid(
            "events.subscribe principal",
            "an authenticated agent session",
        ));
    };
    let session = admission.session.ok_or_else(|| {
        SeError::invalid("events.subscribe session", "an active session identifier")
    })?;
    if let Some(req_project) = requested_project
        && req_project != bound_project
    {
        return Err(SeError::invalid(
            "project_id",
            "the authenticated session's bound project",
        ));
    }
    if let Some(req_agent) = requested_agent
        && req_agent != bound_agent
    {
        return Err(SeError::invalid(
            "agent_id",
            "the authenticated session's bound agent",
        ));
    }
    let credential = context.credential_record_id(phase, &secret)?;
    Ok(AdmittedSubscribe {
        principal: SubscribePrincipal::Session {
            secret,
            purpose,
            project: bound_project.clone(),
            agent: bound_agent.clone(),
            session,
            credential,
        },
        project_filter: Some(bound_project),
        agent_filter: Some(bound_agent),
        after_cursor,
        filter,
        max_batch_bytes,
    })
}
