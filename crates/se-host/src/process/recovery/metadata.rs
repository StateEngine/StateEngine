//! Resolve retained lifecycle and saved-session metadata in one finite read.
use super::*;
fn project_recovery_info<S: Snapshot>(
    project_id: se_types::ProjectId,
    read: &mut S,
) -> Result<(se_types::HumanId, String)> {
    let project = se_core::scope::require_present(
        read.project(project_id).map_err(store_error)?,
        "recovery project",
        "Keep the registered project metadata.",
    )?;
    let original = project.original.as_deref().unwrap_or(&project.current);
    let owner = match &original.body {
        EventBody::ProjectRegistered { owner, .. } => owner.clone(),
        _ => {
            return Err(error(
                "recovery project",
                "original registration unavailable",
            ));
        }
    };
    let project_name = match &project.current.body {
        EventBody::ProjectRegistered { name, .. } | EventBody::ProjectUpdated { name, .. } => {
            name.clone()
        }
        _ => return Err(error("recovery project", "project is no longer active")),
    };
    Ok((owner, project_name))
}

enum SessionLifecycleState {
    Prepared,
    Active,
    Ended,
    Revoked,
}

struct SessionRecovery {
    conversation: Read<se_types::ProviderSessionId>,
    capture: bool,
    provider: se_store::Provider,
    attended: bool,
    state: SessionLifecycleState,
}

fn session_recovery_info<S: Snapshot>(
    session: &se_types::SessionId,
    agent: &se_types::AgentId,
    read: &mut S,
) -> Result<SessionRecovery> {
    let session_head = se_core::scope::require_present(
        read.session(session.clone()).map_err(store_error)?,
        "recovery session",
        "Keep the original session preparation.",
    )?;
    let prepared = session_head
        .original
        .as_deref()
        .unwrap_or(&session_head.current);
    let (conversation, capture, provider, attended) = match &prepared.body {
        EventBody::SessionPrepared {
            session: found,
            agent: principal,
            consent,
            provider,
            surface,
            ..
        } if found == session && principal == agent => (
            se_core::ops::session_reference::read(read, &session_head)?,
            *consent == se_store::Consent::Capture,
            *provider,
            *surface == Some(se_store::SessionSurface::Window),
        ),
        _ => {
            return Err(error(
                "recovery session",
                "original provider preparation differs from retained identity",
            ));
        }
    };
    let state = match session_head.current.body {
        EventBody::SessionActivated { .. } => SessionLifecycleState::Active,
        EventBody::SessionEnded { .. } => SessionLifecycleState::Ended,
        EventBody::SessionRevoked { .. } => SessionLifecycleState::Revoked,
        _ => SessionLifecycleState::Prepared,
    };
    Ok(SessionRecovery {
        conversation,
        capture,
        provider,
        attended,
        state,
    })
}

impl LaunchCoordinator {
    pub(in crate::process) async fn recovery_metadata(
        &self,
        retained: &OwnerGuardProcess,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<(LifecycleMetadata, bool, bool, bool)> {
        let agent = match &retained.identity.principal {
            Actor::Agent(agent) => agent.clone(),
            _ => {
                return Err(error(
                    "managed recovery",
                    "record is not an agent lifecycle",
                ));
            }
        };
        let session = retained
            .identity
            .session
            .clone()
            .ok_or_else(|| error("managed recovery", "session identity absent"))?;
        let lifecycle = retained.identity.record.clone();
        let project_id = retained.project.clone();
        self.store
            .read(admission, deadline, move |cx| {
                let (owner, project_name) = project_recovery_info(project_id.clone(), cx.read)?;
                let control = se_core::scope::require_present(
                    cx.read.control_target(agent.clone()).map_err(store_error)?,
                    "recovery principal",
                    "Keep its exact control metadata.",
                )?;
                let name = match &control.principal.current.body {
                    EventBody::PrincipalRegistered { name, .. }
                    | EventBody::PrincipalRenamed { name, .. } => name.clone(),
                    _ => return Err(error("recovery principal", "current name unavailable")),
                };
                let registration = control
                    .principal
                    .original
                    .as_deref()
                    .unwrap_or(&control.principal.current);
                let ephemeral_one_shot = matches!(
                    registration.body,
                    EventBody::PrincipalRegistered {
                        ephemeral: Some(spec),
                        ..
                    } if spec.one_shot
                );
                let session_info = session_recovery_info(&session, &agent, cx.read)?;
                let model = match control.profile {
                    Read::Present { value } => match value.current.body {
                        EventBody::ProfileSaved { profile, .. } => profile.model,
                        _ => None,
                    },
                    _ => None,
                };
                // Recovery phase keys are bound to the original session rather
                // than inventing the disconnected caller's request identity.
                let request = format!("recovered-{session}").parse()?;
                let (active, retired, activated) = match session_info.state {
                    SessionLifecycleState::Active => (true, false, true),
                    SessionLifecycleState::Ended => (false, true, true),
                    SessionLifecycleState::Revoked => (false, true, false),
                    SessionLifecycleState::Prepared => (false, false, false),
                };
                Ok((
                    LifecycleMetadata {
                        project: se_types::Named {
                            id: project_id,
                            name: project_name,
                        },
                        agent: se_types::Named { id: agent, name },
                        owner,
                        session,
                        lifecycle,
                        request,
                        conversation: session_info.conversation,
                        model,
                        capture: session_info.capture,
                        provider: session_info.provider,
                        attended: session_info.attended,
                        ephemeral_one_shot,
                    },
                    active,
                    retired,
                    activated,
                ))
            })
            .await
    }
}
