//! Resolve retained lifecycle and saved-session metadata in one finite read.
use super::*;
impl LaunchCoordinator {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
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
                let project = se_core::scope::require_present(
                    cx.read
                        .project(project_id.clone())
                        .map_err(|e| se_core::store_error::store_error(&e))?,
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
                    EventBody::ProjectRegistered { name, .. }
                    | EventBody::ProjectUpdated { name, .. } => name.clone(),
                    _ => return Err(error("recovery project", "project is no longer active")),
                };
                let control = se_core::scope::require_present(
                    cx.read
                        .control_target(agent.clone())
                        .map_err(|e| se_core::store_error::store_error(&e))?,
                    "recovery principal",
                    "Keep its exact control metadata.",
                )?;
                let name = match &control.principal.current.body {
                    EventBody::PrincipalRegistered { name, .. }
                    | EventBody::PrincipalRenamed { name, .. } => name.clone(),
                    _ => return Err(error("recovery principal", "current name unavailable")),
                };
                let session_head = se_core::scope::require_present(
                    cx.read
                        .session(session.clone())
                        .map_err(|e| se_core::store_error::store_error(&e))?,
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
                    } if found == &session && principal == &agent => (
                        se_core::ops::session_reference::read(cx.read, &session_head)?,
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
                let active = matches!(
                    session_head.current.body,
                    EventBody::SessionActivated { .. }
                );
                let activated =
                    active || matches!(session_head.current.body, EventBody::SessionEnded { .. });
                let retired = matches!(
                    session_head.current.body,
                    EventBody::SessionEnded { .. } | EventBody::SessionRevoked { .. }
                );
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
                        conversation,
                        model,
                        capture,
                        provider,
                        attended,
                    },
                    active,
                    retired,
                    activated,
                ))
            })
            .await
    }
}
