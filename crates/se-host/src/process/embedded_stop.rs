//! Retiring an external service binding never claims native execution stopped.
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::{agent_launch::TakeoverReport, process_commit};
use se_store::{Admission, ControlTarget, EventBody, Snapshot};
use se_types::{EventId, IdempotencyKey, Read, SessionId};

pub(super) struct EmbeddedRetirement {
    pub session: SessionId,
    pub event: EventId,
    pub service: String,
    pub changed: bool,
}
impl EmbeddedRetirement {
    pub fn report(&self) -> TakeoverReport {
        TakeoverReport {
            previous_session: self.session.clone(),
            previous_sessions: Vec::new(),
            new_conversation: true,
            scope: "engine binding only; external service execution was not stopped".into(),
            inventory_failure: Some(format!(
                "Jobs in {} were not inventoried or stopped",
                self.service
            )),
            external_services: vec![self.service.clone()],
            jobs_stopped: Vec::new(),
            jobs_remaining: Vec::new(),
            jobs_unproved: Vec::new(),
            witness:
                "engine binding retirement read back; no native service or job stop was attempted"
                    .into(),
        }
    }
}
impl LaunchCoordinator {
    pub(super) async fn retire_embedded_bindings(
        &self,
        control: &ControlTarget,
        agent: &se_types::AgentId,
        key: &IdempotencyKey,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<Vec<EmbeddedRetirement>> {
        let mut selected = control.sessions.iter().collect::<Vec<_>>();
        if selected.is_empty()
            && control.processes.is_empty()
            && let Read::Present { value } = &control.latest_session
        {
            selected.push(value);
        }
        let mut retired = Vec::new();
        for original in selected {
            let Some((session, conversation)) = process_commit::embedded_session(original) else {
                continue;
            };
            let session = session.clone();
            let observed_provider = matches!(
                original
                    .original
                    .as_deref()
                    .unwrap_or(&original.current)
                    .body,
                EventBody::SessionPrepared {
                    surface: Some(se_store::SessionSurface::Observed),
                    ..
                }
            );
            let _serial = if observed_provider {
                Some(self.capture.lock_observed(&session, deadline).await?)
            } else {
                None
            };
            let service = match original
                .original
                .as_deref()
                .unwrap_or(&original.current)
                .body
            {
                EventBody::SessionPrepared {
                    surface: Some(se_store::SessionSurface::Observed),
                    ..
                } => format!(
                    "the user-owned provider for conversation {}",
                    conversation.escape_debug()
                ),
                _ => format!(
                    "the externally owned SE Code service for conversation {}",
                    conversation.escape_debug()
                ),
            };
            let reason = format!("Engine binding retired; jobs in {service} were not stopped.");
            let observed = self.embedded_binding(&session, admission, deadline).await?;
            let changed = matches!(
                observed.current.body,
                EventBody::SessionPrepared { .. } | EventBody::SessionActivated { .. }
            );
            if changed {
                if observed.revision != original.revision {
                    return Err(error(
                        "embedded stop selection",
                        "the selected binding revision changed; no newer binding was retired",
                    ));
                }
                if observed_provider {
                    self.catch_up_observed_binding(agent, &session, admission, deadline)
                        .await?;
                }
                let agent = agent.clone();
                let phase =
                    process_commit::phase_key(key, &format!("embedded-retirement/{session}"))?;
                self.store
                    .commit(admission.clone(), deadline, None, move |kernel, cx| {
                        process_commit::retire_embedded(kernel, agent, observed, phase, reason, cx)
                    })
                    .await?;
            }
            let observed = self.embedded_binding(&session, admission, deadline).await?;
            if process_commit::embedded_session(&observed).is_none()
                || !matches!(
                    observed.current.body,
                    EventBody::SessionRevoked { .. } | EventBody::SessionEnded { .. }
                )
            {
                return Err(error(
                    "embedded stop readback",
                    "the original binding is not terminal",
                ));
            }
            retired.push(EmbeddedRetirement {
                session,
                service,
                changed,
                event: observed.current.header.event,
            });
        }
        Ok(retired)
    }
    async fn embedded_binding(
        &self,
        session: &SessionId,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<se_store::ProjectionRecord> {
        let session = session.clone();
        self.store
            .read(admission.clone(), deadline, move |cx| {
                se_core::scope::require_present(
                    cx.read
                        .session(session)
                        .map_err(|e| se_core::store_error::store_error(&e))?,
                    "embedded stop binding",
                    "Restore the exact original binding before retrying.",
                )
            })
            .await
    }
}

impl LaunchCoordinator {
    pub(super) async fn shutdown_observed(&self, deadline: &Deadline) -> Result<Vec<String>> {
        let mut pending = Vec::new();
        for identity in self.capture.identities()? {
            let owner = se_store::Admission {
                actor: se_store::Actor::Human(self.human.clone()),
                scope: se_store::Scope::Project(identity.project.clone()),
                session: None,
                generation: self.store.generation.get(),
            };
            let agent = identity.agent.clone();
            let selected = identity.session.clone();
            let control = self.store.read(owner.clone(), deadline, move |cx| {
                let target = se_core::scope::require_present(cx.read.control_target(agent).map_err(|e| se_core::store_error::store_error(&e))?, "observed shutdown binding", "Restore the original saved binding.")?;
                let observed = target.sessions.iter().any(|row| matches!(&row.original.as_deref().unwrap_or(&row.current).body, EventBody::SessionPrepared { session, surface: Some(se_store::SessionSurface::Observed), .. } if session == &selected));
                Ok(observed.then_some(target))
            }).await?;
            if let Some(control) = control {
                let key: IdempotencyKey = format!(
                    "observed-shutdown-{}-{}",
                    self.store.generation.get(),
                    identity.session
                )
                .parse()?;
                if let Err(error) = self
                    .retire_embedded_bindings(&control, &identity.agent, &key, &owner, deadline)
                    .await
                {
                    pending.push(format!(
                        "Observed session {} retirement is unconfirmed: {error}",
                        identity.session
                    ));
                } else {
                    self.capture.retire(identity, false, deadline).await?;
                }
            }
        }
        Ok(pending)
    }
}

impl LaunchCoordinator {
    async fn catch_up_observed_binding(
        &self,
        agent: &se_types::AgentId,
        session: &SessionId,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<()> {
        let project = se_core::scope::project(admission)?;
        let identity = crate::SessionIdentity {
            project: project.clone(),
            agent: agent.clone(),
            session: session.clone(),
        };
        let pin = se_core::scope::require_present(
            self.capture.recover_binding(identity, deadline).await?,
            "observed provider capture",
            "Restore access to the original transcript binding before retrying stop.",
        )?;
        // Preserve complete records already available from the
        // retained native source. The user-owned writer remains
        // live, so this is never a final-flush or exit claim.
        self.capture
            .catch_up(
                Admission {
                    actor: se_store::Actor::Agent(agent.clone()),
                    scope: se_store::Scope::Project(project),
                    session: Some(session.clone()),
                    generation: admission.generation,
                },
                pin.conversation,
                pin.path,
                deadline,
            )
            .await?;
        Ok(())
    }
}
