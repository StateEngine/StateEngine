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
            let service = format!(
                "the externally owned SE Code service for conversation {}",
                conversation.escape_debug()
            );
            let reason = format!("Engine binding retired; jobs in {service} were not stopped.");
            let observed = self.embedded_binding(&session, admission, deadline).await?;
            if matches!(
                observed.current.body,
                EventBody::SessionPrepared { .. } | EventBody::SessionActivated { .. }
            ) {
                if observed.revision != original.revision {
                    return Err(error(
                        "embedded stop selection",
                        "the selected binding revision changed; no newer binding was retired",
                    ));
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
