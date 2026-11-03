//! The supervisor uses the host's one pinned transcript consumer. No stdout
//! bytes become turns, and no failed capture is reported as flushed.
use super::{owned::Work, *};
use crate::client::lease::Deadline;
use se_types::{Read, Result};
impl LaunchCoordinator {
    pub(super) async fn flush_capture(&self, work: &mut Work, deadline: &Deadline) -> Result<()> {
        if work.capture_flushed || !work.meta.capture || !work.active {
            return Ok(());
        }
        self.capture_progress(work, deadline).await?;
        work.capture_flushed = true;
        Ok(())
    }
    pub(super) async fn capture_progress(
        &self,
        work: &mut Work,
        deadline: &Deadline,
    ) -> Result<()> {
        if work.capture_flushed || !work.meta.capture || !work.active {
            return Ok(());
        }
        if work.transcript.is_none() {
            let restored = self.capture.binding(crate::SessionIdentity {
                project: work.meta.project.id.clone(),
                agent: work.meta.agent.id.clone(),
                session: work.meta.session.clone(),
            })?;
            let transcript = se_core::scope::require_present(
                restored,
                "final transcript capture",
                "Restore the original protected binding and native file incarnation; preserve the committed cursor.",
            )?;
            if !matches!(&work.meta.conversation, Read::Present { value } if value == &transcript.conversation)
            {
                return Err(error(
                    "final transcript capture",
                    "restored binding differs from the original saved conversation",
                ));
            }
            work.transcript = Some(transcript);
        }
        let transcript=work.transcript.clone().ok_or_else(||error("final transcript capture","trusted binding is unavailable; retain the revoked session and committed cursor for recovery"))?;
        let admission = se_store::Admission {
            scope: se_store::Scope::Project(work.meta.project.id.clone()),
            actor: se_store::Actor::Agent(work.meta.agent.id.clone()),
            session: Some(work.meta.session.clone()),
            generation: self.store.generation.get(),
        };
        let result = self
            .capture
            .catch_up(
                admission,
                transcript.conversation,
                transcript.path,
                deadline,
            )
            .await?;
        let se_core::ops::AnyOutput::HookClaude(output) = result.output else {
            return Err(error(
                "final transcript capture",
                "unexpected output family",
            ));
        };
        if let Some(failure) = output.value.failure {
            return Err(se_types::SeError {
                body: failure,
                cause: None,
            });
        }
        match output.value.captured {
            Read::Present { value } => work.last_capture = Some(value),
            Read::Absent { .. } => {}
            Read::Unreadable { reason, .. } => {
                return Err(error("final transcript capture", reason));
            }
            Read::Unknown { what } => return Err(error("final transcript capture", what)),
        }
        Ok(())
    }
}
