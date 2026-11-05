//! The supervisor uses the host's one pinned transcript consumer. No stdout
//! bytes become turns, and no failed capture is reported as flushed.
use super::{owned::Work, *};
use crate::client::lease::Deadline;
use se_types::{Read, Result};
mod recovery;
impl LaunchCoordinator {
    pub(super) async fn flush_capture(&self, work: &mut Work, deadline: &Deadline) -> Result<()> {
        if work.capture_flushed || !work.meta.capture || !work.activated {
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
        self.capture_progress_using(work, deadline, &self.capture)
            .await
    }
    pub(super) async fn capture_progress_using(
        &self,
        work: &mut Work,
        deadline: &Deadline,
        capture: &crate::runtime::CaptureHandle,
    ) -> Result<()> {
        work.capture_failure = None;
        let result = self.capture_progress_inner(work, deadline, capture).await;
        if let Err(error) = &result {
            self.report_capture_failure(work, error).await?;
            work.capture_failure = Some(error.body.clone());
        } else {
            work.capture_failure = None;
        }
        result
    }
    pub(super) async fn report_capture_failure(
        &self,
        work: &Work,
        failure: &se_types::SeError,
    ) -> Result<()> {
        if !work.meta.capture || !work.active {
            return Ok(());
        }
        // The supervisor retains the failed capture after its caller's bound.
        // Give only this durable diagnostic its own short, finite write bound.
        let diagnostic = Deadline::idle()?.stage(std::time::Duration::from_secs(2))?;
        let session = work.meta.session.clone();
        let admission = se_store::Admission {
            scope: se_store::Scope::Project(work.meta.project.id.clone()),
            actor: se_store::Actor::Agent(work.meta.agent.id.clone()),
            session: Some(session.clone()),
            generation: self.store.generation.get(),
        };
        let body = failure.body.clone();
        self.store
            .commit(admission, &diagnostic, None, move |kernel, cx| {
                se_core::ops::process_commit::capture_failure(kernel, session, body, cx)
            })
            .await
            .map_err(|cause| error("live capture diagnostic", format!("capture failed: {failure}; retaining its public failure also failed: {cause}")).with_cause(cause))?;
        Ok(())
    }
    async fn capture_progress_inner(
        &self,
        work: &mut Work,
        deadline: &Deadline,
        capture: &crate::runtime::CaptureHandle,
    ) -> Result<()> {
        if work.capture_flushed || !work.meta.capture || !work.activated {
            return Ok(());
        }
        if work.transcript.is_none() {
            let identity = crate::SessionIdentity {
                project: work.meta.project.id.clone(),
                agent: work.meta.agent.id.clone(),
                session: work.meta.session.clone(),
            };
            let restored = if work.native_already_reconciled {
                capture.recover_binding(identity, deadline).await?
            } else {
                capture.binding(identity)?
            };
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
        let result = if (work.process_retired || work.native_already_reconciled)
            && work.last_witness.is_some()
        {
            capture
                .catch_up_final(
                    admission,
                    transcript.conversation,
                    transcript.path,
                    work.meta.owner.clone(),
                    deadline,
                )
                .await?
        } else {
            capture
                .catch_up(
                    admission,
                    transcript.conversation,
                    transcript.path,
                    deadline,
                )
                .await?
        };
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
        if work.meta.provider == se_store::Provider::Codex {
            self.acknowledge_codex_capture(work, deadline).await?;
        }
        Ok(())
    }
}
