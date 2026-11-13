//! The supervisor uses the host's one pinned transcript consumer. No stdout
//! bytes become turns, and no failed capture is reported as flushed.
use super::{owned::Work, *};
use crate::client::lease::Deadline;
use se_types::{Read, Result};
mod recovery;
impl LaunchCoordinator {
    /// A complete canonical read must cover the durable capture cursor.
    pub(super) async fn verify_captured_end(
        &self,
        admission: se_store::Admission,
        source: se_store::RecordId,
        end: u64,
        deadline: &Deadline,
    ) -> Result<()> {
        use se_store::{EventBody, Snapshot};
        self.store
            .read(admission, deadline, move |cx| {
                let source = se_core::scope::require_present(
                    cx.read
                        .capture_source(source)
                        .map_err(|e| se_core::store_error::store_error(&e))?,
                    "captured prefix",
                    "Preserve the original source and cursor.",
                )?;
                let saved = match &source.current.body {
                    EventBody::CaptureSource { .. } => 0,
                    EventBody::CaptureProgress { new_offset, .. } => *new_offset,
                    _ => return Err(error("captured prefix", "cursor unavailable")),
                };
                if saved != end {
                    return Err(error(
                        "captured prefix",
                        "canonical history ended before covering the saved cursor",
                    ));
                }
                Ok(())
            })
            .await
    }
    pub(super) async fn flush_capture(&self, work: &mut Work, deadline: &Deadline) -> Result<()> {
        if work.capture_flushed || !work.meta.capture || !work.activated {
            return self.retire_capture(work, deadline).await;
        }
        self.capture_progress(work, deadline).await?;
        let session = work.meta.session.clone();
        let owner = work.meta.owner.clone();
        let admission = se_store::Admission {
            scope: se_store::Scope::Project(work.meta.project.id.clone()),
            actor: se_store::Actor::Agent(work.meta.agent.id.clone()),
            session: Some(session.clone()),
            generation: self.store.generation.get(),
        };
        if let Err(error) = self
            .store
            .commit(admission, deadline, None, move |kernel, cx| {
                se_core::ops::process_commit::capture_verified(kernel, session, &owner, None, cx)
            })
            .await
        {
            self.report_capture_failure(work, &error).await?;
            work.capture_failure = Some(error.body.clone());
            return Err(error);
        }
        work.capture_flushed = true;
        self.retire_capture(work, deadline).await
    }
    pub(super) async fn retire_capture(&self, work: &mut Work, deadline: &Deadline) -> Result<()> {
        if !work.session_retired {
            return Ok(());
        }
        // Metadata is not a native pin. An incomplete terminal source can be
        // reopened on an explicit stop retry without retaining file handles.
        work.transcript = None;
        self.capture
            .retire(
                crate::SessionIdentity {
                    project: work.meta.project.id.clone(),
                    agent: work.meta.agent.id.clone(),
                    session: work.meta.session.clone(),
                },
                work.capture_flushed || !work.activated || !work.meta.capture,
                deadline,
            )
            .await
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
        if !work.meta.capture || !work.activated {
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
        let owner = work.session_retired.then(|| work.meta.owner.clone());
        self.store
            .commit(admission, &diagnostic, None, move |kernel, cx| {
                match owner {
                    Some(owner) => se_core::ops::process_commit::final_capture_failure(kernel, session, &owner, body, cx),
                    None => se_core::ops::process_commit::capture_failure(kernel, session, body, cx),
                }
            })
            .await
            .map_err(|cause| error("live capture diagnostic", format!("capture failed: {failure}; retaining its public failure also failed: {cause}")).with_cause(cause))?;
        Ok(())
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    async fn capture_progress_inner(
        &self,
        work: &mut Work,
        deadline: &Deadline,
        capture: &crate::runtime::CaptureHandle,
    ) -> Result<()> {
        if work.meta.provider == se_store::Provider::SeCode && work.active && !work.process_retired
        {
            self.deny_secode_approvals(work, deadline).await?;
        }
        if work.capture_flushed || !work.meta.capture || !work.activated {
            return Ok(());
        }
        if work.meta.provider == se_store::Provider::SeCode {
            return self.capture_secode(work, deadline).await;
        }
        if work.meta.provider == se_store::Provider::Acp {
            return self.capture_acp(work, deadline).await;
        }
        if work.transcript.is_none() {
            let identity = crate::SessionIdentity {
                project: work.meta.project.id.clone(),
                agent: work.meta.agent.id.clone(),
                session: work.meta.session.clone(),
            };
            let restored = if work.native_already_reconciled || work.session_retired {
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
                    admission.clone(),
                    transcript.conversation,
                    transcript.path,
                    work.meta.owner.clone(),
                    deadline,
                )
                .await?
        } else {
            capture
                .catch_up(
                    admission.clone(),
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
        // An accepted final write can outlive its hook and precede the failure
        // diagnostic. Replaying that write leaves the cursor unchanged, so
        // acknowledge only a fresh pinned EOF observation of that failure.
        if !work.session_retired && !work.native_already_reconciled {
            let observed = capture
                .unresolved_at_eof(admission.clone(), deadline)
                .await?;
            if let Some(observed) = observed {
                let session = work.meta.session.clone();
                let owner = work.meta.owner.clone();
                self.store
                    .commit(admission, deadline, None, move |kernel, cx| {
                        se_core::ops::process_commit::capture_verified(
                            kernel,
                            session,
                            &owner,
                            Some(observed),
                            cx,
                        )
                    })
                    .await?;
            }
        }
        Ok(())
    }
}
