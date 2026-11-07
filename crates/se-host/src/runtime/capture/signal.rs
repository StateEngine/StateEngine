//! Native hooks do not repeat a successful availability exit. Retain a bounded
//! retry here, and publish terminal capture failures through the existing writer.
use super::*;
use se_core::{admission::read_scope, commit::Cx, dispatch::Kernel, store_error::store_error};
use se_store::Snapshot;
use std::time::Duration;

#[cfg(all(test, target_os = "linux"))]
#[path = "signal_tests.rs"]
mod tests;

impl Capturing<'_> {
    pub(super) async fn wait_if_busy(&self, error: &SeError, deadline: &Deadline) -> bool {
        if self.retry_busy
            && error.code() == se_types::Code::StoreBusy
            && let Ok(remaining) = deadline.remaining()
            && remaining > Duration::from_millis(25)
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
            true
        } else {
            false
        }
    }

    pub(super) async fn signal(
        &self,
        admission: se_store::Admission,
        terminal: se_core::admission::HumanTerminal,
        selections: Option<se_core::ops::CliSelections>,
        hook: crate::ClaudeHookInput,
        deadline: &Deadline,
    ) -> Result<ExecutedCall> {
        // Leave room inside the native CLI's ten-second budget for transport
        // and the failure receipt. No store/native transaction is cancelled.
        let attempt = deadline.stage(Duration::from_secs(5))?;
        let kind = hook.kind;
        let result = self
            .capture(admission.clone(), terminal, selections, hook, &attempt)
            .await;
        let failure = match result {
            Ok(value) => return Ok(value),
            // SessionStart validates context only; it must remain read-only.
            Err(error) if matches!(kind, crate::ClaudeHookKind::SessionStart) => {
                return Err(error);
            }
            Err(error) => error,
        };
        let retained = self
            .retain_failure(admission.clone(), failure.body.clone())
            .await;
        // Publish the diagnostic before waking the monitor: a successful
        // readback must clear that failure, never race with a later stale one.
        let continued = self.continue_capture(&admission);
        let receipt = match retained {
            Ok(receipt) => receipt,
            // The diagnostic cannot replace the capture outcome, especially
            // its confirmed events and natural keys after a partial commit.
            // Keep the recording error as the secondary cause, without
            // claiming a capture.failed receipt that was not confirmed.
            Err(cause) => {
                let cause = match continued {
                    Ok(()) => cause,
                    Err(wake) => cause.with_cause(wake),
                };
                return Err(failure.with_cause(cause));
            }
        };
        if let Err(cause) = continued {
            return Err(failure.with_cause(cause));
        }
        let mut output = empty_capture(kind);
        output.output = se_core::ops::HookResult {
            stdout: String::new(),
            captured: Read::Unreadable {
                source: "native transcript capture".into(),
                reason: failure.body.message(),
                error: Some(Box::new(failure.body.clone())),
            },
            failure: Some(failure.body),
            receipt: None,
        }
        .into();
        output.committed = Some(super::super::CommittedWrite {
            operation: "agent.launch".into(),
            key: receipt.0,
            natural_events: Vec::new(),
            committed_events: receipt.1.events,
        });
        Ok(output)
    }

    fn continue_capture(&self, admission: &se_store::Admission) -> Result<()> {
        let (se_store::Scope::Project(project), se_store::Actor::Agent(agent), Some(session)) =
            (&admission.scope, &admission.actor, &admission.session)
        else {
            return Err(SeError::invalid(
                "capture continuation",
                "an admitted agent session",
            ));
        };
        self.execution.custody.get().map_or(Ok(()), |custody| {
            custody.notify_capture(&crate::SessionIdentity {
                project: project.clone(),
                agent: agent.clone(),
                session: session.clone(),
            })
        })
    }

    async fn retain_failure(
        &self,
        admission: se_store::Admission,
        failure: se_types::ErrorBody,
    ) -> Result<(Option<se_types::IdempotencyKey>, se_store::CommitReceipt)> {
        // Same short retained diagnostic budget as the native supervisor. An
        // expired caller cannot erase a failed capture or cancel a FULL write.
        let diagnostic = Deadline::idle()?.stage(Duration::from_secs(2))?;
        let session = admission
            .session
            .clone()
            .ok_or_else(|| SeError::invalid("capture failure", "the admitted session"))?;
        let context = self.execution.clone();
        let bound = diagnostic.clone();
        let batch = self
            .execution
            .blocking
            .run_owned(&diagnostic, move || {
                bound.remaining()?;
                let phase = super::super::executor::checked_pooled_phase(
                    &context.reads,
                    context.generation,
                )?;
                let mut read = phase
                    .into_snapshot(read_scope(&admission))
                    .map_err(|error| store_error(&error))?;
                let result = (|| {
                    let kernel = Kernel::new(super::super::start::allocate_facts()?)?;
                    se_core::ops::process_commit::capture_failure(
                        &kernel,
                        session,
                        failure,
                        &mut Cx {
                            read: &mut read,
                            admission: &admission,
                        },
                    )
                })();
                super::super::executor::close_read(result, read.close())
            })
            .await?;
        let identity = super::super::failure::WriteIdentity {
            operation: "agent.launch",
            natural_key: None,
            key: batch.request.as_ref().map(|request| request.key.clone()),
            natural_events: Vec::new(),
        };
        let receipt = super::super::submit::measured(self.execution, batch, &identity, &diagnostic)
            .await?
            .0;
        Ok((identity.key, receipt))
    }
}
