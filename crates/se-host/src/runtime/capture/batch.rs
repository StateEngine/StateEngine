//! One bounded capture batch. Only the coordinator drains consecutive batches;
//! hook replies retain their existing bounded per-signal diagnostics.
use super::*;

pub(super) struct CaptureBatch {
    pub(super) result: ExecutedCall,
    pub(super) complete: bool,
}

#[derive(Default)]
struct BatchProgress {
    host_phases: se_core::ops::HostPhaseTimings,
    commits: Vec<se_core::ops::CaptureCommitDiagnostics>,
    natural_keys: Vec<String>,
    committed_events: Vec<se_types::EventId>,
}

impl BatchProgress {
    fn record_read_phase(&mut self, capture_read: se_core::ops::HostPhaseSpan) {
        self.host_phases.merge(se_core::ops::HostPhaseTimings {
            capture_read: Some(capture_read),
            ..Default::default()
        });
    }

    fn record_commit(&mut self, result: &ExecutedCall, natural_key: String) -> Result<()> {
        self.host_phases.merge(result.host_phases.clone());
        if let se_core::ops::AnyOutput::HookClaude(value) = &result.output
            && let Some(receipt) = &value.value.receipt
        {
            self.committed_events.push(receipt.event_id.clone());
            self.natural_keys.push(natural_key);
            let measured = result.write_timings.as_ref().ok_or_else(|| {
                se_core::scope::unreadable(
                    "capture timings",
                    "committed capture has no per-completion measurement",
                )
            })?;
            let write_timings = se_core::ops::ReceiptWriteTimings::from_store(measured);
            write_timings.validate()?;
            self.commits.push(se_core::ops::CaptureCommitDiagnostics {
                event_id: receipt.event_id.clone(),
                write_timings,
            });
        }
        Ok(())
    }

    fn into_batch(self, result: Result<(ExecutedCall, bool)>) -> Result<CaptureBatch> {
        match result {
            Ok((mut result, complete)) => {
                result.host_phases = self.host_phases;
                result.capture_commits = self.commits;
                result.capture_keys = self.natural_keys;
                Ok(CaptureBatch { result, complete })
            }
            Err(error) if !self.committed_events.is_empty() => Err(SeError::new(
                se_types::Detail::CaptureIncomplete(se_types::details::CaptureIncomplete {
                    committed_events: self.committed_events,
                    natural_keys: self.natural_keys,
                    reason: error.to_string(),
                }),
            )
            .with_cause(error)),
            Err(error) => Err(error),
        }
    }
}

enum NextStep {
    Retry,
    Exhausted {
        capture_read: se_core::ops::HostPhaseSpan,
    },
    Ready {
        capture: Box<TrustedCapture>,
        replayed: bool,
        capture_read: se_core::ops::HostPhaseSpan,
    },
}

impl Capturing<'_> {
    async fn read_next(
        &self,
        admission: &se_store::Admission,
        pin: &Arc<Mutex<BoundTranscript>>,
        hook: &crate::ClaudeHookInput,
        deadline: &Deadline,
        replay: bool,
        last_busy: &mut Option<se_types::ErrorBody>,
    ) -> Result<NextStep> {
        let context = self.execution.clone();
        let admitted = admission.clone();
        let source = Arc::clone(pin);
        let signal = crate::ClaudeHookInput {
            kind: hook.kind,
            conversation: hook.conversation.clone(),
            claimed_transcript: hook.claimed_transcript.clone(),
            payload: serde_json::Value::Null,
        };
        let bound = deadline.clone();
        let final_capture = self.final_capture;
        let read = timings::blocking(
            &self.execution.blocking,
            Mode::Finite,
            deadline,
            move || {
                let mut pin = try_guard(&source)?;
                source::next(
                    &context,
                    &admitted,
                    &mut pin,
                    &signal,
                    &bound,
                    replay,
                    final_capture,
                )
            },
        )
        .await;
        let read = match (read, last_busy.clone()) {
            (Err(error), Some(busy)) if error.code() == se_types::Code::DeadlineExceeded => {
                // The held source is retried until the budget is spent;
                // bounded pool admission can spend it first. Report the
                // busy cause so a load-flipped retry keeps one stable
                // failure identity for the caller and the retained
                // receipt.
                Err(busy.into())
            }
            (read, _) => read,
        };
        if let Err(error) = &read
            && error.code() == se_types::Code::StoreBusy
            && last_busy.is_none()
        {
            *last_busy = Some(error.body.clone());
        }
        let (next, capture_read) = match read {
            Err(error) if self.wait_if_busy(&error, deadline).await => return Ok(NextStep::Retry),
            result => result?,
        };
        match next {
            Some((capture, replayed)) => Ok(NextStep::Ready {
                capture: Box::new(capture),
                replayed,
                capture_read,
            }),
            None => Ok(NextStep::Exhausted { capture_read }),
        }
    }

    #[cfg(feature = "remote")]
    fn publish_remote_turn(
        &self,
        admission: &se_store::Admission,
        session: &se_types::SessionId,
        capture: &TrustedCapture,
        observed_at: std::time::Instant,
    ) {
        let Some(control) = self.execution.mail_waits.remote_control() else {
            return;
        };
        let Ok(Some(publisher)) = control.live() else {
            return;
        };
        let target = match (&admission.scope, &admission.actor) {
            (se_store::Scope::Project(project), se_store::Actor::Agent(agent)) => {
                Some(crate::remote::RemoteTarget {
                    project: project.clone(),
                    agent: agent.clone(),
                })
            }
            _ => None,
        };
        let role = match capture.request.role {
            se_store::Role::User => Some(crate::remote::RemoteTurnRole::User),
            se_store::Role::Assistant => Some(crate::remote::RemoteTurnRole::Assistant),
            se_store::Role::Tool => Some(crate::remote::RemoteTurnRole::Tool),
            _ => None,
        };
        if let (Some(target), Some(role)) = (target, role) {
            publisher.complete_existing(
                &target,
                session,
                &capture.request.vendor_turn,
                role,
                capture.request.text.as_str(),
                observed_at,
            );
        }
    }

    async fn commit_capture(
        &self,
        admission: &se_store::Admission,
        terminal: &se_core::admission::HumanTerminal,
        capture: Box<TrustedCapture>,
        natural_key: &str,
        deadline: &Deadline,
        progress: &mut BatchProgress,
    ) -> Result<Option<ExecutedCall>> {
        let result = execute(
            self.execution.clone(),
            ExecutionCall {
                admitted: HostedCall {
                    remote_credential: None,
                    input: HostedInput::Capture(capture),
                    kernel: se_core::dispatch::Kernel::read_only(),
                    admission: admission.clone(),
                    terminal: terminal.clone(),
                    selections: None,
                },
                deadline: deadline.clone(),
            },
        )
        .await;
        match result {
            Ok(result) => Ok(Some(result)),
            Err(error) if self.wait_if_busy(&error, deadline).await => Ok(None),
            Err(error) => {
                if let se_types::Detail::CommittedResponseUnavailable(known) = error.body.detail() {
                    progress
                        .committed_events
                        .extend(known.committed_events.iter().cloned());
                    progress.natural_keys.push(natural_key.to_owned());
                }
                Err(error)
            }
        }
    }

    pub(super) async fn batch(
        &self,
        admission: se_store::Admission,
        terminal: se_core::admission::HumanTerminal,
        selections: Option<se_core::ops::CliSelections>,
        hook: crate::ClaudeHookInput,
        deadline: &Deadline,
    ) -> Result<CaptureBatch> {
        #[cfg(feature = "remote")]
        let observed_at = deadline.started();
        if selections.is_some() || admission.generation != self.execution.generation.get() {
            return Err(SeError::invalid(
                "capture admission",
                "the exact generation with no CLI selection metadata",
            ));
        }
        let session = admission
            .session
            .as_ref()
            .ok_or_else(|| SeError::invalid("capture session", "an admitted session"))?;
        let pin = loop {
            match self.sources.get(session) {
                Err(error) if self.wait_if_busy(&error, deadline).await => continue,
                result => break result?,
            }
        };
        let mut progress = BatchProgress::default();
        let mut last = None;
        let mut last_busy: Option<se_types::ErrorBody> = None;
        let result = async {
            loop {
                self.check_open()?;
                let (mut capture, replayed) = match self
                    .read_next(
                        &admission,
                        &pin,
                        &hook,
                        deadline,
                        last.is_none(),
                        &mut last_busy,
                    )
                    .await?
                {
                    NextStep::Retry => continue,
                    NextStep::Exhausted { capture_read } => {
                        progress.record_read_phase(capture_read);
                        return Ok((last.unwrap_or_else(|| empty_capture(hook.kind)), true));
                    }
                    NextStep::Ready {
                        capture,
                        replayed,
                        capture_read,
                    } => {
                        progress.record_read_phase(capture_read);
                        (capture, replayed)
                    }
                };
                #[cfg(feature = "remote")]
                if !replayed {
                    self.publish_remote_turn(&admission, session, &capture, observed_at);
                }
                capture.request.recovery_owner = self.recovery_owner.clone();
                if progress.commits.len() >= 128 {
                    return Ok((
                        last.ok_or_else(|| {
                            SeError::invalid(
                                "capture batch",
                                "a committed batch before continuation",
                            )
                        })?,
                        false,
                    ));
                }
                let natural_key = format!(
                    "session={}, provider={:?}, conversation={}, turn={}",
                    session,
                    capture.request.provider,
                    capture.request.conversation,
                    capture.request.vendor_turn
                );
                let Some(result) = self
                    .commit_capture(
                        &admission,
                        &terminal,
                        capture,
                        &natural_key,
                        deadline,
                        &mut progress,
                    )
                    .await?
                else {
                    continue;
                };
                progress.record_commit(&result, natural_key)?;
                if replayed {
                    return Ok((result, true));
                }
                last = Some(result);
            }
        }
        .await;
        progress.into_batch(result)
    }
}
