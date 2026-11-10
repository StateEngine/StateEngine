//! One bounded capture batch. Only the coordinator drains consecutive batches;
//! hook replies retain their existing bounded per-signal diagnostics.
use super::*;

pub(super) struct CaptureBatch {
    pub(super) result: ExecutedCall,
    pub(super) complete: bool,
}

impl Capturing<'_> {
    pub(super) async fn batch(
        &self,
        admission: se_store::Admission,
        terminal: se_core::admission::HumanTerminal,
        selections: Option<se_core::ops::CliSelections>,
        hook: crate::ClaudeHookInput,
        deadline: &Deadline,
    ) -> Result<CaptureBatch> {
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
        let mut host_phases = se_core::ops::HostPhaseTimings::default();
        let mut last = None;
        let mut commits = Vec::new();
        let mut natural_keys = Vec::new();
        let mut committed_events = Vec::new();
        let result = async {
            loop {
                self.check_open()?;
                let context = self.execution.clone();
                let admitted = admission.clone();
                let source = Arc::clone(&pin);
                let signal = crate::ClaudeHookInput {
                    kind: hook.kind,
                    conversation: hook.conversation.clone(),
                    claimed_transcript: hook.claimed_transcript.clone(),
                    payload: serde_json::Value::Null,
                };
                let bound = deadline.clone();
                let replay = last.is_none();
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
                let (next, capture_read) = match read {
                    Err(error) if self.wait_if_busy(&error, deadline).await => continue,
                    result => result?,
                };
                host_phases.merge(se_core::ops::HostPhaseTimings {
                    capture_read: Some(capture_read),
                    ..Default::default()
                });
                let Some((mut capture, replayed)) = next else {
                    return Ok((last.unwrap_or_else(|| empty_capture(hook.kind)), true));
                };
                #[cfg(feature = "remote")]
                if !replayed
                    && let Some(control) = self.execution.mail_waits.remote_control()
                    && let Ok(Some(publisher)) = control.live()
                {
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
                        );
                    }
                }
                capture.request.recovery_owner = self.recovery_owner.clone();
                if commits.len() >= 128 {
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
                let result = execute(
                    self.execution.clone(),
                    ExecutionCall {
                        admitted: HostedCall {
                            remote_credential: None,
                            input: HostedInput::Capture(Box::new(capture)),
                            kernel: se_core::dispatch::Kernel::read_only(),
                            admission: admission.clone(),
                            terminal: terminal.clone(),
                            selections: None,
                        },
                        deadline: deadline.clone(),
                    },
                )
                .await;
                let result = match result {
                    Ok(result) => result,
                    Err(error) if self.wait_if_busy(&error, deadline).await => continue,
                    Err(error) => {
                        if let se_types::Detail::CommittedResponseUnavailable(known) =
                            error.body.detail()
                        {
                            committed_events.extend(known.committed_events.iter().cloned());
                            natural_keys.push(natural_key);
                        }
                        return Err(error);
                    }
                };
                host_phases.merge(result.host_phases.clone());
                if let se_core::ops::AnyOutput::HookClaude(value) = &result.output
                    && let Some(receipt) = &value.value.receipt
                {
                    committed_events.push(receipt.event_id.clone());
                    natural_keys.push(natural_key);
                    let measured = result.write_timings.as_ref().ok_or_else(|| {
                        se_core::scope::unreadable(
                            "capture timings",
                            "committed capture has no per-completion measurement",
                        )
                    })?;
                    let write_timings = se_core::ops::ReceiptWriteTimings::from_store(measured);
                    write_timings.validate()?;
                    commits.push(se_core::ops::CaptureCommitDiagnostics {
                        event_id: receipt.event_id.clone(),
                        write_timings,
                    });
                }
                if replayed {
                    return Ok((result, true));
                }
                last = Some(result);
            }
        }
        .await;
        match result {
            Ok((mut result, complete)) => {
                result.host_phases = host_phases;
                result.capture_commits = commits;
                result.capture_keys = natural_keys;
                Ok(CaptureBatch { result, complete })
            }
            Err(error) if !committed_events.is_empty() => Err(SeError::new(
                se_types::Detail::CaptureIncomplete(se_types::details::CaptureIncomplete {
                    committed_events,
                    natural_keys,
                    reason: error.to_string(),
                }),
            )
            .with_cause(error)),
            Err(error) => Err(error),
        }
    }
}
