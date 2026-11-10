use super::*;
use super::{launch::Work, launch_util::call};
use crate::{HarnessAttach, HarnessRequest, client::lease::Deadline};
use se_core::ops::{LaunchResult, ResumeCommand, process_commit};
use se_proc::{CheckpointKind, ProcessRuntime};
use se_types::{Read, Result};
impl LaunchCoordinator {
    pub(super) async fn attach(
        &self,
        work: &mut Work,
        request: HarnessRequest,
        transport: crate::ProviderTransport,
        record: se_proc::ProcessRecord,
        prepared: Option<crate::BindingWitness>,
        deadline: &Deadline,
    ) -> Result<LaunchResult> {
        let plan = work.plan.clone().ok_or_else(|| {
            se_core::scope::unreadable(
                "provider attach",
                "only a new owned launch can bind its stdout transport",
            )
        })?;
        let attended = request.mode == se_proc::LaunchMode::Window
            && plan.profile.provider == se_store::Provider::Claude;
        if attended {
            work.attended_setup_deadline =
                Some(self.window_activation_deadline(work, deadline).await?);
        }
        work.record = Some(record.clone());
        let owner = work.process.clone().ok_or_else(|| {
            se_core::scope::unreadable("provider attach", "owned process is absent")
        })?;
        let native = self.native.clone();
        let copied = record.clone();
        let generation = self.options.epoch.generation;
        let attach_owner = self
            .store
            .pool
            .run_owned(deadline, move || {
                native
                    .re_adopt(&copied, generation, generation)
                    .map_err(|e| error("attach process reference", e))
            })
            .await?;
        let outcome = if let Some(witness) = prepared {
            crate::LaunchOutcome {
                witness,
                binding: work
                    .binding
                    .take()
                    .ok_or_else(|| error("Codex console", "prepared backend binding is absent"))?,
            }
        } else {
            let wake = work.wake.clone();
            let relaunch = self.window_command(work, true);
            let attach = self.harness_for(plan.profile.provider)?.attach(
                HarnessAttach {
                    request,
                    process: attach_owner,
                    record: record.clone(),
                    transport,
                    transcript: Read::Absent {
                        checked: "transcript pin is published after session activation".into(),
                    },
                },
                &mut work.binding,
                call(self.store.generation, deadline)?,
            );
            if let Some(activation_deadline) = work.attended_setup_deadline {
                wake.awaiting_window
                    .store(true, std::sync::atomic::Ordering::Release);
                let result = self
                    .wait_window(
                        owner.clone(),
                        wake.clone(),
                        activation_deadline,
                        relaunch,
                        attach,
                    )
                    .await;
                wake.awaiting_window
                    .store(false, std::sync::atomic::Ordering::Release);
                result?.ok_or_else(|| self.expired_window_error(work))?
            } else {
                wake.readiness(attach).await?
            }
        };
        // Only the human wait is outside the original short clock. All C3
        // validation, first-use proofs and publication get a bounded call.
        let publication;
        let deadline = if attended {
            publication = Deadline::idle()?.next_call()?;
            &publication
        } else {
            deadline
        };
        if outcome.witness.identity.session != plan.session
            || outcome.witness.identity.project != plan.project.id
            || outcome.witness.identity.agent != plan.agent.id
            || outcome.witness.lifecycle != plan.lifecycle
            || matches!(&plan.conversation, Read::Present { value } if value != &outcome.witness.conversation)
        {
            return Err(se_core::scope::unreadable(
                "provider readiness",
                "harness witness differs from the reserved session/lifecycle",
            ));
        }
        work.binding = Some(outcome.binding);
        if let Some(binding) = work
            .binding
            .as_ref()
            .and_then(|binding| binding.secode.as_ref())
        {
            binding.completion.arm(&work.wake.event)?;
        }
        if let Some(binding) = work
            .binding
            .as_ref()
            .and_then(|binding| binding.claude.as_ref())
        {
            binding.completion.arm(&work.wake.event)?;
        }
        if let Some(binding) = work
            .binding
            .as_ref()
            .and_then(|binding| binding.codex.as_ref())
        {
            binding.completion.arm(&work.wake.event)?;
        }
        work.meta.conversation = Read::Present {
            value: outcome.witness.conversation.clone(),
        };
        let native_pin = if plan.capture && plan.profile.provider != se_store::Provider::SeCode {
            let binding = work
                .binding
                .as_ref()
                .ok_or_else(|| error("capture readiness", "provider binding absent"))?;
            let path = if plan.profile.provider == se_store::Provider::Codex {
                let path = se_core::scope::require_present(
                    crate::codex_rpc::bound(binding)?.rollout_path()?,
                    "Codex rollout readiness",
                    "Restore the exact provider-reported persistent thread path.",
                )?
                .to_local()?;
                crate::codex_capture::location(&path, &crate::codex_capture::existing_home()?)?
            } else {
                crate::claude_transcript_location(binding)?
            };
            let provider = plan.profile.provider;
            let conversation = outcome.witness.conversation.clone();
            let candidate_path = path.clone();
            let mut pin = self
                .store
                .pool
                .run_owned(deadline, move || {
                    se_proc::NativeSourcePin::open(&candidate_path)
                        .map_err(|e| error("provider transcript pin", e))
                })
                .await?;
            let mut history_diagnostic = None;
            // Claude's init echo precedes transcript creation on a fresh
            // conversation. Wait only for absence, under the original launch
            // clock; an unreadable/replaced source must still refuse normally.
            if pin.is_none()
                && provider == se_store::Provider::Claude
                && matches!(plan.conversation, Read::Absent { .. })
            {
                // Leave the rest of the launch clock for first-use proofs and
                // witnessed cleanup if the provider never publishes the file.
                let readiness = deadline.stage(std::time::Duration::from_secs(10))?;
                while pin.is_none() {
                    let remaining =
                        readiness
                            .remaining()
                            .map_err(|failure| match failure.body.detail() {
                                se_types::Detail::DeadlineExceeded(expired) => {
                                    se_types::SeError::new(se_types::Detail::DeadlineExceeded(
                                        se_types::details::DeadlineExceeded {
                                            op: "Claude transcript creation after its init echo"
                                                .into(),
                                            deadline_ms: expired.deadline_ms,
                                        },
                                    ))
                                }
                                _ => failure,
                            })?;
                    let native = self.native.clone();
                    let owner = owner.clone();
                    let path = path.clone();
                    pin = self
                        .store
                        .pool
                        .run_owned(&readiness, move || {
                            let observed = native
                                .observe(&owner)
                                .map_err(|e| error("Claude transcript process witness", e))?;
                            if !matches!(observed.root, se_proc::ProcessObservation::Live(_)) {
                                return Err(error(
                                    "Claude transcript readiness",
                                    "provider exited before creating its transcript",
                                ));
                            }
                            se_proc::NativeSourcePin::open(&path)
                                .map_err(|e| error("provider transcript pin", e))
                        })
                        .await?;
                    if pin.is_none() {
                        tokio::time::sleep(remaining.min(std::time::Duration::from_millis(25)))
                            .await;
                    }
                }
            }
            if pin.is_none()
                && provider == se_store::Provider::Codex
                && matches!(plan.conversation, Read::Absent { .. })
            {
                history_diagnostic = crate::codex_rpc::bound(binding)?
                    .materialize_fresh_rollout(&call(self.store.generation, deadline)?)
                    .await?;
                pin = self
                    .store
                    .pool
                    .run_owned(deadline, move || {
                        se_proc::NativeSourcePin::open(&path)
                            .map_err(|e| error("provider transcript pin", e))
                    })
                    .await?;
            }
            let mut pin = pin.ok_or_else(|| {
                error(
                    "provider transcript readiness",
                    "the provider has not created its transcript",
                )
            })?;
            let pin = self
                .store
                .pool
                .run_owned(deadline, move || {
                    if provider == se_store::Provider::Codex {
                        crate::codex_capture::validate_header(&mut pin, &conversation)?;
                    }
                    Ok(pin)
                })
                .await?;
            if let Some(diagnostic) = history_diagnostic {
                eprintln!(
                    "Codex capture: native rollout header verified; optional empty-history read failed: {diagnostic}"
                );
            }
            work.transcript = Some(crate::TranscriptPin {
                identity: outcome.witness.identity.clone(),
                conversation: outcome.witness.conversation.clone(),
                path: NativePath::from_local(pin.path().into())?,
                file_identity: se_types::Sha256::from_bytes(pin.identity()),
            });
            work.capture_source = Some(process_commit::credential_id(&plan, "capture-source")?);
            Some(pin)
        } else {
            None
        };
        // Re-read the native pinned instance after the async provider handshake.
        // An already-exited provider cannot be published as running.
        let native = self.native.clone();
        let observation = self
            .store
            .pool
            .run_owned(deadline, move || {
                native
                    .observe(&owner)
                    .map_err(|e| error("readiness process witness", e))
            })
            .await?;
        if !matches!(observation.root, se_proc::ProcessObservation::Live(_)) {
            return Err(se_core::scope::unreadable(
                "provider readiness",
                "provider exited before C3 publication",
            ));
        }
        let stored = native_record::identity(
            &plan,
            CheckpointKind::Process(record.clone()),
            Some((&record.root, record.argv_sha256)),
            Some(record.guarantee),
            &self.options.epoch.owner.fields().boot,
        )?;
        let containment_cause = match &stored.containment {
            se_store::ContainmentFact::Uncontained { cause, .. } => {
                Some(se_core::ops::containment_cause_code(cause).into())
            }
            _ => None,
        };
        let previous = self.head(work, deadline).await?;
        let first = loop {
            let changed = work.wake.event.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            work.wake.require_startup()?;
            let native = self.native.clone();
            let owner = work
                .process
                .clone()
                .ok_or_else(|| error("credential readiness", "native owner absent"))?;
            let observed = self
                .store
                .pool
                .run_owned(deadline, move || {
                    native
                        .observe(&owner)
                        .map_err(|e| error("credential readiness process witness", e))
                })
                .await?;
            if !matches!(observed.root, se_proc::ProcessObservation::Live(_)) {
                return Err(error(
                    "credential readiness",
                    "provider exited before verified first use; no credential was activated",
                ));
            }
            let proof = self.proofs.wait(&plan.session, deadline);
            tokio::pin!(proof);
            let result = std::future::poll_fn(|cx| {
                use std::future::Future;
                use std::task::Poll;
                if let Poll::Ready(result) = proof.as_mut().poll(cx) {
                    return Poll::Ready(Some(result));
                }
                changed.as_mut().poll(cx).map(|()| None)
            })
            .await;
            if let Some(result) = result {
                break result?;
            }
        };
        let credentials = process_commit::CredentialActivation {
            session_request: first.session_request,
            http_request: first.http_request,
        };
        let committed_plan = plan.clone();
        work.wake.require_startup()?;
        let capture = work
            .transcript
            .as_ref()
            .zip(work.capture_source)
            .map(|(pin, source)| process_commit::CaptureActivation {
                source,
                native_ref: pin.conversation.to_string(),
                incarnation: pin.file_identity.as_bytes().to_vec(),
            });
        let capture = if plan.profile.provider == se_store::Provider::Codex && capture.is_none() {
            Some(process_commit::CaptureActivation {
                source: process_commit::credential_id(&plan, "capture-source")?,
                native_ref: outcome.witness.conversation.as_str().to_owned(),
                // With capture suppressed this is a logical vendor source,
                // never a file-incarnation claim or authority to read bytes.
                incarnation: <sha2::Sha256 as sha2::Digest>::digest(
                    outcome.witness.conversation.as_str().as_bytes(),
                )
                .to_vec(),
            })
        } else {
            capture
        };
        let secode_binding = work
            .secode
            .as_ref()
            .map(|prepared| {
                Ok::<_, se_types::SeError>(se_core::ops::SecodeBindingView {
                    schema: "se.secode-binding/v1".into(),
                    service_profile: prepared.profile.clone(),
                    service_process: prepared.process.clone(),
                    client_process: native_record::instance(
                        &record.root,
                        record.argv_sha256,
                        &self.options.epoch.owner.fields().boot,
                    )?,
                    session_id: prepared.session.clone(),
                    initial_input_id: prepared.initial_input.clone(),
                    incarnation: prepared.service.incarnation.clone(),
                    service_instance: prepared.service.service_instance.clone(),
                    generation: prepared.service.generation,
                    registration_version: prepared.service.registration_version.clone(),
                })
            })
            .transpose()?;
        let capture = if let Some(binding) = &secode_binding {
            let source = process_commit::credential_id(&plan, "capture-source")?;
            work.capture_source = Some(source);
            Some(process_commit::CaptureActivation {
                source,
                native_ref: binding.session_id.clone(),
                incarnation: serde_json::to_vec(binding)
                    .map_err(|e| error("SE Code source binding", e))?,
            })
        } else {
            capture
        };
        let receipt = self
            .store
            .commit(work.admission.clone(), deadline, None, move |kernel, cx| {
                process_commit::activate(
                    kernel,
                    &committed_plan,
                    &previous,
                    stored,
                    process_commit::Activation {
                        capture,
                        credentials,
                    },
                    cx,
                )
            })
            .await?;
        work.active = true;
        work.activated = true;
        if let Some(native_pin) = native_pin {
            self.capture
                .bind(
                    work.transcript
                        .clone()
                        .ok_or_else(|| error("capture activation", "pin metadata absent"))?,
                    work.capture_source
                        .ok_or_else(|| error("capture activation", "source absent"))?,
                    native_pin,
                    deadline,
                )
                .await?;
        }
        if plan.profile.provider == se_store::Provider::Codex {
            self.codex
                .start_initial(
                    work.binding
                        .as_ref()
                        .ok_or_else(|| error("Codex initial task", "retained binding absent"))?,
                    call(self.store.generation, deadline)?,
                )
                .await?;
        }
        let resume = se_core::ops::AgentCommand::launch_in_home(
            &plan.agent.id,
            &self.options.home,
            &plan.project.id,
            false,
        )
        .filter(|_| plan.profile.provider != se_store::Provider::SeCode)
        .map(|command| command.with_detach(plan.input.detach));
        Ok(LaunchResult {
            secode_binding: secode_binding.map(|value| Read::Present { value }),
            takeover: work.takeover.clone(),
            idempotency_key: plan.input.idempotency_key.clone(),
            event_id: receipt.primary_event,
            launch_id: se_proc::session_launch_id(&plan.session)
                .map_err(|e| error("launch identity", e))?,
            lifecycle_id: plan.lifecycle.clone(),
            project: plan.project.clone(),
            agent: plan.agent.clone(),
            session_id: plan.session.clone(),
            provider: match plan.profile.provider {
                se_store::Provider::Codex => se_types::Provider::Codex,
                se_store::Provider::Claude => se_types::Provider::Claude,
                se_store::Provider::SeCode => se_types::Provider::SeCode,
            },
            model: work.meta.model.clone(),
            permission_profile: plan.resolved.clone(),
            conversation_id: outcome.witness.conversation,
            state: "running".into(),
            surface: if plan.input.detach {
                "headless"
            } else {
                "window"
            }
            .into(),
            process: work.process_view.clone().ok_or_else(|| {
                se_core::scope::unreadable(
                    "launch receipt",
                    "native process birth was not witnessed",
                )
            })?,
            containment: match record.guarantee {
                se_proc::ContainmentGuarantee::KernelScope { .. } => "contained",
                _ => "uncontained",
            }
            .into(),
            containment_cause,
            replies: se_core::ops::AgentCommand::history_in_home(
                &plan.agent.id,
                &self.options.home,
                &plan.project.id,
            ),
            resume: ResumeCommand {
                ready: resume.is_some(),
                mode: "resume".into(),
                reason: resume.is_none().then(|| {
                    if plan.profile.provider == se_store::Provider::SeCode {
                        se_core::ops::AgentCommand::SECODE_RESUME_UNAVAILABLE
                    } else {
                        se_core::ops::AgentCommand::HOME_UNAVAILABLE
                    }
                    .into()
                }),
                command: resume.as_ref().map(|value| value.command.clone()),
                argv: resume.map(|value| value.argv),
            },
        })
    }
}
