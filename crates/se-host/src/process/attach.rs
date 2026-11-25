use super::readiness::refused;
use super::*;
use super::{launch::Work, launch_util::call};
use crate::{HarnessAttach, HarnessRequest, client::lease::Deadline};
use se_core::ops::{LaunchResult, ResumeCommand, process_commit};
use se_proc::{CheckpointKind, ProcessRuntime, StopObservation};
use se_types::{Read, Result};
/// What activation committed, as the launch receipt reports it.
struct Activated {
    event_id: se_types::EventId,
    containment_cause: Option<String>,
    secode_binding: Option<se_core::ops::SecodeBindingView>,
}
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
        let attach_owner = self.re_adopt(&record, deadline).await?;
        let outcome = if let Some(witness) = prepared {
            crate::LaunchOutcome {
                witness,
                binding: work
                    .binding
                    .take()
                    .ok_or_else(|| error("Codex console", "prepared backend binding is absent"))?,
            }
        } else {
            let attached = Arc::new(attach_owner);
            let input = HarnessAttach {
                request,
                process: attached.clone(),
                record: record.clone(),
                transport,
                transcript: Read::Absent {
                    checked: "transcript pin is published after session activation".into(),
                },
                provider_exit: self.provider_exit_proof(attached, deadline),
            };
            self.attach_harness(work, plan.profile.provider, input, owner.clone(), deadline)
                .await?
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
        verify_witness(&plan, &outcome.witness)?;
        let witness = outcome.witness;
        self.adopt_binding(work, outcome.binding, &witness)?;
        let native_pin = self
            .pin_transcript(work, &plan, &witness, &owner, deadline)
            .await?;
        let activated = self
            .activate(work, &plan, &record, &witness, &owner, deadline)
            .await?;
        if let Some(native_pin) = native_pin {
            self.bind_native_capture(work, native_pin, deadline).await?;
        }
        work.binding
            .as_ref()
            .ok_or_else(|| error("provider initial task", "retained binding absent"))?
            .start_initial(call(self.store.generation, deadline)?)
            .await?;
        self.launch_result(
            work,
            &plan,
            &record,
            attended,
            witness.conversation,
            activated,
        )
    }
    /// Takes a second owned reference to the exact birth record for the
    /// provider handshake.
    async fn re_adopt(
        &self,
        record: &se_proc::ProcessRecord,
        deadline: &Deadline,
    ) -> Result<se_proc::OwnedProcess> {
        let native = self.native.clone();
        let copied = record.clone();
        let generation = self.options.epoch.generation;
        self.store
            .pool
            .run_owned(deadline, move || {
                native
                    .re_adopt(&copied, generation, generation)
                    .map_err(|e| error("attach process reference", e))
            })
            .await
    }
    /// Lazy witnessed-exit proof the harness evaluates only when its
    /// handshake fails.
    fn provider_exit_proof(
        &self,
        attached: Arc<se_proc::OwnedProcess>,
        deadline: &Deadline,
    ) -> crate::ProviderExitProof {
        let native = self.native.clone();
        let pool = self.store.pool.clone();
        let proof_deadline = deadline.clone();
        let proof = move || -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> {
            let attached = attached.clone();
            let native = native.clone();
            let pool = pool.clone();
            let proof_deadline = proof_deadline.clone();
            Box::pin(async move {
                pool.run_owned(&proof_deadline, move || {
                    native
                        .witness_exit(&attached)
                        .map_err(|e| error("provider exit witness", e))
                        .map(|obs| matches!(obs, StopObservation::Complete(_)))
                })
                .await
                .unwrap_or(false)
            })
        };
        Arc::new(proof)
    }
    /// Runs the provider handshake; an attended window waits for the human
    /// under its own activation deadline.
    async fn attach_harness(
        &self,
        work: &mut Work,
        provider: se_store::Provider,
        input: HarnessAttach,
        owner: Arc<se_proc::OwnedProcess>,
        deadline: &Deadline,
    ) -> Result<crate::LaunchOutcome> {
        let wake = work.wake.clone();
        let relaunch = self.window_command(work, true);
        let cx = call(self.store.generation, deadline)?;
        let attach = if let Some(timing) = &mut work.startup_timing {
            self.codex.attach_timed(input, cx, timing)
        } else {
            self.harness_for(provider)?
                .attach(input, &mut work.binding, cx)
        };
        let Some(activation_deadline) = work.attended_setup_deadline else {
            return wake.readiness(attach).await;
        };
        wake.awaiting_window
            .store(true, std::sync::atomic::Ordering::Release);
        let result = self
            .wait_window(owner, wake.clone(), activation_deadline, relaunch, attach)
            .await;
        wake.awaiting_window
            .store(false, std::sync::atomic::Ordering::Release);
        result?.ok_or_else(|| self.expired_window_error(work))
    }
    /// Retains the verified binding and arms it for this lifecycle's events.
    fn adopt_binding(
        &self,
        work: &mut Work,
        binding: crate::HarnessBinding,
        witness: &crate::BindingWitness,
    ) -> Result<()> {
        work.binding = Some(binding);
        work.pending_transport = None;
        #[cfg(feature = "remote")]
        self.attach_remote_live(work);
        work.meta.conversation = Read::Present {
            value: witness.conversation.clone(),
        };
        work.binding
            .as_ref()
            .ok_or_else(|| error("provider readiness", "retained binding absent"))?
            .arm(&work.wake.event)
    }
    /// Pins and validates the provider's native transcript when capture is
    /// on, and records it as this lifecycle's capture source.
    async fn pin_transcript(
        &self,
        work: &mut Work,
        plan: &se_core::ops::agent_launch::LaunchPlan,
        witness: &crate::BindingWitness,
        owner: &Arc<se_proc::OwnedProcess>,
        deadline: &Deadline,
    ) -> Result<Option<se_proc::NativeSourcePin>> {
        let harness = self.harness_for(plan.profile.provider)?;
        let transcript = if plan.capture {
            let binding = work
                .binding
                .as_ref()
                .ok_or_else(|| error("capture readiness", "provider binding absent"))?;
            harness.transcript_path(binding)?
        } else {
            None
        };
        let Some(path) = transcript else {
            return Ok(None);
        };
        let binding = work
            .binding
            .as_ref()
            .ok_or_else(|| error("capture readiness", "provider binding absent"))?;
        let conversation = witness.conversation.clone();
        let mut pin = self.open_transcript_pin(path.clone(), deadline).await?;
        let mut history_diagnostic = None;
        // An adapter may announce readiness before publishing its fresh
        // transcript. Wait only for absence, under the original launch
        // clock; unreadable or replaced sources still refuse normally.
        if pin.is_none()
            && matches!(plan.conversation, Read::Absent { .. })
            && let Some(wait) = harness.transcript_wait()
        {
            // Leave the rest of the launch clock for first-use proofs and
            // witnessed cleanup if the provider never publishes the file.
            let readiness = deadline.stage(wait)?;
            pin = self
                .await_transcript(owner, &path, &plan.agent.id, &readiness)
                .await?;
        }
        if pin.is_none() && matches!(plan.conversation, Read::Absent { .. }) {
            history_diagnostic = harness
                .materialize_transcript(binding, call(self.store.generation, deadline)?)
                .await?;
            pin = self.open_transcript_pin(path, deadline).await?;
        }
        let mut pin = pin.ok_or_else(|| {
            refused(
                &plan.agent.id,
                "provider transcript readiness",
                "the provider has not created its transcript",
            )
        })?;
        let validate = harness.transcript_validator();
        let pin = self
            .store
            .pool
            .run_owned(deadline, move || {
                validate(&mut pin, &conversation)?;
                Ok(pin)
            })
            .await?;
        if let Some(diagnostic) = history_diagnostic {
            eprintln!(
                "Provider capture: native source verified; optional empty-history read failed: {diagnostic}"
            );
        }
        work.transcript = Some(crate::TranscriptPin {
            identity: witness.identity.clone(),
            conversation: witness.conversation.clone(),
            path: NativePath::from_local(pin.path().into())?,
            file_identity: se_types::Sha256::from_bytes(pin.identity()),
        });
        work.capture_source = Some(process_commit::credential_id(plan, "capture-source")?);
        Ok(Some(pin))
    }
    async fn open_transcript_pin(
        &self,
        path: std::path::PathBuf,
        deadline: &Deadline,
    ) -> Result<Option<se_proc::NativeSourcePin>> {
        self.store
            .pool
            .run_owned(deadline, move || {
                se_proc::NativeSourcePin::open(&path)
                    .map_err(|e| error("provider transcript pin", e))
            })
            .await
    }
    /// Polls for a transcript the live provider has not yet created, until
    /// it appears, the provider exits, or `readiness` expires.
    async fn await_transcript(
        &self,
        owner: &Arc<se_proc::OwnedProcess>,
        path: &std::path::Path,
        agent: &se_types::AgentId,
        readiness: &Deadline,
    ) -> Result<Option<se_proc::NativeSourcePin>> {
        let mut pin = None;
        while pin.is_none() {
            let remaining = readiness
                .remaining()
                .map_err(transcript_readiness_expired)?;
            let native = self.native.clone();
            let owner = owner.clone();
            let path = path.to_owned();
            let agent = agent.clone();
            let observed_until = readiness.at();
            pin = self
                .store
                .pool
                .run_owned(readiness, move || {
                    let observed = native.observe_until(&owner, observed_until).map_err(|e| {
                        refused(
                            &agent,
                            "provider transcript process witness",
                            format!("{e:?}"),
                        )
                    })?;
                    if !matches!(observed.root, se_proc::ProcessObservation::Live(_)) {
                        return Err(refused(
                            &agent,
                            "provider transcript readiness",
                            format!(
                                "provider exited before creating its transcript: {:?}",
                                observed.root
                            ),
                        ));
                    }
                    se_proc::NativeSourcePin::open(&path)
                        .map_err(|e| error("provider transcript pin", e))
                })
                .await?;
            if pin.is_none() {
                tokio::time::sleep(remaining.min(std::time::Duration::from_millis(25))).await;
            }
        }
        Ok(pin)
    }
    /// Proves first use, then commits the running lifecycle with its
    /// credentials, capture source and any SE Code binding.
    async fn activate(
        &self,
        work: &mut Work,
        plan: &Arc<se_core::ops::agent_launch::LaunchPlan>,
        record: &se_proc::ProcessRecord,
        witness: &crate::BindingWitness,
        owner: &Arc<se_proc::OwnedProcess>,
        deadline: &Deadline,
    ) -> Result<Activated> {
        // Re-read the native pinned instance after the async provider handshake.
        // An already-exited provider cannot be published as running.
        self.ensure_live(owner, &plan.agent.id, false, deadline)
            .await?;
        let stored = native_record::identity(
            plan,
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
        let credentials = self.first_use(work, plan, owner, deadline).await?;
        let committed_plan = plan.clone();
        work.wake.require_startup()?;
        let capture = transcript_capture(work, plan, &witness.conversation)?;
        let secode_binding = self.secode_binding(work, record)?;
        let capture = bound_capture(
            work,
            plan,
            &witness.conversation,
            secode_binding.as_ref(),
            capture,
        )?;
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
        Ok(Activated {
            event_id: receipt.primary_event,
            containment_cause,
            secode_binding,
        })
    }
    /// The provider's first verified credential use, observed directly for
    /// ACP and awaited from the proof channel otherwise.
    async fn first_use(
        &self,
        work: &Work,
        plan: &se_core::ops::agent_launch::LaunchPlan,
        owner: &Arc<se_proc::OwnedProcess>,
        deadline: &Deadline,
    ) -> Result<process_commit::CredentialActivation> {
        let (session_request, http_request) = if plan.profile.provider == se_store::Provider::Acp {
            let observed = self.proofs.observed(&plan.session)?;
            (observed.session_request, observed.http_request)
        } else {
            let first = loop {
                let changed = work.wake.event.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                work.wake.require_startup()?;
                self.ensure_live(owner, &plan.agent.id, true, deadline)
                    .await?;
                let proof = self.proofs.wait(&plan.session, deadline);
                tokio::select! {
                    biased;
                    result = proof => break result?,
                    () = changed => {}
                }
            };
            (Some(first.session_request), Some(first.http_request))
        };
        Ok(process_commit::CredentialActivation {
            session_request,
            http_request,
        })
    }
    fn secode_binding(
        &self,
        work: &Work,
        record: &se_proc::ProcessRecord,
    ) -> Result<Option<se_core::ops::SecodeBindingView>> {
        work.secode
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
            .transpose()
    }
    async fn bind_native_capture(
        &self,
        work: &Work,
        native_pin: se_proc::NativeSourcePin,
        deadline: &Deadline,
    ) -> Result<()> {
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
            .await
    }
    fn launch_result(
        &self,
        work: &Work,
        plan: &se_core::ops::agent_launch::LaunchPlan,
        record: &se_proc::ProcessRecord,
        attended: bool,
        conversation: se_types::ProviderSessionId,
        activated: Activated,
    ) -> Result<LaunchResult> {
        Ok(LaunchResult {
            mail_notifications: if attended {
                self.harness.mail_connected(&plan.session)
            } else {
                Read::Present {
                    value: work.binding.is_some(),
                }
            },
            harness_policy_notice: harness_policy_notice(work, plan)?,
            secode_binding: activated
                .secode_binding
                .map(|value| Read::Present { value }),
            takeover: work.takeover.clone(),
            idempotency_key: plan.input.idempotency_key.clone(),
            event_id: activated.event_id,
            launch_id: se_proc::session_launch_id(&plan.session)
                .map_err(|e| error("launch identity", e))?,
            lifecycle_id: plan.lifecycle.clone(),
            project: plan.project.clone(),
            agent: plan.agent.clone(),
            session_id: plan.session.clone(),
            provider: work
                .binding
                .as_ref()
                .ok_or_else(|| error("provider readiness", "retained binding absent"))?
                .provider(),
            model: work.meta.model.clone(),
            permission_profile: plan.resolved.clone(),
            conversation_id: conversation,
            resumed: matches!(&plan.conversation, Read::Present { .. }),
            saved_conversation_age: plan.saved_conversation_age.clone(),
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
            containment_cause: activated.containment_cause,
            replies: se_core::ops::AgentCommand::history_in_home(
                &plan.agent.id,
                &self.options.home,
                &plan.project.id,
            ),
            resume: self.resume_view(plan),
        })
    }
    fn resume_view(&self, plan: &se_core::ops::agent_launch::LaunchPlan) -> ResumeCommand {
        let resume = se_core::ops::AgentCommand::launch_in_home(
            &plan.agent.id,
            &self.options.home,
            &plan.project.id,
            false,
        )
        .filter(|_| plan.profile.provider != se_store::Provider::SeCode)
        .map(|command| {
            command
                .with_resume_session(&plan.session)
                .with_detach(plan.input.detach)
        });
        ResumeCommand {
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
        }
    }
    async fn ensure_live(
        &self,
        owner: &Arc<se_proc::OwnedProcess>,
        agent: &se_types::AgentId,
        credential: bool,
        deadline: &Deadline,
    ) -> Result<()> {
        let (witness, stage, exited) = if credential {
            (
                "credential readiness process witness",
                "credential readiness",
                "provider exited before verified first use; no credential was activated",
            )
        } else {
            (
                "readiness process witness",
                "provider readiness",
                "provider exited before publication as running",
            )
        };
        let (native, id, until, probe) = (
            self.native.clone(),
            agent.clone(),
            deadline.at(),
            owner.clone(),
        );
        let observed = self
            .store
            .pool
            .run_owned(deadline, move || {
                native
                    .observe_until(&probe, until)
                    .map_err(|e| refused(&id, witness, format!("{e:?}")))
            })
            .await?;
        if !matches!(observed.root, se_proc::ProcessObservation::Live(_)) {
            return Err(refused(
                agent,
                stage,
                format!("{exited}: {:?}", observed.root),
            ));
        }
        Ok(())
    }
}

/// The harness witness must name exactly the reserved session and lifecycle.
fn verify_witness(
    plan: &se_core::ops::agent_launch::LaunchPlan,
    witness: &crate::BindingWitness,
) -> Result<()> {
    if witness.identity.session != plan.session
        || witness.identity.project != plan.project.id
        || witness.identity.agent != plan.agent.id
        || witness.lifecycle != plan.lifecycle
        || matches!(&plan.conversation, Read::Present { value } if value != &witness.conversation)
    {
        return Err(se_core::scope::unreadable(
            "provider readiness",
            "harness witness differs from the reserved session/lifecycle",
        ));
    }
    Ok(())
}
fn transcript_readiness_expired(failure: se_types::SeError) -> se_types::SeError {
    match failure.body.detail() {
        se_types::Detail::DeadlineExceeded(expired) => se_types::SeError::new(
            se_types::Detail::DeadlineExceeded(se_types::details::DeadlineExceeded {
                op: "provider transcript readiness".into(),
                deadline_ms: expired.deadline_ms,
            }),
        ),
        _ => failure,
    }
}
/// The capture source from the pinned transcript; a Codex launch with capture
/// suppressed still records a logical vendor source.
fn transcript_capture(
    work: &Work,
    plan: &se_core::ops::agent_launch::LaunchPlan,
    conversation: &se_types::ProviderSessionId,
) -> Result<Option<process_commit::CaptureActivation>> {
    let capture = work
        .transcript
        .as_ref()
        .zip(work.capture_source)
        .map(|(pin, source)| process_commit::CaptureActivation {
            source,
            native_ref: pin.conversation.to_string(),
            incarnation: pin.file_identity.as_bytes().to_vec(),
        });
    if plan.profile.provider == se_store::Provider::Codex && capture.is_none() {
        return Ok(Some(process_commit::CaptureActivation {
            source: process_commit::credential_id(plan, "capture-source")?,
            native_ref: conversation.as_str().to_owned(),
            // With capture suppressed this is a logical vendor source,
            // never a file-incarnation claim or authority to read bytes.
            incarnation: <sha2::Sha256 as sha2::Digest>::digest(conversation.as_str().as_bytes())
                .to_vec(),
        }));
    }
    Ok(capture)
}
/// An SE Code or ACP launch captures through its live binding instead of a
/// transcript, and records that source on the lifecycle.
fn bound_capture(
    work: &mut Work,
    plan: &se_core::ops::agent_launch::LaunchPlan,
    conversation: &se_types::ProviderSessionId,
    secode_binding: Option<&se_core::ops::SecodeBindingView>,
    capture: Option<process_commit::CaptureActivation>,
) -> Result<Option<process_commit::CaptureActivation>> {
    let capture = if let Some(binding) = secode_binding {
        let source = process_commit::credential_id(plan, "capture-source")?;
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
    if plan.profile.provider != se_store::Provider::Acp {
        return Ok(capture);
    }
    let source = process_commit::credential_id(plan, "capture-source")?;
    work.capture_source = Some(source);
    Ok(Some(process_commit::CaptureActivation {
        source,
        native_ref: conversation.to_string(),
        incarnation: crate::harness::acp::bound(
            work.binding
                .as_ref()
                .ok_or_else(|| error("ACP capture", "binding absent"))?,
        )?
        .source()?,
    }))
}
/// The harness policy notice, joined with the replacement notice when a
/// forced live override could not resume the saved conversation.
fn harness_policy_notice(
    work: &Work,
    plan: &se_core::ops::agent_launch::LaunchPlan,
) -> Result<Option<String>> {
    let forced_notice = if plan.input.override_live
        && !plan.input.fresh()
        && matches!(plan.control.resume_session, Read::Present { .. })
    {
        match &plan.conversation {
            Read::Absent { checked } => Some(checked.clone()),
            _ => None,
        }
    } else {
        None
    };
    let policy_notice = work
        .binding
        .as_ref()
        .ok_or_else(|| error("provider launch status", "binding absent"))?
        .policy_notice()?;
    Ok(match (policy_notice, forced_notice) {
        (Some(policy), Some(replacement)) => Some(format!("{policy} {replacement}")),
        (policy, replacement) => policy.or(replacement),
    })
}
