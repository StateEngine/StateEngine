use super::*;
use super::{launch::Work, launch_util::call};
use crate::{Harness, HarnessAttach, HarnessRequest, client::lease::Deadline};
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
        deadline: &Deadline,
    ) -> Result<LaunchResult> {
        let plan = work.plan.clone().ok_or_else(|| {
            se_core::scope::unreadable(
                "provider attach",
                "only a new owned launch can bind its stdout transport",
            )
        })?;
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
        let outcome = self
            .harness
            .attach(
                HarnessAttach {
                    request,
                    process: attach_owner,
                    record: record.clone(),
                    transport,
                    transcript: Read::Absent {
                        checked: "transcript pin is published after session activation".into(),
                    },
                },
                call(self.store.generation, deadline)?,
            )
            .await?;
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
        work.meta.conversation = Read::Present {
            value: outcome.witness.conversation.clone(),
        };
        let native_pin = if plan.capture {
            let path = crate::claude_transcript_location(
                work.binding
                    .as_ref()
                    .ok_or_else(|| error("capture readiness", "provider binding absent"))?,
            )?;
            let pin = self
                .store
                .pool
                .run_owned(deadline, move || {
                    se_proc::NativeSourcePin::open(&path)
                        .map_err(|e| error("provider transcript pin", e))?
                        .ok_or_else(|| {
                            error(
                                "provider transcript readiness",
                                "the provider has not created its transcript",
                            )
                        })
                })
                .await?;
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
        let previous = self.head(work, deadline).await?;
        let first = loop {
            let changed = work.wake.event.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
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
        let capture = work
            .transcript
            .as_ref()
            .zip(work.capture_source)
            .map(|(pin, source)| process_commit::CaptureActivation {
                source,
                native_ref: pin.conversation.to_string(),
                incarnation: pin.file_identity.as_bytes().to_vec(),
            });
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
        Ok(LaunchResult {
            idempotency_key: plan.input.idempotency_key.clone(),
            event_id: receipt.primary_event,
            launch_id: se_proc::session_launch_id(&plan.session)
                .map_err(|e| error("launch identity", e))?,
            lifecycle_id: plan.lifecycle.clone(),
            project: plan.project.clone(),
            agent: plan.agent.clone(),
            session_id: plan.session.clone(),
            provider: se_types::Provider::Claude,
            model: plan.profile.model.clone(),
            permission_profile: plan.resolved.clone(),
            conversation_id: outcome.witness.conversation,
            state: "running".into(),
            surface: "headless".into(),
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
            containment_cause: match record.guarantee {
                se_proc::ContainmentGuarantee::KernelScope { .. } => None,
                other => Some(format!("{other:?}")),
            },
            resume: ResumeCommand {
                ready: true,
                mode: "resume".into(),
                reason: None,
                command: Some(format!("se launch --agent {} --detach", plan.agent.id)),
                argv: Some(vec![
                    "se".into(),
                    "launch".into(),
                    "--agent".into(),
                    plan.agent.id.to_string(),
                    "--detach".into(),
                ]),
            },
        })
    }
}
