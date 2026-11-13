//! Observe user-owned sessions through explicit registration and native proof.
//! The same bounded writer and pinned capture consumer serve managed sessions.
use super::*;
use crate::{
    adoption::{Action, NativeCall},
    client::lease::Deadline,
};
use se_core::{admission::read_scope, commit::Cx, dispatch::Kernel, ops, store_error::store_error};
use se_store::{Actor, Admission, AtomicBatch, Snapshot};
use se_types::{Read, Result};
use serde_json::json;
use sha2::{Digest, Sha256};

impl HostedRouter {
    async fn adoption_read<T: Send + 'static>(
        &self,
        admission: Admission,
        deadline: &Deadline,
        work: impl FnOnce(&Kernel, &mut Cx<'_, se_store::SqliteSnapshot>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let reads = self.execution.reads.clone();
        let generation = self.execution.generation;
        self.execution
            .blocking
            .run_owned(deadline, move || {
                let phase = executor::checked_pooled_phase(&reads, generation)?;
                let mut read = phase
                    .into_snapshot(read_scope(&admission))
                    .map_err(|e| store_error(&e))?;
                let result = work(
                    &Kernel::new(start::allocate_facts()?)?,
                    &mut Cx {
                        read: &mut read,
                        admission: &admission,
                    },
                );
                executor::close_read(result, read.close())
            })
            .await
    }
    async fn adoption_commit(&self, batch: Option<AtomicBatch>, deadline: &Deadline) -> Result<()> {
        if let Some(batch) = batch {
            let identity = failure::WriteIdentity {
                operation: "session.observe",
                natural_key: None,
                key: batch.request.as_ref().map(|r| r.key.clone()),
                natural_events: vec![],
            };
            submit::submit(&self.execution, batch, &identity, deadline).await?;
        }
        Ok(())
    }
    fn adoption_capture(&self) -> CaptureHandle {
        CaptureHandle::from_router(self)
    }
    pub(crate) async fn execute_adoption(
        &self,
        call: NativeCall,
        deadline: &Deadline,
    ) -> Result<crate::OperationOutput> {
        self.check_open()?;
        let NativeCall { input, provider } = call;
        let identity = observed_identity(&input, &provider, self.execution.generation)?;
        let _serial = if input.action == Action::Mail {
            None
        } else {
            Some(
                super::pool::within(
                    deadline,
                    self.sources
                        .observed_serial(&identity.session)?
                        .lock_owned(),
                )
                .await?,
            )
        };
        let owner = Admission {
            actor: Actor::Human(self.context.owner.clone()),
            scope: se_store::Scope::Project(input.project.clone()),
            session: None,
            generation: self.execution.generation.get(),
        };
        let admitted = Admission {
            actor: Actor::Agent(identity.agent.clone()),
            scope: owner.scope.clone(),
            session: Some(identity.session.clone()),
            generation: owner.generation,
        };
        let mut state = "observed";
        if !matches!(input.action, Action::Mail | Action::End) {
            state = self
                .capture_observed(&input, &identity, &owner, &admitted, deadline)
                .await?;
        }
        let mail = if input.action == Action::Mail {
            let (page, ended) = self
                .observed_mail(&input, &identity, &owner, &admitted, deadline)
                .await?;
            if ended {
                state = "ended";
            }
            Some(page)
        } else {
            None
        };
        if input.action == Action::End {
            self.end_observed(
                &input,
                &provider,
                identity.clone(),
                owner,
                admitted,
                deadline,
            )
            .await?;
            state = "ended";
        }
        Ok(crate::OperationOutput {
            schema: "se.adoption/1".into(),
            value: json!({"state":state,"agent":identity.agent,"session":identity.session,"mail":mail}),
            window: None,
        })
    }
    async fn ensure_observed_agent(
        &self,
        owner: &Admission,
        agent: se_types::AgentId,
        kind: crate::adoption::Kind,
        deadline: &Deadline,
    ) -> Result<()> {
        let selected = agent.clone();
        let config = self.context.configuration.clone().unwrap_or_default();
        let batch = self
            .adoption_read(owner.clone(), deadline, move |_, cx| {
                match cx
                    .read
                    .principal(Actor::Agent(selected.clone()))
                    .map_err(|e| store_error(&e))?
                {
                    Read::Present { .. } => return Ok(None),
                    Read::Absent { .. } => (),
                    other => {
                        se_core::scope::require_present(
                            other,
                            "observed agent",
                            "Restore the original agent registration.",
                        )?;
                    }
                }
                let mut facts = start::allocate_facts()?;
                facts.agent = selected.clone();
                let kernel = Kernel::new(facts)?;
                ops::agent::create(
                    &kernel,
                    ops::AgentCreate {
                        harness: None,
                        name: format!(
                            "{}-{}",
                            kind.name(),
                            &selected.as_str()[se_types::AgentId::PREFIX.len()..]
                        ),
                        provider: Some(kind.policy()),
                        model: None,
                        idempotency_key: format!("observe-agent-{selected}").parse()?,
                    },
                    &config,
                    cx,
                )
                .map(|(batch, _)| Some(batch))
            })
            .await?;
        self.adoption_commit(batch, deadline).await
    }
    async fn capture_observed(
        &self,
        input: &crate::adoption::Input,
        identity: &crate::SessionIdentity,
        owner: &Admission,
        admitted: &Admission,
        deadline: &Deadline,
    ) -> Result<&'static str> {
        let agent = identity.agent.clone();
        let session = identity.session.clone();
        let kind = input.kind;
        self.ensure_observed_agent(owner, agent.clone(), kind, deadline)
            .await?;
        let handle = self.adoption_capture();
        // The path is derived by native admission, then opened readonly and
        // retained by identity. No claimed hook path becomes read authority.
        let path = input.transcript.to_local()?;
        let pin = self
            .execution
            .blocking
            .run_owned(deadline, move || {
                se_proc::NativeSourcePin::open(&path).map_err(crate::adoption::native)
            })
            .await?;
        if let Some(pin) = pin {
            let incarnation = pin.identity().to_vec();
            let binding = ops::adoption::Binding {
                agent: agent.clone(),
                session: session.clone(),
                conversation: input.conversation.clone(),
                incarnation,
            };
            let batch = self
                .adoption_read(owner.clone(), deadline, move |kernel, cx| {
                    ops::adoption::bind_provider(kernel, binding, kind.provider(), cx)
                })
                .await?;
            self.adoption_commit(batch, deadline).await?;
            if matches!(handle.binding(identity.clone())?, Read::Absent { .. }) {
                let source =
                    ops::process_commit::session_credential_id(&session, "capture-source")?;
                handle
                    .bind(
                        crate::TranscriptPin {
                            identity: identity.clone(),
                            conversation: input.conversation.clone(),
                            path: input.transcript.clone(),
                            file_identity: se_types::Sha256::from_bytes(pin.identity()),
                        },
                        source,
                        pin,
                        deadline,
                    )
                    .await?;
            }
            if input.action != Action::Start {
                handle
                    .catch_up(
                        admitted.clone(),
                        input.conversation.clone(),
                        input.transcript.clone(),
                        deadline,
                    )
                    .await?;
            }
        } else {
            return Ok("awaiting-provider-transcript");
        }
        Ok("observed")
    }
    async fn observed_mail(
        &self,
        input: &crate::adoption::Input,
        identity: &crate::SessionIdentity,
        owner: &Admission,
        admitted: &Admission,
        deadline: &Deadline,
    ) -> Result<(ops::MessagePage, bool)> {
        let agent = identity.agent.clone();
        let session = identity.session.clone();
        let changed = std::sync::Arc::new(tokio::sync::Notify::new());
        let signal = std::sync::Arc::new(super::mail::NativeSignal::new(changed.clone()));
        self.execution.mail_waits.register_native(
            super::MailRecipient {
                project: input.project.clone(),
                agent: agent.clone(),
            },
            &signal,
        )?;
        // Register before reading, then arm the notification before the
        // dirty check. A committed message cannot fall between those steps.
        let cursor = input.cursor.clone();
        let page = self
            .adoption_read(admitted.clone(), deadline, move |_, cx| {
                ops::inbox::read(
                    ops::MessageInbox {
                        agent: None,
                        full: true,
                        limit: 20,
                        preview_chars: None,
                        cursor,
                    },
                    cx,
                )
            })
            .await?;
        if page.page.next().is_none()
            && page
                .page
                .items()
                .iter()
                .all(|row| input.offered.contains(&row.id) || row.notification.intent == "quiet")
        {
            let notified = changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !signal
                .dirty
                .swap(false, std::sync::atomic::Ordering::AcqRel)
            {
                let wait = deadline
                    .remaining()?
                    .saturating_sub(std::time::Duration::from_secs(2))
                    .min(std::time::Duration::from_secs(20));
                let _ = tokio::time::timeout(wait, notified).await;
            }
        }
        // SessionEnd may arrive while this read is waiting. An ended
        // binding closes the provider-owned background hook immediately.
        let selected = session.clone();
        let ended = self
            .adoption_read(owner.clone(), deadline, move |_, cx| {
                match cx.read.session(selected).map_err(|e| store_error(&e))? {
                    Read::Present { value } => Ok(matches!(
                        value.current.body,
                        se_store::EventBody::SessionEnded { .. }
                            | se_store::EventBody::SessionRevoked { .. }
                    )),
                    Read::Absent { .. } => Ok(false),
                    other => se_core::scope::require_present(
                        other,
                        "observed session retirement",
                        "Restore the saved session.",
                    )
                    .map(|_| false),
                }
            })
            .await?;
        Ok((page, ended))
    }
    async fn end_observed(
        &self,
        input: &crate::adoption::Input,
        provider: &se_proc::native_ipc::NativeIpcPeer,
        identity: crate::SessionIdentity,
        owner: Admission,
        admitted: Admission,
        deadline: &Deadline,
    ) -> Result<()> {
        let agent = identity.agent.clone();
        let session = identity.session.clone();
        let handle = self.adoption_capture();
        if matches!(handle.binding(identity.clone())?, Read::Present { .. }) {
            handle
                .catch_up(
                    admitted.clone(),
                    input.conversation.clone(),
                    input.transcript.clone(),
                    deadline,
                )
                .await?;
        }
        let selected = session.clone();
        let batch = self
            .adoption_read(owner, deadline, move |kernel, cx| {
                match cx
                    .read
                    .session(selected.clone())
                    .map_err(|e| store_error(&e))?
                {
                    Read::Absent { .. } => Ok(None),
                    _ => ops::adoption::end(kernel, selected, cx),
                }
            })
            .await?;
        self.adoption_commit(batch, deadline).await?;
        self.execution
            .mail_waits
            .committed(&[super::MailRecipient {
                project: input.project.clone(),
                agent: agent.clone(),
            }])?;
        handle.retire(identity, false, deadline).await?;
        crate::adoption::metadata::forget(
            &self.execution.state_directory,
            self.execution.generation,
            provider,
            input,
        )?;
        Ok(())
    }
}
impl AdmittedExchange {
    pub(crate) async fn reply_adoption(
        self,
        output: Result<crate::OperationOutput>,
        deadline: &Deadline,
    ) -> Result<HostedConnection> {
        let mut connection = self.connection;
        let result = match output {
            Ok(output) => crate::IpcResult::Output(Box::new(output)),
            Err(error) => crate::IpcResult::Error(se_types::ErrorEnvelope::new(
                error.body,
                &se_types::RenderCx::default(),
            )?),
        };
        connection
            .connection
            .reply(
                &crate::IpcResponse {
                    version: se_types::API_VERSION,
                    request_id: self.request_id,
                    generation: connection.connection.negotiated().generation,
                    result,
                },
                deadline,
            )
            .await?;
        Ok(connection)
    }
}

fn observed_identity(
    input: &crate::adoption::Input,
    provider: &se_proc::native_ipc::NativeIpcPeer,
    generation: se_types::Generation,
) -> Result<crate::SessionIdentity> {
    let mut agent_seed = Sha256::new();
    agent_seed.update(format!("observed-{}-agent/v1", input.kind.name()));
    agent_seed.update(input.project.as_str());
    agent_seed.update(input.conversation.as_str());
    let agent_hash = agent_seed.finalize();
    let project_bytes = input
        .project
        .canonical_bytes()?
        .ok_or_else(|| crate::adoption::invalid("a canonical registered project identity"))?;
    let mut clock = [0; 8];
    clock[2..].copy_from_slice(&project_bytes[..6]);
    let stamp = u64::from_be_bytes(clock);
    let mut random = [0; 10];
    random.copy_from_slice(&agent_hash[6..16]);
    let agent = se_types::AgentId::from_parts(stamp, random)?;
    let mut session_seed = Sha256::new();
    session_seed.update(format!("observed-{}-session/v1", input.kind.name()));
    session_seed.update(agent.as_str());
    session_seed.update(provider.binding());
    session_seed.update(generation.get().to_le_bytes());
    let session_hash = session_seed.finalize();
    random.copy_from_slice(&session_hash[6..16]);
    let session = se_types::SessionId::from_parts(stamp, random)?;
    Ok(crate::SessionIdentity {
        project: input.project.clone(),
        agent,
        session,
    })
}
