//! Expiring phone confirmation reuses the existing native launch coordinator.
use super::{service::*, *};
use crate::client::lease::Deadline;
use se_core::{
    dispatch::Kernel,
    ops::{AgentLaunch, agent_launch::LaunchPlan},
    scope,
    store_error::store_error,
};
use se_store::{
    EventBody, Snapshot,
    channel::{ActionId, Change, Connection, Pairing, ResumeAction, ResumeTarget},
};
use se_types::{IdempotencyKey, MessageId, Read, Result};
use sha2::{Digest, Sha256};
impl Channels {
    pub(super) fn resume_configuration(&self, policy: &ChannelPolicy) -> Result<Option<[u8; 32]>> {
        match policy {
            ChannelPolicy::SaveOnly => Ok(None),
            ChannelPolicy::ConfirmResume {
                cost_limit: Some(_),
                ..
            } => Err(channel_error(ChannelError::Unsupported)),
            ChannelPolicy::ConfirmResume { .. } => {
                let configuration = self
                    .configuration
                    .as_ref()
                    .ok_or_else(|| channel_error(ChannelError::Unsupported))?;
                let bytes = serde_json::to_vec(configuration)
                    .map_err(|_| channel_error(ChannelError::InvalidInput))?;
                Ok(Some(Sha256::digest(bytes).into()))
            }
        }
    }
    pub(super) async fn validate_resume_consent(
        &self,
        input: &ConnectTelegram,
        deadline: &Deadline,
    ) -> Result<()> {
        let ChannelPolicy::ConfirmResume {
            profile,
            profile_revision,
            ..
        } = &input.policy
        else {
            return Ok(());
        };
        if !self.supports_resume() {
            return Err(channel_error(ChannelError::Unsupported));
        }
        self.resume_configuration(&input.policy)?;
        let selected = input.target.clone();
        let profile = profile.clone();
        let revision = *profile_revision;
        self.read(Some(selected.project),deadline,move|cx| {
            let target=scope::require_present(cx.read.control_target(selected.agent).map_err(|e|store_error(&e))?,"phone lifecycle target","Select a saved Rust agent.")?;
            let saved=scope::require_present(target.profile,"phone lifecycle profile","Save its existing profile natively.")?;
            let EventBody::ProfileSaved{profile:current,..}=saved.current.body else{return Err(channel_error(ChannelError::InvalidInput))};
            if saved.revision.value.get()!=revision || current.named_profile!=profile || target.principal.revision.value.get()!=selected.selection_revision {return Err(channel_error(ChannelError::RevisionConflict));}
            if current.provider==se_store::Provider::SeCode {return Err(channel_error(ChannelError::Unsupported));}
            if let Read::Present{value}=target.latest_session {
                let original=value.original.as_deref().unwrap_or(&value.current);
                if !matches!(&original.body,EventBody::SessionPrepared{provider,..} if *provider==current.provider) {return Err(channel_error(ChannelError::Unsupported));}
            }
            Ok(())
        }).await
    }
    async fn resume_plan(
        &self,
        state: &Connection,
        key: IdempotencyKey,
        deadline: &Deadline,
    ) -> Result<LaunchPlan> {
        let ChannelPolicy::ConfirmResume {
            profile,
            profile_revision,
            cost_limit: None,
        } = &state.policy
        else {
            return Err(channel_error(ChannelError::Unsupported));
        };
        if self.resume_configuration(&state.policy)? != state.resume_configuration {
            return Err(channel_error(ChannelError::RevisionConflict));
        }
        let configuration = self
            .configuration
            .clone()
            .ok_or_else(|| channel_error(ChannelError::Unsupported))?;
        let profile = profile.clone();
        let profile_revision = *profile_revision;
        let selected = state.target.clone();
        self.read(Some(selected.project.clone()), deadline, move |cx| {
            let kernel = Kernel::new(crate::runtime::start::allocate_facts()?)?
                .with_configuration(configuration.clone())?;
            let plan = se_core::ops::process_plan::launch(
                &kernel,
                AgentLaunch {
                    target_agent_id: Some(selected.agent),
                    fresh: false,
                    model: None,
                    task: None,
                    detach: true,
                    override_live: false,
                    force_selection: None,
                    idempotency_key: key,
                    owner_agent: None,
                    owner_provider: None,
                },
                &configuration,
                cx,
            )?;
            let saved = scope::require_present(
                plan.control.profile.as_ref(),
                "phone lifecycle profile",
                "Refresh the native channel grant.",
            )?;
            if plan.control.principal.revision.value.get() != selected.selection_revision
                || saved.revision.value.get() != profile_revision
                || plan.profile.named_profile != profile
            {
                return Err(channel_error(ChannelError::RevisionConflict));
            }
            if !plan.control.sessions.is_empty() || !plan.control.processes.is_empty() {
                return Err(channel_error(ChannelError::Unsupported));
            }
            if matches!(plan.control.latest_session, Read::Present { .. })
                && !matches!(plan.conversation, Read::Present { .. })
            {
                return Err(channel_error(ChannelError::Unsupported));
            }
            Ok(plan)
        })
        .await
    }
    pub(super) async fn offer_resume(
        &self,
        state: &Connection,
        message: MessageId,
        deadline: &Deadline,
    ) -> Result<()> {
        if matches!(state.policy, ChannelPolicy::SaveOnly) {
            return Ok(());
        }
        let id = state.id.clone();
        let original = message.clone();
        let exists = self
            .read(Some(state.target.project.clone()), deadline, move |cx| {
                cx.read
                    .channel_message_action(&id, &original)
                    .map_err(|e| store_error(&e))
            })
            .await?;
        match exists {
            Read::Present { .. } => return Ok(()),
            Read::Absent { .. } => {}
            other => {
                scope::require_present(
                    other,
                    "phone lifecycle action",
                    "Restore native channel access.",
                )?;
            }
        }
        let agent = state.target.agent.clone();
        let stopped = self
            .read(Some(state.target.project.clone()), deadline, move |cx| {
                let target = scope::require_present(
                    cx.read.control_target(agent).map_err(|e| store_error(&e))?,
                    "phone resume target",
                    "Choose the saved Rust agent.",
                )?;
                Ok(target.sessions.is_empty() && target.processes.is_empty())
            })
            .await?;
        if !stopped {
            return Ok(());
        }
        let key = IdempotencyKey::new(format!("phone-resume-{}-{message}", state.id))
            .map_err(|_| channel_error(ChannelError::InvalidInput))?;
        let plan = self.resume_plan(state, key, deadline).await?;
        let previous_session_event = match &plan.control.latest_session {
            Read::Present { value } => Some(value.current.header.event.clone()),
            Read::Absent { .. } => None,
            _ => return Err(channel_error(ChannelError::Unsupported)),
        };
        let conversation = match plan.conversation {
            Read::Present { value } => Some(value),
            Read::Absent { .. } => None,
            _ => return Err(channel_error(ChannelError::Unsupported)),
        };
        let profile = scope::require_present(
            plan.control.profile,
            "phone profile",
            "Refresh the native channel grant.",
        )?;
        let Pairing::Paired { phone } = &state.pairing else {
            return Err(channel_error(ChannelError::BindingRevoked));
        };
        let random = se_proc::random_secret()
            .map_err(|_| channel_error(ChannelError::CredentialStoreUnavailable))?;
        let action = ResumeAction {
            id: ActionId::new(format!(
                "cha-{}",
                se_types::hex_lower(&random.expose()[..16])
            ))
            .map_err(|_| channel_error(ChannelError::InvalidInput))?,
            connection: state.id.clone(),
            binding_revision: state.revision,
            message: message.clone(),
            target: ResumeTarget {
                principal_revision: plan.control.principal.revision.value.get(),
                profile_revision: profile.revision.value.get(),
                previous_session_event,
                conversation,
                configuration: state
                    .resume_configuration
                    .ok_or_else(|| channel_error(ChannelError::Unsupported))?,
            },
            subject: phone.subject,
            private_chat: phone.private_chat,
            expires_at_us: now()?.saturating_add(300000000),
            state: "offered".into(),
            code: None,
        };
        let key = IdempotencyKey::new(format!("phone-offer-{}-{message}", state.id))
            .map_err(|_| channel_error(ChannelError::InvalidInput))?;
        let change = Change::ResumeOffered { action };
        self.change(
            state.target.project.clone(),
            intent("channel.resume.offer", key, &change)?,
            change,
            deadline,
        )
        .await?;
        Ok(())
    }
    pub(super) async fn run_resumes(&self, id: ChannelId, deadline: &Deadline) -> Result<()> {
        let state = self.connection(id.clone(), deadline).await?;
        let actions = self
            .read(Some(state.target.project.clone()), deadline, move |cx| {
                cx.read
                    .channel_confirmed_actions(&id)
                    .map_err(|e| store_error(&e))
            })
            .await?;
        for action in actions {
            let gate = self.output_gate(&state.id)?;
            let _release = tokio::time::timeout(deadline.remaining()?, gate.lock_owned())
                .await
                .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))?;
            let result = self.execute_resume(&state, &action, deadline).await;
            if let Err(error) = result {
                let change = Change::ResumeFailed {
                    connection: state.id.clone(),
                    action: action.id.clone(),
                    code: match error.body.detail() {
                        se_types::Detail::MessagingChannelRefused(detail) => detail.reason.code(),
                        _ => error.code().as_str(),
                    }
                    .into(),
                };
                let key = IdempotencyKey::new(format!("phone-resume-failed-{}", action.id))
                    .map_err(|_| channel_error(ChannelError::InvalidInput))?;
                self.change(
                    state.target.project.clone(),
                    intent("channel.resume.failed", key, &change)?,
                    change,
                    deadline,
                )
                .await?;
            }
        }
        Ok(())
    }
    async fn execute_resume(
        &self,
        state: &Connection,
        action: &ResumeAction,
        deadline: &Deadline,
    ) -> Result<()> {
        if action.binding_revision != state.revision || action.expires_at_us <= now()? {
            return Err(channel_error(ChannelError::RevisionConflict));
        }
        let key = IdempotencyKey::new(format!("phone-resume-{}-{}", state.id, action.message))
            .map_err(|_| channel_error(ChannelError::InvalidInput))?;
        let mut plan = self.resume_plan(state, key, deadline).await?;
        let previous = match &plan.control.latest_session {
            Read::Present { value } => Some(value.current.header.event.clone()),
            Read::Absent { .. } => None,
            _ => return Err(channel_error(ChannelError::Unsupported)),
        };
        let conversation = match &plan.conversation {
            Read::Present { value } => Some(value.clone()),
            Read::Absent { .. } => None,
            _ => return Err(channel_error(ChannelError::Unsupported)),
        };
        if previous != action.target.previous_session_event
            || conversation != action.target.conversation
        {
            return Err(channel_error(ChannelError::RevisionConflict));
        }
        plan.channel_resume = Some((state.id.clone(), action.id.clone()));
        let coordinator = self
            .context
            .custody
            .get()
            .ok_or_else(|| channel_error(ChannelError::Unsupported))?;
        coordinator
            .execute(
                se_core::ports::CustodyPlan::Launch(Box::new(plan)),
                self.admission(Some(state.target.project.clone()))?,
                deadline,
            )
            .await?;
        Ok(())
    }
}

impl Channels {
    pub(super) async fn resume_keyboard(
        &self,
        state: &Connection,
        output: &se_store::channel::Outbound,
        deadline: &Deadline,
    ) -> Result<Option<serde_json::Value>> {
        if output.kind != "resume" {
            return Ok(None);
        }
        let message = output
            .original
            .clone()
            .ok_or_else(|| channel_error(ChannelError::InvalidInput))?;
        let id = state.id.clone();
        let action = self
            .read(Some(state.target.project.clone()), deadline, move |cx| {
                cx.read
                    .channel_message_action(&id, &message)
                    .map_err(|e| store_error(&e))
            })
            .await?;
        let action = scope::require_present(
            action,
            "phone resume offer",
            "Inspect its original native action.",
        )?;
        if action.state != "offered" || action.expires_at_us <= now()? {
            return Ok(None);
        }
        Ok(Some(
            serde_json::json!({"inline_keyboard":[[{"text":"Start/resume selected agent","callback_data":format!("r:{}",action.id)}]]}),
        ))
    }
}
