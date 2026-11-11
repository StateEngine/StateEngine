//! Provider callback acknowledgments do not grant lifecycle or read authority.
use super::{service::*, *};
use crate::client::lease::Deadline;
use se_core::store_error::store_error;
use se_store::{
    EventBody, Snapshot,
    channel::{ActionId, Change, Connection},
};
use se_types::{Read, Result};
impl Channels {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) async fn confirm_resume(
        &self,
        state: &Connection,
        input: &IncomingContent,
        request: &se_store::RequestIdentity,
        update: ExternalId,
        cursor: ReceiveCursor,
        deadline: &Deadline,
    ) -> Result<bool> {
        let IncomingContent::Callback {
            phone,
            data,
            callback_id,
        } = input
        else {
            return Ok(false);
        };
        let Some(id) = data.strip_prefix("r:") else {
            return Ok(false);
        };
        let Ok(id) = ActionId::new(id) else {
            return Ok(false);
        };
        let connection = state.id.clone();
        let selected = id.clone();
        let action = self
            .read(Some(state.target.project.clone()), deadline, move |cx| {
                cx.read
                    .channel_action(&connection, &selected)
                    .map_err(|e| store_error(&e))
            })
            .await?;
        let Read::Present { value: action } = action else {
            return Ok(false);
        };
        if action.state != "offered"
            || action.subject != phone.subject
            || action.private_chat != phone.private_chat
            || action.expires_at_us <= now()?
        {
            return Ok(false);
        }
        if action.binding_revision != state.revision
            || self.resume_configuration(&state.policy)? != Some(action.target.configuration)
        {
            return Ok(false);
        }
        let target = state.target.agent.clone();
        let current = self
            .read(Some(state.target.project.clone()), deadline, move |cx| {
                let target = se_core::scope::require_present(
                    cx.read
                        .control_target(target)
                        .map_err(|e| store_error(&e))?,
                    "phone lifecycle target",
                    "Inspect its saved state natively.",
                )?;
                let profile = se_core::scope::require_present(
                    target.profile.as_ref(),
                    "phone profile",
                    "Refresh native approval.",
                )?;
                let previous = match &target.latest_session {
                    Read::Present { value } => Some(value.current.header.event.clone()),
                    Read::Absent { .. } => None,
                    _ => return Err(channel_error(ChannelError::Unsupported)),
                };
                Ok((
                    target.principal.revision.value.get(),
                    profile.revision.value.get(),
                    previous,
                    target.sessions.is_empty() && target.processes.is_empty(),
                ))
            })
            .await?;
        if current.0 != action.target.principal_revision
            || current.1 != action.target.profile_revision
            || current.2 != action.target.previous_session_event
            || !current.3
        {
            return Ok(false);
        }
        let confirm = Change::ResumeConfirmed {
            connection: state.id.clone(),
            action: id.clone(),
            subject: phone.subject.clone(),
            private_chat: phone.private_chat.clone(),
        };
        let handled = Change::UpdateHandled {
            connection: state.id.clone(),
            binding_revision: state.revision,
            update,
            cursor: Some(cursor),
            disposition: se_store::channel::Disposition::Action { action: id },
        };
        self.commit(
            state.target.project.clone(),
            request.clone(),
            deadline,
            move |cx| {
                Ok(vec![
                    event(cx, EventBody::ChannelRecorded { change: confirm })?,
                    event(cx, EventBody::ChannelRecorded { change: handled })?,
                ])
            },
        )
        .await?;
        if let Some(callback_id) = callback_id {
            self.ack_callback(state, callback_id, true, deadline)
                .await?;
        }
        Ok(true)
    }
    pub(super) async fn ack_callback(
        &self,
        state: &Connection,
        id: &str,
        accepted: bool,
        deadline: &Deadline,
    ) -> Result<()> {
        let result = async {
            let token = self.token(state.credential.clone(), deadline).await?;
            self.transport(state.connector)?
                .answer_callback(&token, id, accepted)
                .await
                .map_err(channel_error)
        }
        .await;
        if let Err(error) = result {
            self.set_health(
                state.id.clone(),
                ConnectionHealth::Unavailable {
                    code: error.code().as_str().into(),
                },
            )?;
        }
        Ok(())
    }
}
