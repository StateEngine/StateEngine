//! Rust saved-agent choices carry the exact principal/profile revisions.
//! A Node registration or a cached display row is never a valid selection.
use super::{service::*, *};
use crate::client::lease::Deadline;
use se_core::{ops::agent_status, scope, store_error::store_error};
use se_store::{Actor, Snapshot};
use se_types::{Page, PageRequest, Result, Window};
use std::num::NonZeroU32;
impl Channels {
    pub async fn targets(
        &self,
        input: ChannelTargets,
        deadline: &Deadline,
    ) -> Result<Page<ChannelAgentChoice>> {
        if input.after.as_ref().is_some_and(|c| c.as_str().len() > 512) {
            return Err(channel_error(ChannelError::InvalidInput));
        }
        let remaining = deadline.remaining()?.min(std::time::Duration::from_secs(5));
        let native_resume = self.supports_resume();
        self.read(Some(input.project.clone()), deadline, move |cx| {
            let page = agent_status::page(
                se_store::ReadBudget {
                    page: PageRequest {
                        after: input.after,
                        limit: NonZeroU32::new(100)
                            .ok_or_else(|| channel_error(ChannelError::InvalidInput))?,
                        max_bytes: NonZeroU32::new(200 * 1024)
                            .ok_or_else(|| channel_error(ChannelError::InvalidInput))?,
                    },
                    deadline: remaining,
                },
                cx,
            )?;
            let mut fields = page
                .window()
                .fields()
                .cloned()
                .ok_or_else(|| channel_error(ChannelError::InvalidInput))?;
            let next = page.next().cloned();
            let mut choices = Vec::new();
            for saved in page.into_items() {
                let principal = scope::require_present(
                    cx.read
                        .principal(Actor::Agent(saved.id.clone()))
                        .map_err(|e| store_error(&e))?,
                    "saved agent selection",
                    "Refresh the Rust saved-agent list.",
                )?;
                let profile = scope::require_present(
                    cx.read
                        .profile(saved.id.clone())
                        .map_err(|e| store_error(&e))?,
                    "saved agent profile",
                    "Refresh the Rust saved-agent list.",
                )?;
                let saved_provider=match &profile.current.body {se_store::EventBody::ProfileSaved{profile,..}=>profile.provider,_=>return Err(channel_error(ChannelError::InvalidInput))};
                let target=cx.read.control_target(saved.id.clone()).map_err(|e|store_error(&e))?;
                let available=match target {
                    se_types::Read::Present{value}=>match value.latest_session {
                        se_types::Read::Absent{..}=>native_resume,
                        se_types::Read::Present{value}=>native_resume && matches!(&value.original.as_deref().unwrap_or(&value.current).body,se_store::EventBody::SessionPrepared{provider,..} if *provider==saved_provider && *provider!=se_store::Provider::SeCode),
                        _=>false,
                    },
                    _=>false,
                };
                choices.push(ChannelAgentChoice {
                    target: ChannelTarget {
                        project: input.project.clone(),
                        agent: saved.id.clone(),
                        selection_revision: principal.revision.value.get(),
                    },
                    saved,
                    profile_revision: profile.revision.value.get(),
                    confirmed_resume_supported:available,
                    resume_reason:if available {None}else{Some("Approve start/resume locally in StateEngine; this host cannot perform a scoped phone resume for the selected conversation.".into())},
                });
            }
            fields.bytes = serde_json::to_vec(&choices)
                .map_err(|_| channel_error(ChannelError::InvalidInput))?
                .len() as u64;
            if fields.bytes > 256 * 1024 {
                return Err(channel_error(ChannelError::MessageTooLarge));
            }
            Page::new(choices, Window::new(fields)?, next)
        })
        .await
    }
}
