//! One durable, elapsed-time status per original phone message.
use super::{service::*, *};
use crate::client::lease::Deadline;
use se_core::store_error::store_error;
use se_store::{
    Snapshot,
    channel::{Change, Pairing},
};
use se_types::{IdempotencyKey, Result};
impl Channels {
    pub(super) async fn queue_delays(&self, id: ChannelId, deadline: &Deadline) -> Result<()> {
        let state = self.connection(id.clone(), deadline).await?;
        if !matches!(state.pairing, Pairing::Paired { .. }) {
            return Ok(());
        }
        let at = now()?;
        let messages = self
            .read(Some(state.target.project.clone()), deadline, move |cx| {
                cx.read
                    .channel_due_delays(&id, at)
                    .map_err(|e| store_error(&e))
            })
            .await?;
        for message in messages {
            let key = IdempotencyKey::new(format!("channel-delay-{}-{message}", state.id))
                .map_err(|_| channel_error(ChannelError::InvalidInput))?;
            let change = Change::DelayQueued {
                connection: state.id.clone(),
                binding_revision: state.revision,
                message: message.clone(),
            };
            self.change(
                state.target.project.clone(),
                intent("channel.delay", key, &change)?,
                change,
                deadline,
            )
            .await?;
            self.offer_resume(&state, message, deadline).await?;
        }
        Ok(())
    }
}
