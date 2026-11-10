//! A successful pipe write is an offer; canonical input capture settles delivery.
use super::*;
pub(crate) struct InputFailure {
    pub error: SeError,
    pub completed_bytes: Option<u32>,
}
impl AcpHarness {
    pub(crate) async fn offer_mail(
        &self,
        binding: &HarnessBinding,
        conversation: &ProviderSessionId,
        text: &Body,
        key: &str,
        cx: CallContext,
    ) -> std::result::Result<u64, InputFailure> {
        let unsent = |error| InputFailure {
            error,
            completed_bytes: Some(0),
        };
        let binding = bound(binding).map_err(unsent)?;
        let observed = binding.session.observe().map_err(unsent)?;
        if observed.conversation.as_deref() != Some(conversation.as_str())
            || observed.active_input.is_some()
            || observed.cancelling
        {
            return Err(unsent(error("mail requires the exact idle conversation")));
        }
        // The existing durable offer receipt has an eight-KiB byte bound.
        // Check the longest possible request ID before crossing stdio.
        if crate::acp::prompt_frame_bytes(u64::MAX, conversation.as_str(), text.as_str())
            .map_err(unsent)?
            > 8192
        {
            return Err(unsent(error(
                "mail frame exceeds the eight-KiB offer bound",
            )));
        }
        let id = binding
            .session
            .prompt_tracked(key.into(), text.as_str().into(), cx)
            .await
            .map_err(|failure| InputFailure {
                error: failure.error,
                completed_bytes: failure.completed_bytes,
            })?;
        // The write has completed; a later accounting failure cannot turn it
        // back into a not-sent offer.
        crate::acp::prompt_frame_bytes(id, conversation.as_str(), text.as_str()).map_err(|error| {
            InputFailure {
                error,
                completed_bytes: None,
            }
        })
    }
}
