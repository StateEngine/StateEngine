//! The retained stream-json input port. A complete write proves only an offer.
use super::*;

pub(crate) struct MailWriteFailure {
    pub error: SeError,
    /// None means the platform did not prove how many bytes crossed the pipe.
    pub completed_bytes: Option<u32>,
}
impl MailWriteFailure {
    fn unsent(error: SeError) -> Self {
        Self {
            error,
            completed_bytes: Some(0),
        }
    }
}
impl ClaudeHarness {
    pub(crate) async fn offer_mail(
        &self,
        binding: &HarnessBinding,
        conversation: &ProviderSessionId,
        text: &se_types::Body,
        cx: CallContext,
    ) -> std::result::Result<(), MailWriteFailure> {
        let binding = claude_binding(binding).map_err(MailWriteFailure::unsent)?;
        if binding.attended {
            return Err(MailWriteFailure::unsent(SeError::invalid(
                "Claude attended mail",
                "the provider-native attended mail route; console input is never manufactured",
            )));
        }
        if &binding.conversation != conversation {
            return Err(MailWriteFailure::unsent(SeError::invalid(
                "mail target",
                "the exact retained provider conversation before writing stdin",
            )));
        }
        let frame = claude::input_frame(text).map_err(MailWriteFailure::unsent)?;
        let expected = frame.len();
        let written = binding
            .io
            .write(&binding.transport, frame, cx)
            .await
            .map_err(|error| MailWriteFailure {
                error,
                completed_bytes: None,
            })?;
        match written.failure {
            None if written.completed_bytes as usize == expected => Ok(()),
            failure => Err(MailWriteFailure {
                error: failure.map(SeError::from).unwrap_or_else(|| {
                    SeError::invalid(
                        "mail input",
                        "a complete stream-json frame; retain an incomplete write as uncertain",
                    )
                }),
                completed_bytes: Some(written.completed_bytes),
            }),
        }
    }
}
