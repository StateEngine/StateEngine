//! The retained stream-json input port. Successful writing proves an offer;
//! captured user input and recipient dispositions are verified by the host.
use super::*;

impl ClaudeHarness {
    pub(crate) async fn offer_mail(
        &self,
        binding: &HarnessBinding,
        text: &se_types::Body,
        cx: CallContext,
    ) -> Result<ProviderSessionId> {
        let binding = claude_binding(binding)?;
        write_frame(binding, text, &cx).await?;
        Ok(binding.conversation.clone())
    }
}
