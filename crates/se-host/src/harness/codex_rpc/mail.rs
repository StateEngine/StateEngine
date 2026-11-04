//! Serialized real app-server input. A successful RPC is vendor acceptance;
//! delivery still requires the matching user item committed by capture.
use super::*;
pub(crate) struct InputFailure {
    pub error: SeError,
    pub completed_bytes: Option<u32>,
}
impl CodexHarness {
    pub(crate) async fn offer_mail(
        &self,
        binding: &HarnessBinding,
        conversation: &ProviderSessionId,
        text: &se_types::Body,
        key: &str,
        cx: CallContext,
    ) -> std::result::Result<String, InputFailure> {
        let unsent = |error| InputFailure {
            error,
            completed_bytes: Some(0),
        };
        let binding = bound(binding).map_err(unsent)?;
        if binding.conversation().map_err(unsent)? != *conversation {
            return Err(unsent(SeError::invalid(
                "Codex mail target",
                "the exact retained provider thread",
            )));
        }
        let input = tokio::time::timeout(cx.timeout, binding.input.lock())
            .await
            .map_err(|_| {
                unsent(incompatible(
                    "input queue deadline expired",
                    "Retry after the current serialized input finishes.",
                ))
            })?;
        let active = binding.active_turn().map_err(unsent)?;
        let (method, mut params) = match active {
            Some(turn) => (
                "turn/steer",
                input::steer(conversation, &turn, text).map_err(unsent)?,
            ),
            None => (
                "turn/start",
                json!({"threadId":conversation.as_str(),"input":[{"type":"text","text":text.as_str()}]}),
            ),
        };
        params["clientUserMessageId"] = json!(format!(
            "se-{}",
            se_types::hex_lower(&Sha256::digest(key.as_bytes()))
        ));
        let result = binding
            .request(method, params, &cx)
            .await
            .map_err(|error| InputFailure {
                error,
                completed_bytes: None,
            })?;
        if method == "turn/start" {
            binding
                .accept_turn_response(&result)
                .map_err(|error| InputFailure {
                    error,
                    completed_bytes: None,
                })?;
        }
        let turn = result
            .pointer("/turn/id")
            .or_else(|| result.get("turnId"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 512)
            .ok_or_else(|| InputFailure {
                error: SeError::invalid("Codex input response", "the actual accepted turn ID"),
                completed_bytes: None,
            })?;
        drop(input);
        Ok(turn.to_owned())
    }
}
