//! A short-lived native stdio client offers mail without putting bodies or
//! credentials in process arguments. Queue acceptance is never recipient read.
use super::*;
pub fn offer(
    registration: &Registration,
    conversation: &se_types::ProviderSessionId,
    frame: &Value,
) -> Result<()> {
    let executable = registration.provider.to_local()?;
    let config_home = registration.config_home.to_local()?;
    let text =
        serde_json::to_string(frame).map_err(|_| invalid("serializable native mail offer"))?;
    let conversation = conversation.to_string();
    // The outer protected offer journal is committed before this call. The
    // provider does not deduplicate client IDs: unknown acceptance must never
    // cause automatic replay, even with an unchanged client message identity.
    let mut hash = Sha256::new();
    hash.update(b"codex-observed-mail/v1");
    hash.update(&conversation);
    hash.update(&text);
    let client_id = format!("se-mail-{}", se_types::hex_lower(&hash.finalize()));
    let input = json!([{"type":"text","text":text,"text_elements":[]}]);
    let result = super::rpc::call(
        executable,
        config_home,
        std::env::current_dir().map_err(io)?,
        "thread/queue/add",
        json!({
            "threadId":conversation,"clientUserMessageId":client_id,"input":input
        }),
    )?;
    let queued = result
        .get("queuedSubmission")
        .ok_or_else(|| invalid("a native queue receipt; acceptance is unconfirmed"))?;
    if queued.get("clientUserMessageId").and_then(Value::as_str) != Some(&client_id)
        || queued.get("input") != Some(&input)
        || !queued.get("id").and_then(Value::as_str).is_some_and(|id| {
            !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control)
        })
    {
        return Err(invalid(
            "an exact native queue receipt; acceptance is unconfirmed",
        ));
    }
    Ok(())
}
