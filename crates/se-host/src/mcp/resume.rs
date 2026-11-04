//! Resume is a read-only tool with one representation and an exact wire budget.
use super::*;
use se_core::ops::{AnyOp, Resume};

pub(super) async fn call(
    backend: &mut impl McpBackend,
    capability: Arc<Secret>,
    id: Value,
    input: Resume,
) -> Value {
    let limit = (input.byte_budget as usize).min(backend.response_limit());
    let response = select(backend, capability, id, input, limit).await;
    let response = budgeted(response, limit.saturating_sub(1));
    // Even an error cannot echo an ID that consumes the whole caller budget.
    if serde_json::to_vec(&response).is_ok_and(|bytes| bytes.len() < limit) {
        response
    } else {
        rpc_error(
            Value::Null,
            -32602,
            "resume response budget cannot contain this request ID; retry with a shorter ID",
        )
    }
}

async fn select(
    backend: &mut impl McpBackend,
    capability: Arc<Secret>,
    id: Value,
    mut input: Resume,
    limit: usize,
) -> Value {
    let mut last_size = limit;
    // A smaller snapshot is another read: it acknowledges no packet or mail.
    // Keep the transport's original deadline and capability on every attempt.
    for _ in 0..8 {
        let output = match backend
            .call(Arc::clone(&capability), AnyOp::Resume(input.clone()))
            .await
        {
            Ok(output) => output,
            Err(error) => return failure(id, &error),
        };
        let response = measured(id.clone(), output, limit);
        let (response, needed) = match response {
            Ok(value) => value,
            Err(error) => return failure(id, &error),
        };
        if needed <= limit {
            return response;
        }
        last_size = needed;
        // Reserve a few bytes for counters whose encoded widths can change.
        let next = (input.byte_budget as usize)
            .saturating_mul(limit)
            .checked_div(needed)
            .unwrap_or(0)
            .saturating_sub(16)
            .max(1024);
        if next >= input.byte_budget as usize {
            break;
        }
        input.byte_budget = next as u32;
    }
    failure(
        id,
        &SeError::too_large("MCP resume response", limit, last_size),
    )
}

fn measured(id: Value, mut output: Value, limit: usize) -> Result<(Value, usize)> {
    let mut used = 0;
    for _ in 0..8 {
        if let Some(budget) = output.get_mut("budget").and_then(Value::as_object_mut) {
            budget.insert("limit_bytes".into(), json!(limit));
            budget.insert("used_bytes".into(), json!(used));
        }
        let response = success(id.clone(), text(&output, false));
        // Stdio's line terminator is included. HTTP has this one-byte reserve.
        let needed = serde_json::to_vec(&response)
            .map_err(|e| se_core::scope::unreadable("MCP resume encoding", &e.to_string()))?
            .len()
            .saturating_add(1);
        if needed == used {
            return Ok((response, needed));
        }
        used = needed;
    }
    Err(se_core::scope::unreadable(
        "MCP resume encoding",
        "wire byte count did not converge",
    ))
}
fn text(output: &Value, is_error: bool) -> Value {
    json!({"content":[{"type":"text","text":output.to_string()}],"isError":is_error})
}
fn failure(id: Value, error: &SeError) -> Value {
    match error_value(error) {
        Ok(output) => success(id, text(&output, true)),
        Err(error) => rpc_error(id, -32603, &error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Backend {
        calls: usize,
    }
    impl McpBackend for Backend {
        async fn check_session(&mut self, _: Arc<Secret>) -> Result<()> {
            Ok(())
        }
        async fn call(&mut self, _: Arc<Secret>, operation: AnyOp) -> Result<Value> {
            let AnyOp::Resume(input) = operation else {
                return Err(SeError::invalid("test read", "resume only"));
            };
            self.calls += 1;
            // Deliberately escape-heavy Unicode: UTF-8 payload bytes alone
            // cannot predict the encoded text or final JSON-RPC size.
            Ok(
                json!({"budget":{"limit_bytes":input.byte_budget,"used_bytes":0},"working_state":"\"\\\n🦊".repeat(input.byte_budget.saturating_sub(200) as usize / 8)}),
            )
        }
        fn response_limit(&self) -> usize {
            1024 * 1024
        }
    }
    fn input() -> Resume {
        Resume {
            limit: 20,
            governing_cursor: None,
            since: None,
            byte_budget: 4096,
            preview_agent: None,
        }
    }
    #[test]
    fn one_representation_counts_escaping_id_and_line_ending()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut backend = Backend { calls: 0 };
        let response = runtime.block_on(call(
            &mut backend,
            Arc::new(Secret::new(vec![1; 32])?),
            json!("quoted-\"-request"),
            input(),
        ));
        let bytes = serde_json::to_vec(&response)?.len() + 1;
        assert!(bytes <= 4096 && backend.calls > 1);
        assert!(response["result"].get("structuredContent").is_none());
        let body: Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .ok_or("missing text")?,
        )?;
        assert_eq!(body["budget"]["used_bytes"], bytes);
        assert_eq!(body["budget"]["limit_bytes"], 4096);
        Ok(())
    }
    #[test]
    fn oversized_request_id_cannot_defeat_the_wire_budget()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let response = runtime.block_on(call(
            &mut Backend { calls: 0 },
            Arc::new(Secret::new(vec![1; 32])?),
            json!("x".repeat(5000)),
            input(),
        ));
        assert!(serde_json::to_vec(&response)?.len() + 1 <= 4096);
        assert!(response["id"].is_null() && response["error"].is_object());
        Ok(())
    }
}
