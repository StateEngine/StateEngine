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
    let original = input.clone();
    let mut floor = 1024;
    let mut smallest = None;
    for _ in 0..8 {
        let output = match backend
            .call(Arc::clone(&capability), AnyOp::Resume(input.clone()))
            .await
        {
            Ok(output) => output,
            Err(error) => {
                if let se_types::Detail::InputTooLarge(detail) = error.body.detail() {
                    let needed = detail.got_bytes as usize;
                    if needed <= se_core::ops::continuity::MAX_BYTES as usize
                        && needed > input.byte_budget as usize
                    {
                        floor = needed;
                        input.byte_budget = needed as u32;
                        continue;
                    }
                    return wire_refusal(id, &original, limit, None, backend.response_limit());
                }
                return failure(id, &error);
            }
        };
        let (response, needed) = match measured(id.clone(), output.clone(), limit) {
            Ok(value) => value,
            Err(error) => return failure(id, &error),
        };
        if needed <= limit {
            return response;
        }
        smallest = Some(output);
        if input.byte_budget as usize <= floor {
            break;
        }
        let next = (input.byte_budget as usize)
            .saturating_mul(limit)
            .checked_div(needed)
            .unwrap_or(0)
            .saturating_sub(16)
            .max(floor);
        input.byte_budget = next.min(input.byte_budget as usize - 1) as u32;
    }
    let needed = smallest.and_then(|output| {
        let mut candidate = limit;
        for _ in 0..8 {
            let (_, needed) = measured(id.clone(), output.clone(), candidate).ok()?;
            if needed == candidate {
                return Some(needed);
            }
            candidate = needed;
        }
        None
    });
    wire_refusal(id, &original, limit, needed, backend.response_limit())
}
fn wire_refusal(
    id: Value,
    input: &Resume,
    limit: usize,
    needed: Option<usize>,
    transport_cap: usize,
) -> Value {
    let cap = (se_core::ops::continuity::MAX_BYTES as usize).min(transport_cap);
    let mut error = match needed {
        Some(needed) => SeError::too_large(
            "MCP resume JSON-RPC wire bytes including the line ending",
            limit,
            needed,
        ),
        None => SeError::invalid(
            &format!("MCP resume budget ({limit} complete wire bytes)"),
            "a separately paged read; no supported complete response was measured",
        ),
    };
    let command = needed.filter(|needed| *needed <= cap).and_then(|needed| {
        let mut retry = input.clone();
        retry.byte_budget = needed as u32;
        serde_json::to_value(retry)
            .ok()
            .map(|args| se_types::Cmd::Tool {
                name: "stateengine_resume".into(),
                args,
            })
    });
    let retry = command.is_some();
    error.body=error.body.with_remedy(se_types::Remedy {
        text:if retry {"Retry stateengine_resume with the measured complete wire budget and the same request ID; this count includes JSON escaping, the ID and newline.".into()}
        else {format!("No supported complete response was measured within the {cap}-byte cap. Read working-state, mail and history separately through their paged tools.")},
        command:Some(command.unwrap_or(se_types::Cmd::Manual)),
    });
    failure(id, &error)
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
        Ok(mut output) => {
            // Raw ErrorBody carries recovery across IPC; the rendered remedy
            // already contains it here, so the transport emits one command.
            if let Some(body) = output.as_object_mut() {
                body.remove("recovery");
            }
            success(id, text(&output, true))
        }
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
    struct Minimum;
    impl McpBackend for Minimum {
        async fn check_session(&mut self, _: Arc<Secret>) -> Result<()> {
            Ok(())
        }
        async fn call(&mut self, _: Arc<Secret>, operation: AnyOp) -> Result<Value> {
            let AnyOp::Resume(input) = operation else {
                return Err(SeError::invalid("test read", "resume only"));
            };
            if input.byte_budget < 2048 {
                return Err(SeError::too_large(
                    "core JSON minimum",
                    input.byte_budget as usize,
                    2048,
                ));
            }
            Ok(
                json!({"budget":{"limit_bytes":input.byte_budget,"used_bytes":0},"working_state":"\\\"".repeat(400),"omissions":[{"section":"working_state","count":499,"reason":"UTF-8 byte budget"}]}),
            )
        }
        fn response_limit(&self) -> usize {
            1048576
        }
    }
    #[test]
    fn shrunk_refusal_names_original_wire_budget_and_replays_at_measured_need()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let capability = Arc::new(Secret::new(vec![1; 32])?);
        let mut request = input();
        request.byte_budget = 2300;
        let mut backend = Minimum;
        let response = runtime.block_on(call(
            &mut backend,
            Arc::clone(&capability),
            json!("same-id"),
            request.clone(),
        ));
        let error: Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .ok_or("missing refusal")?,
        )?;
        assert_eq!(error["detail"]["limit_bytes"], 2300);
        let needed = error["detail"]["got_bytes"]
            .as_u64()
            .ok_or("missing measured wire need")?;
        assert!(needed > 2300);
        assert_eq!(error["remedy"]["command"]["name"], "stateengine_resume");
        let retry: Resume = serde_json::from_value(error["remedy"]["command"]["args"].clone())?;
        assert_eq!(retry.byte_budget as u64, needed);
        let response = runtime.block_on(call(&mut backend, capability, json!("same-id"), retry));
        let output: Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .ok_or("missing success")?,
        )?;
        assert_eq!(response["result"]["isError"], false);
        assert!(serde_json::to_vec(&response)?.len() + 1 <= needed as usize);
        assert_eq!(
            output["omissions"],
            json!([{"section":"working_state","count":499,"reason":"UTF-8 byte budget"}])
        );
        Ok(())
    }
    struct AboveCap;
    impl McpBackend for AboveCap {
        async fn check_session(&mut self, _: Arc<Secret>) -> Result<()> {
            Ok(())
        }
        async fn call(&mut self, _: Arc<Secret>, _: AnyOp) -> Result<Value> {
            Err(SeError::too_large("core JSON minimum", 4096, 1048577))
        }
        fn response_limit(&self) -> usize {
            1048576
        }
    }
    #[test]
    fn unsupported_minimum_has_a_manual_cap_remedy_without_an_invalid_retry()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let response = runtime.block_on(call(
            &mut AboveCap,
            Arc::new(Secret::new(vec![1; 32])?),
            json!(1),
            input(),
        ));
        let error: Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .ok_or("missing refusal")?,
        )?;
        assert_eq!(error["remedy"]["command"]["kind"], "manual");
        assert!(
            error["remedy"]["text"]
                .as_str()
                .is_some_and(|text| text.contains("1048576"))
        );
        assert!(serde_json::to_vec(&response)?.len() + 1 <= 4096);
        Ok(())
    }
}
