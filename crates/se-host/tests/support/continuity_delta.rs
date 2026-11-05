//! The real store packet fitter and MCP wire fitter must retain what changed.
use super::*;
use se_core::ops::AnyOp;
use se_host::mcp::{McpBackend, McpReply};
use se_types::{SeError, Secret};
use serde_json::{Value, json};

struct Backend(Harness);
impl McpBackend for Backend {
    async fn check_session(&mut self, _: Arc<Secret>) -> se_types::Result<()> {
        Ok(())
    }
    async fn call(&mut self, _: Arc<Secret>, op: AnyOp) -> se_types::Result<Value> {
        let AnyOp::Resume(input) = op else {
            return Err(SeError::invalid("delta test", "resume only"));
        };
        let h = &self.0;
        let output = h
            .resume(h.scope(&h.f.a, Some(h.a.clone())), input)
            .map_err(|e| se_core::scope::unreadable("fixture", &e.to_string()))??;
        let mut output = serde_json::to_value(output)
            .map_err(|e| se_core::scope::unreadable("fixture output", &e.to_string()))?;
        output["schema"] = json!("se.resume/v1");
        Ok(output)
    }
    fn response_limit(&self) -> usize {
        1_048_576
    }
}

#[test]
fn mcp_since_keeps_new_capture_before_older_context() -> Check {
    for (short_state, trailing_user, long_answer) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (true, false, true),
    ] {
        let mut h = Harness::new()?;
        if short_state {
            h.direct.append(
                h.f.working(
                    "private A state: phase two complete; verify my work.",
                    revision(1)?,
                    "delta-short-state",
                )?,
                &*h.lease,
            )?;
        }
        let baseline = h.resume(
            h.scope(&h.f.a, Some(h.a.clone())),
            resume_request(32768, None),
        )??;
        for (offset, expected, marker) in [(60, 7, "delta-first"), (70, 8, "delta-latest-🦊\"\\")]
        {
            let mut batch =
                capture::capture(&h.f, &h.a, h.source, b"first", offset, expected, marker)?;
            for event in &mut batch.events {
                if let EventBody::SessionTurn { role, text, .. } = &mut event.body {
                    if trailing_user && offset == 70 {
                        *role = Role::User;
                    }
                    if long_answer && offset == 70 {
                        *text = InputText::Inline("captured delta-latest 🦊\"\\".repeat(100));
                    }
                }
            }
            h.direct.append(batch, &*h.lease)?;
        }
        let before = h.head()?;
        let mut input = resume_request(4096, None);
        input.since = Some(baseline.cursor.clone());
        let wanted = if trailing_user {
            "delta-first"
        } else {
            "delta-latest"
        };
        let cli = h.resume(h.scope(&h.f.a, Some(h.a.clone())), input.clone())??;
        assert!(cli.recent_turns.iter().any(|t| t.preview.contains(wanted)));
        let mut backend = Backend(h);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let request = serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "id":"delta-\"-🦊", "method":"tools/call",
            "params":{"name":"stateengine_resume","arguments":input}
        }))?;
        let McpReply::Json(response) = runtime.block_on(se_host::mcp::dispatch(
            &request,
            Some(Arc::new(Secret::new(vec![1; 32])?)),
            &mut backend,
        )) else {
            return Err("missing MCP response".into());
        };
        assert_ne!(
            response["result"]["isError"], true,
            "short_state={short_state}, trailing_user={trailing_user}, long_answer={long_answer}; {response}; CLI={cli:?}"
        );
        let bytes = serde_json::to_vec(&response)?.len() + 1;
        assert!(bytes <= 4096, "MCP exceeded its complete wire budget");
        let packet: Value = serde_json::from_str(
            response["result"]["content"][0]["text"]
                .as_str()
                .ok_or("text")?,
        )?;
        assert_eq!(packet["budget"]["used_bytes"], bytes);
        assert_recovery_argv(&packet)?;
        assert_eq!(packet["principal"]["agent"]["id"], backend.0.f.a.as_str());
        assert_eq!(packet["since"], baseline.cursor.as_str());
        assert!(
            packet["working_state"]["value"]["text"]
                .as_str()
                .ok_or("state")?
                .starts_with("private A state")
        );
        assert_eq!(
            packet["unread"]["items"][0]["body"]["text"],
            "unread A packet marker"
        );
        let turns = packet["recent_turns"].as_array().ok_or("turns")?;
        if long_answer {
            assert!(
                turns.iter().any(|turn| turn["complete"] == false),
                "large answer claimed complete"
            );
            assert!(
                packet["omissions"]
                    .as_array()
                    .ok_or("omissions")?
                    .iter()
                    .any(|item| item["section"] == "recent_turn_content")
            );
        }
        for omitted in packet["omissions"].as_array().ok_or("omissions")? {
            if omitted["section"] == "recovery_commands" {
                assert!(
                    omitted["command"]
                        .as_str()
                        .ok_or("command")?
                        .contains(baseline.cursor.as_str()),
                    "expanded recovery lost since cursor"
                );
            }
        }
        assert!(
            turns.iter().any(|t| t["role"] == "assistant"
                && t["preview"].as_str().is_some_and(|s| s.contains(wanted))),
            "lost new capture: {packet}"
        );
        assert!(
            !turns.iter().any(|t| t["preview"]
                .as_str()
                .is_some_and(|s| s.contains("packet-turn"))),
            "since leaked old turns"
        );
        let omitted: u64 = packet["omissions"]
            .as_array()
            .ok_or("omissions")?
            .iter()
            .filter(|v| v["section"] == "recent_turns")
            .map(|v| v["count"].as_u64().unwrap_or(0))
            .sum();
        assert_eq!(turns.len() as u64 + omitted, 2);
        assert_eq!(
            backend.0.head()?,
            before,
            "resume wrote or acknowledged mail"
        );
        backend.0.finish()?;
    }
    Ok(())
}

fn assert_recovery_argv(value: &Value) -> Check {
    match value {
        Value::Object(fields) => {
            if let Some(command) = fields.get("command").and_then(Value::as_str)
                && !command.is_empty()
            {
                let argv = serde_json::from_value::<Vec<String>>(fields["argv"].clone())?;
                let rendered =
                    se_core::ops::AgentCommand::from_argv(argv).ok_or("invalid recovery argv")?;
                assert_eq!(
                    command, rendered.command,
                    "wire recovery command and argv diverged"
                );
            }
            for child in fields.values() {
                assert_recovery_argv(child)?;
            }
        }
        Value::Array(items) => {
            for child in items {
                assert_recovery_argv(child)?;
            }
        }
        _ => (),
    }
    Ok(())
}
