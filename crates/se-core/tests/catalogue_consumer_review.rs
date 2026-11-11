//! Independent controls through the public discovery and argument decoder.
use se_core::ops::{decode_tool, mcp_tools, schema_catalogue};
use se_types::{Class, Code, Detail, MessageId};
use serde_json::{Value, json};

type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn refusal(tool: &str, arguments: Value) -> Check {
    let error = match decode_tool(tool, arguments) {
        Ok(_) => return Err(format!("{tool} accepted malformed arguments").into()),
        Err(error) => error,
    };
    assert_eq!(error.body.code().class(), Class::Usage, "{tool}: {error}");
    assert!(!error.body.detail().message().trim().is_empty(), "{tool}");
    match error.body.detail() {
        Detail::InputUnknownField(detail) => {
            assert!(!detail.next_step.trim().is_empty(), "{tool}");
        }
        Detail::UsageInvalidValue(detail) => {
            assert!(!detail.argument.trim().is_empty(), "{tool}");
            assert!(!detail.expected.trim().is_empty(), "{tool}");
        }
        _ => assert!(!error.to_string().trim().is_empty(), "{tool}"),
    }
    Ok(())
}

#[test]
fn every_discovered_tool_refuses_unknown_fields_and_non_object_input() -> Check {
    let tools = mcp_tools()?;
    assert!(!tools.is_empty());
    for tool in tools {
        let error = match decode_tool(tool.name, json!({"unadvertised_argument":true})) {
            Ok(_) => return Err(format!("{} admitted an unknown field", tool.name).into()),
            Err(error) => error,
        };
        assert_eq!(error.body.code(), Code::InputUnknownField, "{}", tool.name);
        match error.body.detail() {
            Detail::InputUnknownField(detail) => {
                assert_eq!(detail.field, "unadvertised_argument");
                assert!(!detail.op.is_empty() && !detail.next_step.is_empty());
            }
            _ => return Err("unknown field lost its typed explanation".into()),
        }
        for input in [json!([1, 2]), json!("not an argument object")] {
            refusal(tool.name, input)?;
        }
    }
    Ok(())
}

#[test]
fn actual_value_grammars_remain_enforced_after_discovery_trim() -> Check {
    for (tool, arguments) in [
        ("stateengine_event_read", json!({"event_id":""})),
        ("stateengine_msg_read", json!({"message_id":"bad id"})),
        ("stateengine_msg_ack", json!({"message_id":"bad id"})),
        ("stateengine_msg_dismiss", json!({"message_id":"bad id"})),
        ("stateengine_msg_list", json!({"limit":0})),
        (
            "stateengine_msg_send",
            json!({"to":"recipient","body":"","idempotency_key":"synthetic-review-send"}),
        ),
        (
            "stateengine_msg_send",
            json!({"to":"floor","body":"work","idempotency_key":"synthetic-review-floor"}),
        ),
        (
            "stateengine_working_state_set",
            json!({"text":"note","expect":0,"idempotency_key":"synthetic-review-state"}),
        ),
        (
            "stateengine_agent_create",
            json!({"name":"","idempotency_key":"synthetic-review-create"}),
        ),
        (
            "stateengine_agent_launch",
            json!({"force":"yes","idempotency_key":"synthetic-review-launch"}),
        ),
        (
            "stateengine_agent_stop",
            json!({"target_agent_id":"bad id","idempotency_key":"synthetic-review-stop"}),
        ),
        ("stateengine_resume", json!({"byte_budget":1})),
        ("stateengine_atlas_find", json!({"query":"work","limit":0})),
        ("stateengine_atlas_refs", json!({"target":"src/example.rs"})),
        (
            "stateengine_atlas_impact",
            json!({"target":{"File":"src/example.rs"},"depth":0}),
        ),
        (
            "stateengine_atlas_changes",
            json!({"since":"not-a-baseline"}),
        ),
        ("stateengine_atlas_outline", json!({"path":"","limit":0})),
    ] {
        refusal(tool, arguments)?;
    }
    let message = MessageId::from_parts(1, [5; 10])?;
    for name in [
        "stateengine_msg_read",
        "stateengine_msg_ack",
        "stateengine_msg_dismiss",
    ] {
        for field in ["message_id", "msg_id"] {
            decode_tool(name, json!({field:message}))?;
        }
    }
    for target in [
        json!({"File":"src/example.rs"}),
        json!({"Symbol":{"Name":{"name":"example"}}}),
    ] {
        for name in ["stateengine_atlas_refs", "stateengine_atlas_impact"] {
            decode_tool(name, json!({"target":target}))?;
        }
    }
    Ok(())
}

#[test]
fn launch_guidance_only_names_the_accepted_live_replacement_argument() -> Check {
    let tools = mcp_tools()?;
    let launch = tools
        .iter()
        .find(|tool| tool.name == "stateengine_agent_launch")
        .ok_or("launch absent")?;
    assert!(launch.input_schema["properties"].get("force").is_some());
    assert!(
        launch.input_schema["properties"]
            .get("override_live")
            .is_none()
    );
    let canonical = decode_tool(
        launch.name,
        json!({"force":true,"idempotency_key":"synthetic-review-force"}),
    )?;
    assert_eq!(serde_json::to_value(canonical)?["input"]["force"], true);
    let old = decode_tool(
        launch.name,
        json!({"override_live":true,"idempotency_key":"synthetic-review-force"}),
    );
    assert!(matches!(old, Err(ref error) if error.body.code() == Code::InputUnknownField));
    assert!(
        !launch.description.contains("override_live"),
        "catalogue tells the agent to send override_live, but the actual decoder refuses it; use its advertised force field"
    );
    Ok(())
}

#[test]
fn discovery_keeps_registered_tools_and_accepts_nullable_choices() -> Check {
    let tools = mcp_tools()?;
    let encoded = serde_json::to_vec(&tools)?;
    println!(
        "catalogue bytes: {}; tool count: {}",
        encoded.len(),
        tools.len()
    );
    let names: std::collections::BTreeSet<_> = tools.iter().map(|tool| tool.name).collect();
    let registered = schema_catalogue(None)?;
    let expected = registered
        .ops
        .iter()
        .filter(|op| op.metadata["mcp"]["kind"] == "tool")
        .map(|op| {
            op.metadata["mcp"]["name"]
                .as_str()
                .ok_or("registered tool has no name".into())
        })
        .collect::<Check<std::collections::BTreeSet<_>>>()?;
    assert_eq!(names, expected);
    for (name, arguments) in [
        (
            "stateengine_atlas_find",
            json!({"query":"work","mode":null}),
        ),
        (
            "stateengine_atlas_find",
            json!({"query":"work","mode":"exact"}),
        ),
        (
            "stateengine_agent_create",
            json!({"name":"example","provider":null,"idempotency_key":"synthetic-review-create"}),
        ),
    ] {
        decode_tool(name, arguments)?;
    }
    if let Some(path) = std::env::var_os("CATALOGUE_REVIEW_EVIDENCE") {
        std::fs::write(path, encoded)?;
    }
    Ok(())
}
