//! Pending is retained request metadata, never an activated launch receipt.
use se_core::ops::{AgentLaunch, AnyOutput, decode_tool, mcp_tools};
use se_types::{AgentId, IdempotencyKey, LifecycleId, ProjectId, SessionId};
use serde_json::{Value, json};

type Check = Result<(), Box<dyn std::error::Error>>;

fn reply(state: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let agent = AgentId::from_parts(1, [1; 10])?;
    let project = ProjectId::from_parts(1, [2; 10])?;
    let session = SessionId::from_parts(1, [3; 10])?;
    let lifecycle = LifecycleId::from_parts(1, [4; 10])?;
    let key = IdempotencyKey::new("pending-reply-test")?;
    Ok(json!({
        "schema": AgentLaunch::META.family.schema(),
        "state": state,
        "idempotency_key": key,
        "lifecycle_id": lifecycle,
        "session_id": session,
        "project": {"id": project, "name": "Test project"},
        "agent": {"id": agent, "name": "Test agent"},
        "provider": "claude",
        "retry": {
            "target_agent_id": agent,
            "new": false,
            "model": null,
            "task": "Complete the original request",
            "detach": false,
            "idempotency_key": key
        },
        "retry_command": null
    }))
}

#[test]
fn both_pending_states_round_trip_without_running_facts() -> Check {
    for state in ["starting", "setup-needed"] {
        let value = reply(state)?;
        let output: AnyOutput = serde_json::from_value(value.clone())?;
        assert!(matches!(output, AnyOutput::AgentLaunch(_)));
        let encoded = serde_json::to_value(output)?;
        assert_eq!(encoded, value);
        for field in ["event_id", "conversation_id", "process", "containment"] {
            assert!(encoded.get(field).is_none(), "{field}: {encoded}");
        }
    }
    Ok(())
}

#[test]
fn pending_retry_decodes_as_the_same_attended_operation() -> Check {
    let value = reply("setup-needed")?;
    let output: AnyOutput = serde_json::from_value(value.clone())?;
    let encoded = serde_json::to_value(output)?;
    let operation = decode_tool("stateengine_agent_launch", encoded["retry"].clone())?;
    let decoded = serde_json::to_value(operation)?;
    assert_eq!(decoded["op"], "agent.launch");
    assert_eq!(decoded["input"], value["retry"]);
    assert_eq!(
        decoded["input"]["idempotency_key"],
        value["idempotency_key"]
    );
    assert_eq!(decoded["input"]["target_agent_id"], value["agent"]["id"]);
    assert_eq!(decoded["input"]["detach"], false);
    Ok(())
}

#[test]
fn incomplete_running_and_invented_pending_facts_do_not_decode() -> Check {
    for state in ["running", "setup-expired", "unknown"] {
        assert!(serde_json::from_value::<AnyOutput>(reply(state)?).is_err());
    }
    for field in ["event_id", "conversation_id", "process", "containment"] {
        let mut value = reply("starting")?;
        value[field] = Value::Null;
        assert!(
            serde_json::from_value::<AnyOutput>(value).is_err(),
            "{field}"
        );
    }
    Ok(())
}

#[test]
fn pending_followup_does_not_add_an_owner_only_status_tool() -> Check {
    let tools = mcp_tools()?;
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "stateengine_agent_launch")
    );
    assert!(
        !tools
            .iter()
            .any(|tool| tool.name == "stateengine_agent_show")
    );
    Ok(())
}
