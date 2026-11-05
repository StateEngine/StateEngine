//! Mail IDs returned by the product work on the first call; legacy callers stay valid.
use se_core::ops::{decode_tool, mcp_tools};
use se_types::MessageId;
use serde_json::{Value, json};

type Check = Result<(), Box<dyn std::error::Error>>;
const TOOLS: [&str; 3] = [
    "stateengine_msg_read",
    "stateengine_msg_ack",
    "stateengine_msg_dismiss",
];

#[test]
fn mail_discovery_advertises_the_receipt_spelling() -> Check {
    let tools = mcp_tools()?;
    for name in TOOLS {
        let tool = tools.iter().find(|tool| tool.name == name).ok_or(name)?;
        assert!(tool.input_schema["properties"]["message_id"].is_object());
        assert!(tool.input_schema["properties"].get("msg_id").is_none());
        assert_eq!(tool.input_schema["required"], json!(["message_id"]));
        assert_eq!(tool.input_schema["additionalProperties"], false);
    }
    Ok(())
}

#[test]
fn both_mail_spellings_decode_to_the_same_message() -> Check {
    let id = MessageId::from_parts(1, [7; 10])?;
    for tool in TOOLS {
        for spelling in ["message_id", "msg_id"] {
            let operation = decode_tool(tool, json!({spelling: id}))?;
            let encoded = serde_json::to_value(operation)?;
            assert_eq!(encoded["input"]["message_id"], json!(id));
            assert!(encoded["input"].get("msg_id").is_none());
        }
    }
    Ok(())
}

#[test]
fn malformed_ambiguous_and_unrelated_mail_fields_still_refuse() -> Check {
    let id = MessageId::from_parts(1, [7; 10])?;
    for tool in TOOLS {
        for arguments in [
            json!({}),
            json!({"message_id": Value::Null}),
            json!({"message_id": "not-a-message"}),
            json!({"msg_id": "not-a-message"}),
            json!({"message_id": id, "msg_id": id}),
            json!({"message_id": id, "unknown": true}),
        ] {
            assert!(
                decode_tool(tool, arguments.clone()).is_err(),
                "{tool}: {arguments}"
            );
        }
    }
    assert!(decode_tool("stateengine_status", json!({"message_id": id})).is_err());
    Ok(())
}
