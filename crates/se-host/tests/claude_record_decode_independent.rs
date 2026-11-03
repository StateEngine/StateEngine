//! Production decoder: metadata and tool evidence must not become chat prose.
//! Public capture publication is exercised separately by capture_chat_independent.
#[path = "../src/runtime/capture/claude.rs"]
mod claude;

use se_types::{ProviderSessionId, Result};
use serde_json::{Value, json};

fn conversation() -> Result<ProviderSessionId> {
    ProviderSessionId::new("independent-h05-conversation")
}

fn decode(record: Value) -> Result<Option<claude::TextRecord>> {
    let bytes = serde_json::to_vec(&record)
        .map_err(|_| se_types::SeError::invalid("judge JSON", "a serializable fixture"))?;
    claude::decode(&bytes, &conversation()?)
}

fn user(content: Value) -> Value {
    json!({
        "type":"user", "sessionId":"independent-h05-conversation", "uuid":"native-user-item",
        "message":{"role":"user", "content":content}
    })
}

#[test]
fn ownership_tools_and_request_shape_records_are_metadata() -> Result<()> {
    for kind in [
        "session-owner",
        "tools-used",
        "api-request-shape",
        "api-request",
    ] {
        let record = json!({
            "type":kind, "sessionId":"independent-h05-conversation",
            "owner":"native-owner", "tools":["Read","Write"], "requestId":"request-1"
        });
        assert!(decode(record)?.is_none(), "metadata became chat: {kind}");
    }
    Ok(())
}

#[test]
fn request_cache_accepts_its_envelope_and_refuses_disguised_text_records() -> Result<()> {
    for role in ["system", "user", "assistant"] {
        for content in [
            json!("REQUEST_CACHE_SECRET"),
            json!([{"type":"text","text":"REQUEST_CACHE_SECRET"}]),
        ] {
            let record = json!({"type":"api-request-blob", "hash":"ab".repeat(32),
                "message":{"role":role,"content":content}});
            assert!(
                decode(record.clone())?.is_none(),
                "cached API text became chat"
            );
            let mut text_record = record.clone();
            text_record["uuid"] = json!("turn-shaped-cache");
            assert!(
                decode(text_record).is_err(),
                "a turn-shaped cache envelope was discarded"
            );
            let mut wrong_hash = record;
            wrong_hash["hash"] = json!("not-a-sha256");
            assert!(
                decode(wrong_hash).is_err(),
                "a malformed cache envelope was discarded"
            );
        }
    }
    Ok(())
}

#[test]
fn tool_replies_are_dropped_and_mixed_user_prose_keeps_its_identity() -> Result<()> {
    for tool_content in [
        json!("TOOL_SECRET"),
        json!([{"type":"text","text":"TOOL_SECRET"}]),
    ] {
        let tool = json!({"type":"tool_result","tool_use_id":"call-1","content":tool_content});
        assert!(
            decode(user(json!([tool.clone()])))?.is_none(),
            "tool-only output became a user turn"
        );
        let record = decode(user(json!([
            tool, {"type":"text","text":"real user π"}, {"type":"text","text":" and café"}
        ])))?
        .ok_or_else(|| se_types::SeError::invalid("mixed user record", "retained prose"))?;
        assert_eq!(record.text.as_str(), "real user π and café");
        assert_eq!(record.vendor_turn, "native-user-item");
        assert_eq!(record.role, se_store::Role::User);
        assert!(!record.text.as_str().contains("TOOL_SECRET"));
    }
    Ok(())
}

#[test]
fn assistant_text_survives_known_non_chat_blocks() -> Result<()> {
    let record = decode(json!({
        "type":"assistant", "sessionId":"independent-h05-conversation", "uuid":"native-assistant-item",
        "message":{"role":"assistant","content":[
            {"type":"thinking","thinking":"PRIVATE_REASONING"},
            {"type":"tool_use","name":"Read","input":{"path":"PRIVATE_PATH"}},
            {"type":"fallback"}, {"type":"text","text":"visible assistant λ"}
        ]}
    }))?.ok_or_else(|| se_types::SeError::invalid("assistant record", "visible prose"))?;
    assert_eq!(record.text.as_str(), "visible assistant λ");
    assert_eq!(record.vendor_turn, "native-assistant-item");
    assert_eq!(record.role, se_store::Role::Assistant);
    Ok(())
}

#[test]
fn message_bearing_metadata_and_mismatched_conversations_refuse() -> Result<()> {
    for kind in [
        "session-owner",
        "tools-used",
        "api-request-shape",
        "api-request",
    ] {
        assert!(
            decode(json!({"type":kind, "message":{"role":"user","content":"MUST_NOT_DISAPPEAR"}}))
                .is_err()
        );
        assert!(decode(json!({"type":kind, "content":"MUST_NOT_DISAPPEAR"})).is_err());
        assert!(decode(json!({"type":kind, "sessionId":"another-conversation"})).is_err());
    }
    let mut wrong_session = user(json!("visible"));
    wrong_session["sessionId"] = json!("another-conversation");
    assert!(decode(wrong_session).is_err());
    let mut wrong_role = user(json!("visible"));
    wrong_role["message"]["role"] = json!("assistant");
    assert!(decode(wrong_role).is_err());
    Ok(())
}

#[test]
fn malformed_tool_results_and_unknown_blocks_refuse() {
    for content in [
        Value::Null,
        json!(42),
        json!([{"type":"image","source":"unknown"}]),
        json!([{"type":"text"}]),
    ] {
        assert!(decode(user(json!([{"type":"tool_result","content":content}]))).is_err());
    }
    assert!(
        decode(user(
            json!([{"type":"new-provider-block","text":"MUST_NOT_DISAPPEAR"}])
        ))
        .is_err()
    );
}

#[test]
fn unknown_record_names_are_escaped_bounded_and_explicitly_truncated() -> Result<()> {
    let kind = "λ\n\"".repeat(20_000);
    let error = decode(json!({"type":kind}))
        .err()
        .ok_or_else(|| se_types::SeError::invalid("unknown record", "an explicit refusal"))?;
    let message = error.to_string();
    assert!(
        message.len() < 1200,
        "unknown-record refusal grew to {} bytes",
        message.len()
    );
    assert!(
        message.contains("truncated"),
        "unknown record omitted its truncation notice"
    );
    assert!(
        !message.contains('\n'),
        "unknown record injected a diagnostic line"
    );
    assert!(
        message.contains("\\n") && message.contains("\\\""),
        "unknown record lost diagnostic escaping"
    );
    assert!(
        message.contains("preserve the old cursor"),
        "schema drift omitted the recovery boundary"
    );
    Ok(())
}
