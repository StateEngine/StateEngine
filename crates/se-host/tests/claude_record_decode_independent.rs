//! Protects: metadata stays separate from chat while malformed known chat still refuses.
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
        metadata(record, kind)?;
    }
    Ok(())
}

fn metadata(value: Value, kind: &str) -> Result<()> {
    let record = decode(value)?
        .ok_or_else(|| se_types::SeError::invalid("metadata", "a durable System record"))?;
    assert_eq!(record.role, se_store::Role::System);
    let body: Value = serde_json::from_str(record.text.as_str())
        .map_err(|_| se_types::SeError::invalid("metadata", "JSON"))?;
    assert_eq!(body["schema"], "se.transcript-event/v1");
    assert_eq!(body["kind"], kind);
    assert!(!record.text.as_str().contains("REQUEST_CACHE_SECRET"));
    assert!(!record.text.as_str().contains("MUST_NOT_DISAPPEAR"));
    Ok(())
}

#[test]
fn request_cache_is_metadata_even_when_it_contains_provider_text() -> Result<()> {
    for kind in ["api-request-blob", "queue-operation"] {
        for role in ["system", "user", "assistant"] {
            for content in [
                json!("REQUEST_CACHE_SECRET"),
                json!([{"type":"text","text":"REQUEST_CACHE_SECRET"}]),
            ] {
                let record = json!({"type":kind, "operation":"dequeue", "hash":"ab".repeat(32), "message":{"role":role,"content":content}});
                metadata(record.clone(), kind)?;
                let mut with_uuid = record.clone();
                with_uuid["uuid"] = json!("turn-shaped-cache");
                metadata(with_uuid, kind)?;
                let mut unknown_cache_shape = record;
                unknown_cache_shape["hash"] = json!("not-a-sha256");
                metadata(unknown_cache_shape, kind)?;
                metadata(
                    json!({"type":kind,"operation":"dequeue","content":"REQUEST_CACHE_SECRET"}),
                    kind,
                )?;
            }
        }
    }
    Ok(())
}

/// Protects: queue input is not discarded when no later native user record exists.
#[test]
fn queued_enqueue_input_is_retained_with_queue_provenance() -> Result<()> {
    let record = decode(json!({
        "type":"queue-operation", "operation":"enqueue",
        "sessionId":"independent-h05-conversation",
        "timestamp":"2026-11-04T00:00:00.000Z",
        "content":"QUEUED_INPUT_MUST_SURVIVE"
    }))?
    .ok_or_else(|| se_types::SeError::invalid("queued input", "a retained record"))?;
    assert!(
        record.text.as_str().contains("QUEUED_INPUT_MUST_SURVIVE"),
        "queued input payload was dropped"
    );
    assert!(
        record.text.as_str().contains("queue") || record.vendor_turn.contains("queue"),
        "queued input lost its distinct provenance"
    );
    Ok(())
}

#[test]
fn metadata_only_queue_records_need_no_text_but_present_invalid_text_refuses() -> Result<()> {
    for operation in ["enqueue", "dequeue"] {
        metadata(
            json!({"type":"queue-operation", "operation":operation}),
            "queue-operation",
        )?;
    }
    for content in [Value::Null, json!(42), json!([]), json!("")] {
        assert!(
            decode(json!({"type":"queue-operation", "operation":"enqueue", "content":content}))
                .is_err()
        );
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
fn other_noise_payloads_and_mismatched_metadata_sessions_refuse() -> Result<()> {
    for kind in [
        "session-owner",
        "tools-used",
        "api-request-shape",
        "api-request",
        "file-history-snapshot",
    ] {
        assert!(
            decode(json!({"type":kind, "message":{"role":"user","content":"MUST_NOT_DISAPPEAR"}}))
                .is_err(),
            "message-bearing {kind} silently dropped"
        );
        assert!(
            decode(json!({"type":kind, "content":"MUST_NOT_DISAPPEAR"})).is_err(),
            "content-bearing {kind} silently dropped"
        );
    }
    for kind in [
        "api-request-blob",
        "queue-operation",
        "file-history-snapshot",
        "mode",
    ] {
        assert!(
            decode(json!({"type":kind,"operation":"dequeue","sessionId":"another-conversation"}))
                .is_err(),
            "foreign metadata session accepted for {kind}"
        );
        metadata(
            json!({"type":kind,"operation":"dequeue","sessionId":"independent-h05-conversation"}),
            kind,
        )?;
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
fn unknown_record_names_and_payload_are_tolerated_as_metadata() -> Result<()> {
    metadata(
        json!({"type":"future-λ\n\"", "content":"MUST_NOT_DISAPPEAR"}),
        "future-λ\n\"",
    )?;
    Ok(())
}

/// Protects: malformed JSON and known message shapes still refuse after metadata tolerance.
#[test]
fn malformed_json_and_known_message_shapes_still_refuse() -> Result<()> {
    for kind in ["user", "assistant"] {
        for value in [
            json!({"type":kind}),
            json!({"type":kind,"sessionId":"independent-h05-conversation","uuid":"broken"}),
            json!({"type":kind,"sessionId":"independent-h05-conversation","uuid":"broken","message":{"role":kind}}),
        ] {
            assert!(
                decode(value).is_err(),
                "malformed known {kind} was accepted"
            );
        }
    }
    for value in [
        json!({}),
        json!({"type":42}),
        json!({"type":"User","message":{"role":"user","content":"MUST_NOT_DISAPPEAR"}}),
        json!({"type":"future-chat","message":{"role":"assistant","content":"MUST_NOT_DISAPPEAR"}}),
    ] {
        assert!(
            decode(value).is_err(),
            "ambiguous or future chat-shaped record silently became metadata"
        );
    }
    assert!(claude::decode(b"{broken json}\n", &conversation()?).is_err());
    Ok(())
}
