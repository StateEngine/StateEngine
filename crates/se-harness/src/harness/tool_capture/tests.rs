use super::*;
use serde_json::{Value, json};
type Check = std::result::Result<(), Box<dyn std::error::Error>>;
fn called(id: &str, path: &str) -> Value {
    json!({"type":"assistant","sessionId":"native","cwd":"/native/work",
        "message":{"role":"assistant","content":[{"type":"tool_use","id":id,"name":"Edit",
            "input":{"file_path":path,"new_string":"INTENDED_BYTES_NOT_A_REVISION"}}]}})
}
fn completed(id: &str, error: bool) -> Value {
    json!({"type":"user","sessionId":"native","message":{"role":"user",
        "content":[{"type":"tool_result","tool_use_id":id,"is_error":error,"content":"PRIVATE_TOOL_OUTPUT"}]}})
}
#[test]
fn claude_joins_only_actual_ids_and_keeps_missing_or_conflicting_facts_unknown() -> Check {
    let mut tracker = claude::Tracker::default();
    tracker.observe(&called("call-a", "a.rs"))?;
    tracker.observe(&called("call-b", "b.rs"))?;
    for (id, path) in [("call-b", "b.rs"), ("call-a", "a.rs")] {
        let facts = tracker.observe(&completed(id, false))?;
        let fact = &facts[0];
        assert!(matches!(&fact.native,NativeIdentity::ClaudeCall{tool_use_id} if tool_use_id==id));
        assert!(matches!(fact.outcome, Outcome::Succeeded));
        let Target::Paths(paths) = &fact.target else {
            return Err("actual ID did not join its target".into());
        };
        assert_eq!(paths[0].spelling, path);
        assert_eq!(paths[0].cwd.as_deref(), Some("/native/work"));
        assert!(
            paths[0].content_revision.is_none(),
            "intended Edit content became a revision witness"
        );
    }
    let result = tracker.observe(&completed("unmatched", true))?;
    assert!(matches!(result[0].outcome, Outcome::Failed));
    assert!(matches!(
        result[0].target,
        Target::Unknown(UnknownReason::UnmatchedIdentity)
    ));
    tracker.observe(&called("missing-outcome", "unknown.rs"))?;
    let mut missing = completed("missing-outcome", false);
    missing["message"]["content"][0]
        .as_object_mut()
        .ok_or("block")?
        .remove("is_error");
    assert!(matches!(
        tracker.observe(&missing)?[0].outcome,
        Outcome::Unknown(UnknownReason::NoNativeOutcome)
    ));
    assert!(matches!(
        tracker.observe(&completed("call-b", true))?[0].outcome,
        Outcome::Unknown(UnknownReason::ConflictingEvidence)
    ));
    let conflict = tracker.observe(&called("call-a", "different.rs"))?;
    assert!(matches!(
        conflict[0].target,
        Target::Unknown(UnknownReason::ConflictingEvidence)
    ));
    assert!(matches!(
        tracker.observe(&completed("call-a", false))?[0].outcome,
        Outcome::Unknown(UnknownReason::ConflictingEvidence)
    ));
    let mut cache = called("cache-copy", "not-an-edit");
    cache["type"] = json!("api-request-blob");
    assert!(
        tracker.observe(&cache)?.is_empty(),
        "cached model traffic became another native call"
    );
    let mut shell = called("shell", "ignored");
    shell["message"]["content"][0]["name"] = json!("Bash");
    shell["message"]["content"][0]["input"] = json!({"command":"echo data > forged.rs"});
    assert!(matches!(
        tracker.observe(&shell)?[0].target,
        Target::Command(ref text) if text == "echo data > forged.rs"
    ));
    Ok(())
}
#[test]
fn codex_preserves_item_call_namespaces_and_real_multi_path_outcomes() -> Check {
    let conversation = "native".parse()?;
    let item = json!({"type":"FileChange","id":"item-actual","call_id":"call-distinct","status":"Completed",
        "changes":[{"path":"old.rs","kind":{"type":"update","move_path":"new.rs"},"diff":"INTENDED_PATCH_NOT_CONTENT"}]});
    let native = json!({"type":"event_msg","payload":{"type":"item_completed","thread_id":"native","turn_id":"turn-actual","item":item}});
    let fact = codex::decode(&serde_json::to_vec(&native)?, &conversation)?.ok_or("no tool")?;
    assert!(
        matches!(&fact.native,NativeIdentity::CodexItem{turn_id:Some(turn),item_id:Some(item),call_id:Some(call)} if turn=="turn-actual"&&item=="item-actual"&&call=="call-distinct")
    );
    assert!(matches!(fact.outcome, Outcome::Succeeded));
    let Target::Paths(paths) = &fact.target else {
        return Err("native paths missing".into());
    };
    assert_eq!(
        paths
            .iter()
            .map(|p| p.spelling.as_str())
            .collect::<Vec<_>>(),
        ["new.rs", "old.rs"]
    );
    assert!(paths.iter().all(|p| p.content_revision.is_none()));
    let mut rpc_item = item.clone();
    rpc_item["type"] = json!("fileChange");
    rpc_item["status"] = json!("completed");
    let rpc = json!({"method":"item/completed","params":{"threadId":"native","turnId":"turn-actual","item":rpc_item}});
    let notified = codex::notification(&rpc, &conversation)?.ok_or("no notification")?;
    assert_eq!(fact.key, notified.key);
    let identity = crate::SessionIdentity {
        session: SessionId::from_parts(1, [1; 10])?,
        agent: se_types::AgentId::from_parts(1, [2; 10])?,
        project: se_types::ProjectId::from_parts(1, [3; 10])?,
    };
    let source = <RecordId as se_store::RecordIdentity>::from_parts(1, [4; 10])
        .map_err(|error| se_core::store_error::store_error(&error))?;
    let record = fact.record(
        &identity,
        Provider::Codex,
        source,
        Position {
            offset: 10,
            length: 20,
        },
    )?;
    assert!(notified.matches(record.captured_tool.as_ref().ok_or("metadata")?)?);
    let text = record.body()?;
    assert!(!text.as_str().contains("INTENDED_PATCH_NOT_CONTENT"));
    let mut altered = record.captured_tool.ok_or("metadata")?;
    altered.outcome = Outcome::Failed;
    assert!(!notified.matches(&altered)?);
    Ok(())
}
#[test]
fn codex_unknowns_are_explicit_and_a_large_target_set_is_never_trimmed() -> Check {
    let conversation = "native".parse()?;
    let mut item = json!({"type":"FileChange","id":"file","changes":(0..17).map(|n|json!({"path":format!("{n}.rs")})).collect::<Vec<_>>()});
    let envelope = |item: &Value| json!({"method":"item/completed","params":{"threadId":"native","turnId":"turn","item":item}});
    let fact = codex::notification(&envelope(&item), &conversation)?.ok_or("tool")?;
    assert!(matches!(
        fact.target,
        Target::Unknown(UnknownReason::OverBudget)
    ));
    assert!(matches!(
        fact.outcome,
        Outcome::Unknown(UnknownReason::NoNativeOutcome)
    ));
    item = json!({"type":"mcpToolCall","id":"mcp-item","tool":"search","status":"failed","arguments":{"query":"explicit query"}});
    let fact = codex::notification(&envelope(&item), &conversation)?.ok_or("tool")?;
    assert!(matches!(fact.outcome, Outcome::Failed));
    assert!(matches!(fact.target,Target::Query(ref query) if query=="explicit query"));
    item["arguments"] = json!({"command":"write imaginary.rs"});
    assert!(matches!(
        codex::notification(&envelope(&item), &conversation)?
            .ok_or("tool")?
            .target,
        Target::Unknown(UnknownReason::NoNativeTarget)
    ));
    let mut delta = envelope(&item);
    delta["method"] = json!("item/tool/outputDelta");
    assert!(codex::notification(&delta, &conversation)?.is_none());
    Ok(())
}

fn observed(fact: &Fact) -> Result<Observation> {
    let identity = crate::SessionIdentity {
        session: SessionId::from_parts(1, [1; 10])?,
        agent: se_types::AgentId::from_parts(1, [2; 10])?,
        project: se_types::ProjectId::from_parts(1, [3; 10])?,
    };
    let source = <RecordId as se_store::RecordIdentity>::from_parts(1, [4; 10])
        .map_err(|error| se_core::store_error::store_error(&error))?;
    fact.record(
        &identity,
        Provider::Codex,
        source,
        Position {
            offset: 10,
            length: 20,
        },
    )?
    .captured_tool
    .ok_or_else(|| SeError::invalid("test observation", "captured native tool"))
}
fn notified(item: Value) -> Result<Fact> {
    codex::notification(
        &json!({"method":"item/completed","params":{
            "threadId":"native","turnId":"turn-actual","item":item
        }}),
        &"native".parse()?,
    )?
    .ok_or_else(|| SeError::invalid("test notification", "completed native tool"))
}

#[test]
fn native_path_keyed_file_change_matches_rpc_array_without_inventing_a_revision() -> Check {
    // Actual Codex 0.166 rollout shape from the retained README failure;
    // conversation/item IDs and the path spelling are anonymized.
    let native: Value =
        serde_json::from_str(include_str!("fixtures/codex-file-change-path-map.json"))?;
    let fact =
        codex::decode(&serde_json::to_vec(&native)?, &"native".parse()?)?.ok_or("native tool")?;
    let rpc = notified(
        json!({"type":"fileChange","id":"item-actual","status":"completed",
        "changes":[{"path":"/work/notes.md","kind":{"type":"add"},"diff":"NOT_A_CONTENT_REVISION"}]}),
    )?;
    assert_eq!(fact.key, rpc.key);
    let captured = observed(&fact)?;
    assert!(
        rpc.matches(&captured)?,
        "same native item disagrees across the actual rollout/RPC representations"
    );
    let Target::Paths(paths) = &captured.target else {
        return Err("known path lost".into());
    };
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].spelling, "/work/notes.md");
    assert!(paths[0].cwd.is_none() && paths[0].content_revision.is_none());
    assert!(!serde_json::to_string(&captured)?.contains("demonstration"));
    Ok(())
}

#[test]
fn file_change_maps_and_arrays_canonicalize_complete_sets_including_moves() -> Check {
    let map = json!({"type":"FileChange","id":"item-actual","status":"completed","changes":{
        "z.rs":{"type":"add","content":"NOT_AN_OBSERVED_REVISION"},
        "a.rs":{"type":"update","move_path":"b.rs","unified_diff":"NOT_AN_OBSERVED_REVISION"}}});
    let array = json!({"type":"fileChange","id":"item-actual","status":"completed","changes":[
        {"path":"z.rs","kind":{"type":"add"}},
        {"path":"a.rs","kind":{"type":"update","move_path":"b.rs"}}]});
    let captured = observed(&notified(map)?)?;
    assert!(notified(array)?.matches(&captured)?);
    let Target::Paths(paths) = captured.target else {
        return Err("paths".into());
    };
    assert_eq!(
        paths
            .iter()
            .map(|p| p.spelling.as_str())
            .collect::<Vec<_>>(),
        ["a.rs", "b.rs", "z.rs"]
    );
    assert!(paths.iter().all(|p| p.content_revision.is_none()));
    let large: serde_json::Map<String, Value> = (0..17)
        .map(|n| (format!("{n}.rs"), json!({"type":"add"})))
        .collect();
    let item =
        notified(json!({"type":"FileChange","id":"large","status":"completed","changes":large}))?;
    assert!(matches!(
        item.target,
        Target::Unknown(UnknownReason::OverBudget)
    ));
    Ok(())
}

#[test]
fn unknown_file_targets_remain_explicit_without_rejecting_the_same_completed_item() -> Check {
    let item = json!({"type":"FileChange","id":"item-actual","status":"completed","changes":{"future":{"new_shape":true}}});
    let unknown = notified(item)?;
    assert!(matches!(
        unknown.target,
        Target::Unknown(UnknownReason::UnsupportedShape)
    ));
    let unknown_record = observed(&unknown)?;
    let item = json!({"type":"fileChange","id":"item-actual","status":"completed","changes":[{"path":"known.rs"}]});
    let known = notified(item.clone())?;
    assert!(
        known.matches(&unknown_record)?,
        "unknown metadata made a durable completed item unacknowledgeable"
    );
    assert!(unknown.matches(&observed(&known)?)?);
    assert!(
        matches!(
            unknown_record.target,
            Target::Unknown(UnknownReason::UnsupportedShape)
        ),
        "acknowledgement replaced the retained unknown"
    );
    let mut different = item.clone();
    different["id"] = json!("another-item");
    assert!(!notified(different)?.matches(&unknown_record)?);
    let mut different = item.clone();
    different["status"] = json!("failed");
    assert!(!notified(different)?.matches(&unknown_record)?);
    let mut different = item;
    different["changes"][0]["path"] = json!("different.rs");
    assert!(
        !notified(different)?.matches(&observed(&known)?)?,
        "known path conflict accepted"
    );
    Ok(())
}
