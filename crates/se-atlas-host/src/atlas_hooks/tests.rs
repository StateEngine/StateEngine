use super::*;
#[test]
fn native_inputs_are_narrow_and_output_cannot_decide_permissions() -> Result<()> {
    let event = |tool: &str, input: serde_json::Value| serde_json::json!({"hook_event_name":"PreToolUse","tool_name":tool,"tool_input":input,"cwd":std::env::current_dir().map(|p|p.to_string_lossy().into_owned()).unwrap_or_default()});
    assert!(matches!(
        classify(&event("Grep", serde_json::json!({"pattern":"alpha"}))),
        Some(AtlasHookTarget::Symbol(_))
    ));
    assert!(matches!(
        classify(&event(
            "exec_command",
            serde_json::json!({"cmd":"rg -n alpha"})
        )),
        Some(AtlasHookTarget::Symbol(_))
    ));
    for command in [
        "rg alpha; launch-provider",
        "rg alpha | cat",
        "rg $(credential)",
        "cat ../private",
        "rg alpha elsewhere",
    ] {
        assert!(classify(&event("Bash", serde_json::json!({"command":command}))).is_none());
    }
    assert!(classify(&event("Grep", serde_json::json!({"pattern":"alpha.*"}))).is_none());
    let mut text = "Atlas indexed context (sample)".to_owned();
    for _ in 0..30 {
        add(&mut text, "调用者: λ界.ts:23".into());
    }
    let output =
        encode(&text).ok_or_else(|| se_types::SeError::invalid("hook test", "bounded JSON"))?;
    assert!(output.len() <= 600);
    let value: serde_json::Value = serde_json::from_str(&output)
        .map_err(|e| se_types::SeError::invalid("hook JSON", &e.to_string()))?;
    assert_eq!(value["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(
        value["hookSpecificOutput"].as_object().map(|v| v.len()),
        Some(2)
    );
    assert!(se_core::ops::decode_tool("stateengine_atlas_augment", serde_json::json!({})).is_err());
    Ok(())
}
#[test]
fn ingress_deadline_cannot_be_supplied_by_a_native_peer() {
    assert!(
        serde_json::from_value::<AtlasAugment>(
            serde_json::json!({"target":{"Symbol":"alpha"},"deadline":9000000000u64})
        )
        .is_err()
    );
}
