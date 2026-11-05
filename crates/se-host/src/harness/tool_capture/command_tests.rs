use super::*;
use serde_json::json;
type Check = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn claude_keeps_native_command_text_through_the_matching_result() -> Check {
    let mut tracker = claude::Tracker::default();
    let command = "printf 'native command' > not-an-edit-witness.rs";
    let called = json!({"type":"assistant","message":{"content":[{
        "type":"tool_use","id":"native-shell","name":"Bash","input":{"command":command}}]}});
    let facts = tracker.observe(&called)?;
    assert!(matches!(&facts[0].target, Target::Command(text) if text == command));
    assert!(matches!(facts[0].phase, Phase::Called));
    let result = |error| {
        json!({"type":"user","message":{"content":[{
        "type":"tool_result","tool_use_id":"native-shell","is_error":error,"content":"PRIVATE_OUTPUT"}]}})
    };
    let facts = tracker.observe(&result(false))?;
    assert!(matches!(&facts[0].target, Target::Command(text) if text == command));
    assert!(matches!(facts[0].outcome, Outcome::Succeeded));
    let identity = crate::SessionIdentity {
        session: SessionId::from_parts(1, [1; 10])?,
        agent: se_types::AgentId::from_parts(1, [2; 10])?,
        project: se_types::ProjectId::from_parts(1, [3; 10])?,
    };
    let source = <RecordId as se_store::RecordIdentity>::from_parts(1, [4; 10])?;
    let record = facts[0].record(
        &identity,
        Provider::Claude,
        source,
        Position {
            offset: 10,
            length: 20,
        },
    )?;
    assert!(record.body()?.as_str().contains("native command"));
    assert!(!record.body()?.as_str().contains("PRIVATE_OUTPUT"));
    assert!(matches!(
        tracker.observe(&result(true))?[0].target,
        Target::Unknown(UnknownReason::ConflictingEvidence)
    ));
    Ok(())
}

#[test]
fn codex_native_argv_and_rpc_command_agree_without_inferred_paths() -> Check {
    let conversation = "command-thread".parse()?;
    // Retained rollout shape: CommandExecution stores argv and snake-case exit_code.
    let native = json!({"type":"event_msg","payload":{"type":"item_completed",
        "thread_id":"command-thread","turn_id":"command-turn","item":{
            "type":"CommandExecution","id":"command-item","command":["/bin/bash","-lc","printf 'native command'"],
            "status":"completed","exit_code":0,"aggregated_output":"PRIVATE_OUTPUT"}}});
    let fact = codex::decode(&serde_json::to_vec(&native)?, &conversation)?
        .ok_or("native command skipped")?;
    let Target::Command(command) = &fact.target else {
        return Err("native command became a path".into());
    };
    assert_eq!(
        shlex::split(command).ok_or("quoted argv invalid")?,
        ["/bin/bash", "-lc", "printf 'native command'"]
    );
    let rpc = json!({"method":"item/completed","params":{"threadId":"command-thread","turnId":"command-turn",
        "item":{"type":"commandExecution","id":"command-item","command":command,"status":"completed","exitCode":0}}});
    let notified = codex::notification(&rpc, &conversation)?.ok_or("RPC command skipped")?;
    let identity = crate::SessionIdentity {
        session: SessionId::from_parts(1, [1; 10])?,
        agent: se_types::AgentId::from_parts(1, [2; 10])?,
        project: se_types::ProjectId::from_parts(1, [3; 10])?,
    };
    let source = <RecordId as se_store::RecordIdentity>::from_parts(1, [4; 10])?;
    let record = fact.record(
        &identity,
        Provider::Codex,
        source,
        Position {
            offset: 10,
            length: 20,
        },
    )?;
    assert!(notified.matches(record.captured_tool.as_ref().ok_or("command metadata")?)?);
    let mut altered = rpc.clone();
    altered["params"]["item"]["command"] = json!("printf another-command");
    assert!(
        !codex::notification(&altered, &conversation)?
            .ok_or("altered command skipped")?
            .matches(record.captured_tool.as_ref().ok_or("command metadata")?)?
    );
    let mut failed = rpc;
    failed["params"]["item"]["exitCode"] = json!(2);
    assert!(matches!(
        codex::notification(&failed, &conversation)?
            .ok_or("failed command skipped")?
            .outcome,
        Outcome::Failed
    ));
    Ok(())
}

#[test]
fn command_bounds_are_explicit_and_never_shorten_native_text() {
    for value in [
        json!("x".repeat(1025)),
        json!(["/bin/sh", "-c", "x".repeat(1025)]),
    ] {
        assert!(matches!(
            targets::command(Some(&value)),
            Target::Unknown(UnknownReason::OverBudget)
        ));
    }
    for value in [json!("bad\0command"), json!([]), json!(["echo", 7])] {
        assert!(matches!(
            targets::command(Some(&value)),
            Target::Unknown(UnknownReason::UnsupportedShape)
        ));
    }
    assert!(matches!(
        targets::command(None),
        Target::Unknown(UnknownReason::NoNativeTarget)
    ));
    let value = json!("printf 'one\ntwo'");
    assert!(
        matches!(targets::command(Some(&value)), Target::Command(text) if text == "printf 'one\ntwo'")
    );
}
