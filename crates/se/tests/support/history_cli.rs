use se_store::*;
use se_types::{EventId, ProjectId};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    process::{Command, Output},
};
pub fn read(
    home: &Path,
    project: &ProjectId,
    event: &EventId,
) -> Result<(Output, serde_json::Value), Box<dyn std::error::Error>> {
    let output = command(home, project, event, true).output()?;
    let value = serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "actual history JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })?;
    Ok((output, value))
}
pub fn human(
    home: &Path,
    project: &ProjectId,
    event: &EventId,
) -> Result<Output, Box<dyn std::error::Error>> {
    Ok(command(home, project, event, false).output()?)
}
fn command(home: &Path, project: &ProjectId, event: &EventId, json: bool) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    if json {
        command.arg("--json");
    }
    command.arg("--home").arg(home).args([
        "--project",
        project.as_str(),
        "history",
        "--event",
        event.as_str(),
    ]);
    for name in [
        "SE_HOME",
        "SE_PROJECT",
        "SE_CONFIG",
        "SE_LOG",
        "SE_SESSION",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(name);
    }
    command
}
/// Protects: the real Claude Stop capture is independently readable through the public CLI event family, with complete turn payload and original host provenance.
pub fn captured_turn(
    home: &Path,
    project: &ProjectId,
    event: &StoredEvent,
) -> Result<(), Box<dyn std::error::Error>> {
    let (output, value) = read(home, project, &event.header.event)?;
    assert!(
        output.status.success(),
        "public captured-turn read refused: {value}; {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(value["schema"], "se.event/v1");
    assert_eq!(value["event_id"], event.header.event.as_str());
    assert_eq!(value["kind"], "session.turn");
    assert_eq!(value["project"]["id"], project.as_str());
    assert_eq!(value["payload"]["body"]["text"], "outside provider text");
    assert_eq!(value["payload"]["body"]["complete"], true);
    assert_eq!(
        value["payload"]["body"]["bytes"],
        "outside provider text".len()
    );
    let hash: String = Sha256::digest(b"outside provider text")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(value["payload"]["body"]["sha256"], hash);
    for name in ["position", "read_at", "recorded_at"] {
        assert!(value[name].as_str().is_some_and(|value| !value.is_empty()));
    }
    assert_eq!(value["payload"]["role"], "assistant");
    assert_eq!(value["payload"]["provider"], "claude");
    assert_eq!(value["payload"]["turn_id"], "otto-record-1");
    assert_eq!(
        value["payload"]["provider_session"],
        "otto-real-listener-conversation"
    );
    assert!(value["payload"]["session_id"].is_string());
    assert!(matches!(
        value["payload"]["source"].as_str(),
        Some("hook" | "transcript" | "app-server" | "integration")
    ));
    assert!(value["payload"].get("occurred_at").is_some());
    let WriterKind::Host { generation } = event.writer.kind() else {
        return Err("real capture did not retain a host writer".into());
    };
    assert_eq!(value["writer"]["mode"], "host");
    assert_eq!(
        value["writer"]["host_generation"],
        generation.to_string(),
        "public captured turn lost original host writer generation"
    );
    Ok(())
}
