#![allow(
    dead_code,
    reason = "The native store fixture is shared with other consumers."
)]
use se_store::*;
use se_types::{AgentId, HumanId, IdempotencyKey, ProjectId};
use std::{path::Path, process::Command};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn call(
    home: &Path,
    root: &Path,
    args: &[&str],
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    command
        .args(["--json", "--home"])
        .arg(home)
        .args(args)
        .current_dir(root);
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
    let output = command.output()?;
    assert!(
        output.status.success(),
        "CLI refused: {}; {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

/// Protects: actual CLI allocation creates independent agent/registration/profile IDs in one durable batch; replay retains that original identity and both original events.
#[test]
fn created_agent_and_atomic_profile_have_independent_ids_and_replay_them() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let root = f.home.join("repository");
    std::fs::create_dir(&root)?;
    let initialized = call(
        &f.options.state_directory,
        &root,
        &["init", "--name", "allocations"],
    )?;
    let owner: HumanId = initialized["owner"]["human_id"]
        .as_str()
        .ok_or("initialized owner")?
        .parse()?;
    let project: ProjectId = initialized["project"]["id"]
        .as_str()
        .ok_or("initialized project")?
        .parse()?;
    let first = call(
        &f.options.state_directory,
        &root,
        &["--key", "independent-agent", "agent", "add", "reviewer"],
    )?;
    assert_eq!(first["state"], "committed");
    assert_eq!(first["process_started"], false);
    let agent: AgentId = first["agent"]["id"]
        .as_str()
        .ok_or("created agent")?
        .parse()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(ReadScope {
        admission: Admission {
            scope: Scope::Project(project),
            actor: Actor::Human(owner.clone()),
            session: None,
            generation: 1,
        },
        visibility: Visibility::Owner,
    })?;
    let principal = present(snapshot.principal(Actor::Agent(agent.clone()))?)?;
    let profile = present(snapshot.profile(agent.clone())?)?;
    assert!(
        matches!(&profile.current.body, EventBody::ProfileSaved { agent: target, .. } if target == &agent)
    );
    let agent_bytes = agent
        .canonical_bytes()?
        .ok_or("canonical agent allocation")?;
    let identity_bytes = principal
        .current
        .header
        .event
        .canonical_bytes()?
        .ok_or("canonical registration event")?;
    let profile_bytes = profile
        .current
        .header
        .event
        .canonical_bytes()?
        .ok_or("canonical profile event")?;
    assert_ne!(
        agent_bytes, identity_bytes,
        "agent reused registration event bytes"
    );
    assert_ne!(
        agent_bytes, profile_bytes,
        "agent reused profile event bytes"
    );
    assert_ne!(
        identity_bytes, profile_bytes,
        "atomic event IDs must differ"
    );
    let receipt = present(snapshot.operation_receipt(
        Actor::Human(owner),
        IdempotencyKey::new("independent-agent")?,
    )?)?;
    assert_eq!(receipt.events.len(), 2);
    assert!(receipt.events.contains(&principal.current.header.event));
    assert!(receipt.events.contains(&profile.current.header.event));
    assert_eq!(first["event_id"], principal.current.header.event.as_str());
    snapshot.close()?;
    let replay = call(
        &f.options.state_directory,
        &root,
        &["--key", "independent-agent", "agent", "add", "reviewer"],
    )?;
    assert_eq!(replay["state"], "replayed");
    assert_eq!(replay["agent"], first["agent"]);
    assert_eq!(replay["event_id"], first["event_id"]);
    Ok(())
}
