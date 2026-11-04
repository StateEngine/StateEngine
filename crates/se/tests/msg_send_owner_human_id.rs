#![allow(
    dead_code,
    reason = "Shared native fixture supports several public consumers."
)]
use se_store::*;
use se_types::HumanId;
use std::{
    path::Path,
    process::{Command, Output},
    sync::Arc,
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn clean(command: &mut Command) {
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
}
fn command(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    command.arg("--json").arg("--home").arg(home);
    clean(&mut command);
    command
}
fn json(output: &Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    Ok(serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "CLI JSON: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })?)
}
fn success(output: Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    assert!(
        output.status.success(),
        "CLI refused: {}; {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    json(&output)
}
fn setup() -> Result<(Fixture, SqliteDirect, Arc<Lease>), Box<dyn std::error::Error>> {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    store.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-msg_send_owner_human_id-{}",
                serial()
            ))?),
            vec![EventBody::PrincipalRegistered {
                principal: Actor::Human(f.owner.clone()),
                kind: PrincipalKind::Human,
                owner: f.owner.clone(),
                created_by: None,
                name: "Owner".into(),
                role: "owner".into(),
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    Ok((f, store, lease))
}

/// Protects: `se msg send` accepts the exact owner human ID the CLI printed during init, resolves it to the same actor the `owner` selector resolves to, and still refuses a foreign human ID as target-unknown.
#[test]
fn msg_send_accepts_the_registered_owner_human_id() -> Check {
    let (f, mut store, _lease) = setup()?;
    let home = &f.options.state_directory;
    let to_selector = success(
        command(home)
            .args([
                "--project",
                f.project.as_str(),
                "--key",
                "owner-selector-baseline",
                "msg",
                "send",
                "owner",
                "sent to the owner selector",
            ])
            .output()?,
    )?;
    let to_human = success(
        command(home)
            .args([
                "--project",
                f.project.as_str(),
                "--key",
                "owner-selector-human-id",
                "msg",
                "send",
                f.owner.as_str(),
                "sent to the owner human id",
            ])
            .output()?,
    )?;
    assert_eq!(
        to_selector["to"]["id"],
        f.owner.as_str(),
        "owner selector receipt: {to_selector}"
    );
    assert_eq!(
        to_human["to"]["id"],
        f.owner.as_str(),
        "human id receipt: {to_human}"
    );
    assert_eq!(
        to_human["to"]["id"], to_selector["to"]["id"],
        "human id and owner selector must name one actor"
    );
    assert_ne!(
        to_human["message_id"], to_selector["message_id"],
        "two distinct messages were sent"
    );
    let foreign = HumanId::from_parts(1_700_000_000_000 + serial(), [4; 10])?;
    let output = command(home)
        .args([
            "--project",
            f.project.as_str(),
            "--key",
            "owner-selector-foreign",
            "msg",
            "send",
            foreign.as_str(),
            "sent to a foreign human id",
        ])
        .output()?;
    assert!(
        !output.status.success(),
        "foreign human id must refuse: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let error = json(&output)?;
    assert_eq!(
        error["code"], "target-unknown",
        "foreign human id refusal: {error}"
    );
    store.close()?;
    Ok(())
}
