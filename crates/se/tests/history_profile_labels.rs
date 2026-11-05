#![allow(
    dead_code,
    reason = "Shared native fixture supports several public consumers."
)]
use se_store::*;
use std::{
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
fn setup() -> Result<(Fixture, SqliteDirect, Arc<Lease>), Box<dyn std::error::Error>> {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    // The fixture registers the owner human at Registry scope; the history
    // payload projection resolves principals project-scoped.
    store.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-history_profile_labels-owner-{}",
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
    store.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-history_profile_labels-{}",
                serial()
            ))?),
            vec![EventBody::ProfileSaved {
                agent: f.a.clone(),
                profile: Profile {
                    provider: Provider::Claude,
                    model: None,
                    permission: PermissionProfile::WorkspaceWrite,
                    named_profile: "default".into(),
                    effort: None,
                },
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    Ok((f, store, lease))
}
fn plain(output: Output) -> Result<String, Box<dyn std::error::Error>> {
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "CLI refused: {text} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(text)
}

/// Protects: plain `se history` renders a saved profile with the same permission and provider terms that init and launch print, while `--json` keeps the stored wire values.
#[test]
fn plain_history_uses_onboarding_profile_terms() -> Check {
    let (f, store, _lease) = setup()?;
    let home = &f.options.state_directory;
    let project = f.project.as_str();
    let mut json = Command::new(env!("CARGO_BIN_EXE_se"));
    clean(&mut json);
    let json = json
        .arg("--json")
        .arg("--home")
        .arg(home)
        .arg("--project")
        .arg(project)
        .args(["history", "--limit", "100"])
        .output()?;
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).map_err(|error| {
        format!(
            "CLI JSON: {error}; stdout={}",
            String::from_utf8_lossy(&json.stdout)
        )
    })?;
    assert!(
        json.status.success(),
        "history --json refused: {}",
        String::from_utf8_lossy(&json.stdout)
    );
    let items = value["items"]
        .as_array()
        .ok_or("history page has no items")?;
    let saved = items
        .iter()
        .find(|item| item["kind"] == "profile.saved")
        .ok_or("the saved profile event is missing from history")?;
    assert_eq!(
        saved["payload"]["profile"]["permission"], "WorkspaceWrite",
        "JSON must keep the stored permission wire value: {saved}"
    );
    assert_eq!(
        saved["payload"]["profile"]["provider"], "Claude",
        "JSON must keep the stored provider wire value: {saved}"
    );
    let mut plain_command = Command::new(env!("CARGO_BIN_EXE_se"));
    clean(&mut plain_command);
    let plain_output = plain_command
        .arg("--home")
        .arg(home)
        .arg("--project")
        .arg(project)
        .args(["history", "--limit", "100"])
        .output()?;
    let text = plain(plain_output)?;
    assert!(
        text.contains("Permissions: workspace-write"),
        "plain history lost the onboarding permission term:\n{text}"
    );
    assert!(
        text.contains("Provider: Claude Code"),
        "plain history lost the onboarding provider term:\n{text}"
    );
    assert!(
        !text.contains("WorkspaceWrite"),
        "plain history leaked the internal permission enum:\n{text}"
    );
    assert!(
        !text.lines().any(|line| line.trim() == "Provider: Claude"),
        "plain history kept the internal provider enum:\n{text}"
    );
    store.close()?;
    Ok(())
}
