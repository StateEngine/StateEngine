//! A missing unrelated registration must not disable an existing repository.
#![allow(
    dead_code,
    reason = "Shared real store fixture serves other consumers."
)]
use std::{path::Path, process::Command};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn command(home: &Path, root: &Path, json: bool) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    command.arg("--home").arg(home).current_dir(root);
    if json {
        command.arg("--json");
    }
    for key in [
        "SE_HOME",
        "SE_CONFIG",
        "SE_PROJECT",
        "SE_SESSION",
        "SE_LOG",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(key);
    }
    command
}

#[test]
fn moving_an_unrelated_registered_root_preserves_json_and_human_cwd_selection() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let fixture = Fixture::new()?;
    let home = &fixture.options.state_directory;
    let first = fixture.home.join("unrelated repository");
    let second = fixture.home.join("intact repository");
    std::fs::create_dir(&first)?;
    std::fs::create_dir(&second)?;
    let mut selected = None;
    for (root, name) in [(&first, "unrelated"), (&second, "intact")] {
        let output = command(home, root, true)
            .args(["init", "--name", name])
            .output()?;
        assert!(
            output.status.success(),
            "init refused: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        if name == "intact" {
            selected = Some(value["project"]["id"].clone());
        }
    }
    let original = std::fs::read(home.join("machine.json"))?;
    std::fs::rename(&first, fixture.home.join("moved unrelated repository"))?;
    for json in [true, false] {
        let output = command(home, &second, json).arg("status").output()?;
        assert!(
            output.status.success(),
            "missing unrelated root disabled intact cwd: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if json {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            assert_eq!(value["project"]["state"], "present");
            assert_eq!(Some(&value["project"]["value"]["id"]), selected.as_ref());
        } else {
            let output = String::from_utf8(output.stdout)?;
            let line = output
                .lines()
                .find(|line| line.starts_with("Project:"))
                .ok_or("human selected project absent")?;
            assert!(
                line.contains("intact") && !line.contains("unrelated"),
                "{line}"
            );
        }
    }
    assert_eq!(std::fs::read(home.join("machine.json"))?, original);
    assert!(
        !first.try_exists()?,
        "read-only selection recreated an absent root"
    );
    Ok(())
}
