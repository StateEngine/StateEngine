//! A moved project is named by doctor, re-attached with se project move, and a
//! bare repository is refused at init.
#![allow(
    dead_code,
    reason = "Shared real store fixture serves other consumers."
)]
use std::{error::Error, path::Path, process::Command};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn command(home: &Path, root: &Path, json: bool, project: Option<&str>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    command.arg("--home").arg(home).current_dir(root);
    if let Some(project) = project {
        command.args(["--project", project]);
    }
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

fn git(root: &Path, args: &[&str]) -> Check {
    let output = Command::new("git").args(args).current_dir(root).output()?;
    assert!(
        output.status.success(),
        "git {args:?} refused: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn doctor_check(
    output: &std::process::Output,
    id: &str,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let row = value["checks"]
        .as_array()
        .ok_or("doctor JSON has no checks")?
        .iter()
        .find(|row| row["id"] == id)
        .ok_or("project root check was not diagnosed")?;
    Ok(row.clone())
}

#[test]
fn moved_project_is_diagnosed_and_reattached_with_the_recorded_git_identity() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let fixture = Fixture::new()?;
    let home = &fixture.options.state_directory;
    let original = fixture.home.join("move repository");
    let moved = fixture.home.join("moved repository");
    std::fs::create_dir(&original)?;
    git(&original, &["init", "-q", "-b", "main", "."])?;
    git(&original, &["config", "user.email", "se@stateengine.local"])?;
    git(&original, &["config", "user.name", "SE"])?;
    std::fs::write(original.join("note.txt"), "moved later\n")?;
    git(&original, &["add", "."])?;
    git(&original, &["commit", "-qm", "base"])?;
    let output = command(home, &original, true, None)
        .args(["init", "--name", "Mover"])
        .output()?;
    assert!(
        output.status.success(),
        "init refused: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let row = doctor_check(
        &command(home, &original, true, None)
            .arg("doctor")
            .output()?,
        "project.root.Mover",
    )?;
    assert_eq!(row["state"], "ok");
    assert_eq!(row["observed"], "1 of 1 registered roots present on disk");
    assert!(row["fix"].is_null(), "{row}");
    std::fs::rename(&original, &moved)?;
    let failed = doctor_check(
        &command(home, &moved, true, None).arg("doctor").output()?,
        "project.root.Mover",
    )?;
    assert_eq!(failed["state"], "failed");
    let observed = failed["observed"]
        .as_str()
        .ok_or("failed check has no observed text")?;
    let original_text = original.to_str().ok_or("original root is not UTF-8")?;
    assert!(observed.contains(original_text), "{failed}");
    assert_eq!(
        failed["fix"]["argv"],
        serde_json::json!([
            "se",
            "--home",
            home.to_str().ok_or("state home is not UTF-8")?,
            "--project",
            "Mover",
            "project",
            "move",
            "<new-folder>"
        ])
    );
    let output = command(home, &moved, false, Some("Mover"))
        .args(["project", "move", moved.to_str().ok_or("moved root is not UTF-8")?])
        .output()?;
    assert!(
        output.status.success(),
        "project move refused: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(
        stdout.contains(&format!("Project Mover moved from {}", original.display())),
        "{stdout}"
    );
    assert!(
        stdout.contains("Git identity: HEAD") && stdout.contains("on main"),
        "{stdout}"
    );
    assert!(stdout.contains("Event: "), "{stdout}");
    let row = doctor_check(
        &command(home, &moved, true, None).arg("doctor").output()?,
        "project.root.Mover",
    )?;
    assert_eq!(row["state"], "ok");
    assert_eq!(row["observed"], "1 of 1 registered roots present on disk");
    Ok(())
}

#[test]
fn init_refuses_a_bare_repository_before_registering_a_project() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let fixture = Fixture::new()?;
    let home = &fixture.options.state_directory;
    let bare = fixture.home.join("bare repository");
    std::fs::create_dir(&bare)?;
    git(&bare, &["init", "-q", "--bare", "."])?;
    let output = command(home, &bare, false, None)
        .args(["init", "--name", "Bare"])
        .output()?;
    assert!(!output.status.success(), "bare init must refuse");
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        rendered.contains("a bare Git repository has no working tree for an agent to work in"),
        "{rendered}"
    );
    Ok(())
}
