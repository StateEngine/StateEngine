//! Public owner commands against a private, synthetic project.
#![cfg(target_os = "linux")]
#[path = "../../test-support/directory.rs"]
mod directory;
#[path = "../../test-support/home_reaper.rs"]
mod home_reaper;
#[path = "../../test-support/provider_home.rs"]
mod provider_home;
use std::{error::Error, os::unix::fs::PermissionsExt, path::Path, process::Command};

type Check = Result<(), Box<dyn Error>>;

fn se(root: &Path, repo: &Path, args: &[&str]) -> Result<Command, Box<dyn Error>> {
    let path = std::env::var_os("PATH").ok_or("PATH unavailable")?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    command.env_clear().env("PATH", path);
    let owner = root.join("owner");
    provider_home::isolate_at(
        &mut command,
        root,
        &owner,
        &owner.join(".codex"),
        &owner.join(".claude"),
    );
    command
        .env("XDG_RUNTIME_DIR", root.join("runtime"))
        .current_dir(repo)
        .arg("--home")
        .arg(root.join("state"))
        .arg("--json")
        .args(args);
    Ok(command)
}

fn run(root: &Path, repo: &Path, args: &[&str]) -> Result<serde_json::Value, Box<dyn Error>> {
    let output = se(root, repo, args)?.output()?;
    if !output.status.success() {
        return Err(format!(
            "command {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn captain_designation_survives_restart_and_can_be_cleared() -> Check {
    let root = directory::private_case_directory()?;
    let repo = root.join("repo");
    std::fs::create_dir(&repo)?;
    std::fs::create_dir(root.join("owner"))?;
    std::fs::create_dir(root.join("runtime"))?;
    std::fs::set_permissions(root.join("runtime"), std::fs::Permissions::from_mode(0o700))?;
    let git = Command::new("git")
        .current_dir(&repo)
        .args(["init", "--quiet"])
        .status()?;
    if !git.success() {
        return Err("fixture repository initialization failed".into());
    }
    // The explicit `down` below covers returns; this covers a killed test.
    let reaper =
        home_reaper::HomeReaper::arm(&se(&root, &repo, &["down"])?, &root.join("state"), true)?;
    let result = (|| -> Check {
        let repo_text = repo.to_str().ok_or("fixture path is not UTF-8")?;
        run(
            &root,
            &repo,
            &[
                "init",
                "--repo",
                repo_text,
                "--name",
                "Project",
                "--agent",
                "worker",
                "--provider",
                "codex",
            ],
        )?;
        run(&root, &repo, &["up"])?;
        run(
            &root,
            &repo,
            &["--key", "captain-set", "captain", "set", "worker"],
        )?;
        run(&root, &repo, &["down"])?;
        run(&root, &repo, &["up"])?;
        let shown = run(&root, &repo, &["captain", "show"])?;
        if shown["captain"]["name"] != "worker" {
            return Err(format!("unexpected captain: {shown}").into());
        }
        run(
            &root,
            &repo,
            &["--key", "captain-owner", "captain", "set", "me"],
        )?;
        let shown = run(&root, &repo, &["captain", "show"])?;
        if shown["captain"]["kind"] != "owner" {
            return Err(format!("owner captain unavailable: {shown}").into());
        }
        run(
            &root,
            &repo,
            &["--key", "captain-clear", "captain", "clear"],
        )?;
        let shown = run(&root, &repo, &["captain", "show"])?;
        if !shown["captain"].is_null() {
            return Err(format!("captain was not cleared: {shown}").into());
        }
        Ok(())
    })();
    let cleanup = run(&root, &repo, &["down"]);
    drop(reaper);
    let result = match (result, cleanup) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(error), Ok(_)) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup failed: {cleanup}").into()),
    };
    root.finish(result)
}
