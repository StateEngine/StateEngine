//! Public status must keep and refresh a commit count in an ordinary terminal.
#![allow(
    dead_code,
    reason = "The native store fixture is shared by several consumers."
)]

use serde_json::Value;
use std::{fs, path::Path, process::Command};

#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::{Check, Fixture};

fn command(program: &str, repo: &Path, owner: &Path) -> Command {
    let mut command = Command::new(program);
    command
        .current_dir(repo)
        .env("HOME", owner)
        .env("USERPROFILE", owner)
        .env("XDG_CONFIG_HOME", owner);
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("GIT_")
        {
            command.env_remove(name);
        }
    }
    for name in ["SE_HOME", "SE_PROJECT", "SE_CONFIG", "SE_SESSION", "SE_LOG"] {
        command.env_remove(name);
    }
    command.env("GIT_CONFIG_NOSYSTEM", "1");
    command
}

fn read(command: &mut Command) -> Result<String, Box<dyn std::error::Error>> {
    let output = command.output()?;
    assert!(
        output.status.success(),
        "command {command:?} failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

fn commit(repo: &Path, owner: &Path, label: &str) -> Check {
    fs::write(repo.join("tracked.txt"), label)?;
    read(command("git", repo, owner).args(["add", "tracked.txt"]))?;
    read(command("git", repo, owner).args([
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-qm",
        label,
        "--",
        "tracked.txt",
    ]))?;
    Ok(())
}

fn cache_entries(home: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(home)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("git-count-")
        {
            entries.push(fs::read_to_string(entry.path())?);
        }
    }
    Ok(entries)
}

#[test]
fn pager_status_caches_and_refreshes_after_commit() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let repo = f.home.join("repository");
    let owner = f.home.join("fixture-owner");
    fs::create_dir(&repo)?;
    fs::create_dir(&owner)?;
    read(command("git", &repo, &owner).args(["init", "-q"]))?;
    commit(&repo, &owner, "first")?;

    let cli = || {
        let mut command = command(env!("CARGO_BIN_EXE_se"), &repo, &owner);
        command.arg("--json").arg("--home").arg(home);
        command
    };
    read(cli().args(["init", "--name", "Cache fixture"]))?;
    let status = |name| -> Result<Value, Box<dyn std::error::Error>> {
        let output = read(cli().env(name, "cat").arg("status"))?;
        Ok(serde_json::from_str(&output)?)
    };

    let first = status("GIT_PAGER")?;
    let first_cache = cache_entries(home)?;
    assert_eq!(first["project"]["value"]["git"]["commits"], 1, "{first}");
    let before = first["project"]["value"]["git"]["head"]
        .as_str()
        .ok_or("first head missing")?;

    commit(&repo, &owner, "second")?;
    let now = read(command("git", &repo, &owner).args(["rev-parse", "HEAD"]))?;
    let after = now.trim();
    assert_ne!(before, after);
    let second = status(if cfg!(windows) {
        "git_pager"
    } else {
        "GIT_PAGER"
    })?;
    let second_cache = cache_entries(home)?;
    assert_eq!(second["project"]["value"]["git"]["head"], after, "{second}");
    assert_eq!(second["project"]["value"]["git"]["commits"], 2, "{second}");
    assert_eq!(first_cache, [format!("git-count-v1\n{before}\n1\n")]);
    assert_eq!(second_cache, [format!("git-count-v1\n{after}\n2\n")]);
    Ok(())
}
