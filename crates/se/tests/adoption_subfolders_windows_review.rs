//! Exercise the native hook at the registered root, its children, and a nested repo.
#![cfg(windows)]

#[path = "../../test-support/directory.rs"]
mod directory;
#[path = "../../test-support/executable.rs"]
mod executable;
#[path = "support/foreground_host.rs"]
mod foreground_host;

use executable::ExecutableCommand;
use se_host::adoption::{Project, Registration, settings};
use se_types::{NativePath, ProjectId};
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

type Check<T = ()> = Result<T, Box<dyn Error>>;

fn command(image: &Path, home: &Path, owner: &Path, cwd: &Path) -> Command {
    let mut command = Command::new(image);
    for (name, _) in std::env::vars_os() {
        let key = name.to_string_lossy().to_ascii_uppercase();
        if ["SE_", "STATEENGINE_", "CLAUDE", "CODEX"]
            .iter()
            .any(|prefix| key.starts_with(*prefix))
        {
            command.env_remove(name);
        }
    }
    command
        .args(["--json", "--home"])
        .arg(home)
        .env("HOME", owner)
        .env("USERPROFILE", owner)
        .current_dir(cwd);
    command
}

fn checked(command: &mut Command) -> Check<serde_json::Value> {
    let output = command.output_executable()?;
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn register(home: &Path, root: &Path, config: &Path, python: &Path, project: ProjectId) -> Check {
    let settings_path = config.join("settings.json");
    fs::write(&settings_path, b"{}\n")?;
    se_host::adoption::publish(
        home,
        &Registration {
            schema: 1,
            settings: NativePath::from_local(settings_path.clone())?,
            provider: NativePath::from_local(se_proc::canonicalize_path(python)?)?,
            config_home: NativePath::from_local(se_proc::canonicalize_path(config)?)?,
            hooks: Vec::new(),
            layout: settings::layout(&settings_path, &[])?,
            installed: true,
            projects: vec![Project {
                project,
                root: NativePath::from_local(se_proc::canonicalize_path(root)?)?,
                discovery: None,
            }],
            discovery: None,
            discovery_refusal: None,
            installation: None,
        },
    )?;
    Ok(())
}

#[test]
fn adoption_accepts_windows_subfolder_aliases_but_refuses_nested_git() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let scratch = directory::private_directory()?;
    let image = scratch.join("se.exe");
    fs::copy(env!("CARGO_BIN_EXE_se"), &image)?;
    let owner = scratch.join("owner");
    let config = owner.join("claude");
    let home = scratch.join("state");
    let root = scratch.join("Registered Worktree With Spaces");
    let child = root.join("Task Inputs With Spaces");
    let nested = child.join("Nested Project With Spaces");
    fs::create_dir_all(&config)?;
    fs::create_dir_all(&nested)?;
    for worktree in [&root, &nested] {
        let git = Command::new("git")
            .args(["init", "-q"])
            .current_dir(worktree)
            .output()?;
        assert!(
            git.status.success(),
            "{}",
            String::from_utf8_lossy(&git.stderr)
        );
    }
    let initialized = checked(command(&image, &home, &owner, &root).args([
        "init",
        "--provider",
        "claude",
        "--key",
        "windows-hook-fixture",
    ]))?;
    let project: ProjectId = serde_json::from_value(initialized["project"]["id"].clone())?;
    let python = PathBuf::from(
        checked(
            Command::new("python")
                .args(["-c", "import json,sys; print(json.dumps(sys.executable))"]),
        )?
        .as_str()
        .ok_or("fixture interpreter path missing")?,
    );
    register(&home, &root, &config, &python, project.clone())?;

    let host =
        foreground_host::ForegroundHost::start(command(&image, &home, &owner, &root), &home)?;
    let package = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(&python)
        .arg("-B")
        .arg(package.join("tests/judges/adoption_subfolders_windows_review.py"))
        .args([
            &image,
            &home,
            &config,
            &se_proc::canonicalize_path(&root)?,
            &se_proc::canonicalize_path(&child)?,
            &se_proc::canonicalize_path(&nested)?,
        ])
        .arg(project.to_string())
        .arg(package.join("../../target/judge-diagnostics/adoption-subfolders-windows.json"))
        .output()?;
    let down = checked(command(&image, &home, &owner, &root).arg("down"))?;
    assert_eq!(down["complete"], true);
    host.wait()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
