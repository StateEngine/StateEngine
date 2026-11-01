#![allow(
    dead_code,
    reason = "The real native fixture is shared with store consumers."
)]
use se_store::*;
use std::{
    path::Path,
    process::{Command, Output},
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

fn command(home: &Path, cwd: &Path, json: bool) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    if json {
        command.arg("--json");
    }
    command.arg("--home").arg(home).current_dir(cwd);
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
fn json(output: Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    assert!(
        output.status.success(),
        "actual project CLI failed: {}; {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
fn plain_root(actual: &str, expected: &Path) -> Check {
    assert!(
        !actual.starts_with(r"\\?\") && !actual.starts_with(r"\??\"),
        "public/stored project root kept a Windows device prefix: {actual}"
    );
    assert!(Path::new(actual).is_absolute());
    assert_eq!(
        std::fs::canonicalize(actual)?,
        std::fs::canonicalize(expected)?,
        "plain spelling changed the actual native directory"
    );
    Ok(())
}

/// Protects: real init stores and prints ordinary project roots; JSON and human status select the correct persisted root by cwd when two projects prevent sole-project fallback.
#[test]
fn init_and_status_keep_plain_roots_and_match_each_cwd() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = Fixture::new()?;
    let home = &f.options.state_directory;
    let first = f.home.join("first project");
    let second = f.home.join("second project");
    std::fs::create_dir(&first)?;
    std::fs::create_dir(&second)?;
    let mut initialized = Vec::new();
    for (root, name) in [(&first, "root-first"), (&second, "root-second")] {
        let output = json(
            command(home, root, true)
                .args(["init", "--repo"])
                .arg(root)
                .args(["--name", name])
                .output()?,
        )?;
        plain_root(
            output["project"]["root"]
                .as_str()
                .ok_or("init project root")?,
            root,
        )?;
        plain_root(
            output["repo"]["root"]
                .as_str()
                .ok_or("init repository root")?,
            root,
        )?;
        initialized.push(output);
    }
    assert_ne!(
        initialized[0]["project"]["id"],
        initialized[1]["project"]["id"]
    );
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(ReadScope {
        admission: Admission {
            scope: Scope::Registry,
            actor: Actor::Human(
                initialized[0]["owner"]["human_id"]
                    .as_str()
                    .ok_or("real initialized human")?
                    .parse()?,
            ),
            session: None,
            generation: 1,
        },
        visibility: Visibility::Owner,
    })?;
    for (root, initialized) in [(&first, &initialized[0]), (&second, &initialized[1])] {
        let id = initialized["project"]["id"]
            .as_str()
            .ok_or("real initialized project")?;
        let stored = present(snapshot.project(id.parse()?)?)?;
        let EventBody::ProjectRegistered { roots, .. } = &stored.current.body else {
            return Err("stored project registration missing".into());
        };
        assert_eq!(roots.len(), 1);
        plain_root(
            roots[0]
                .path
                .to_local()?
                .to_str()
                .ok_or("stored root encoding")?,
            root,
        )?;
        let working_directories = vec![root.join("nested working directory")];
        #[cfg(windows)]
        let working_directories = {
            let mut working_directories = working_directories;
            let special = std::fs::canonicalize(root)?.join("literal.");
            // The ordinary alias exists with different native identity, so
            // display conversion must retain the child's verbatim prefix.
            std::fs::create_dir(root.join("literal"))?;
            std::fs::create_dir(&special)?;
            assert!(
                se_proc::canonicalize_path(&special)?
                    .to_string_lossy()
                    .starts_with(r"\\?\")
            );
            working_directories.push(special);
            working_directories
        };
        for nested in working_directories {
            std::fs::create_dir_all(&nested)?;
            let status = json(command(home, &nested, true).arg("status").output()?)?;
            assert_eq!(status["project"]["state"], "present");
            assert_eq!(
                status["project"]["value"]["id"], id,
                "cwd selection did not match the persisted root"
            );
            let selected = status["project"]["value"]["root"]
                .as_str()
                .ok_or("status project root")?;
            plain_root(selected, root)?;
            let human = command(home, &nested, false).arg("status").output()?;
            assert!(human.status.success());
            let printed = String::from_utf8_lossy(&human.stdout);
            let project_line = printed
                .lines()
                .find(|line| line.starts_with("Project:"))
                .ok_or("human project status line")?;
            assert!(project_line.contains(selected));
            assert!(!project_line.contains(r"\\?\") && !project_line.contains(r"\??\"));
        }
    }
    snapshot.close()?;
    Ok(())
}
