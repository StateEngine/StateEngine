//! Keep CLI and harness configuration inside an owned fixture before exec.
#![allow(
    dead_code,
    reason = "Each integration test uses its fixture's path layout."
)]

use std::{
    env, fs, io,
    path::{Component, Path, PathBuf},
    process::Command,
};

pub fn for_state(command: &mut Command, state: &Path) {
    let (Some(parent), Some(name)) = (state.parent(), state.file_name()) else {
        panic!(
            "fixture state must have a parent and name: {}",
            state.display()
        );
    };
    let mut account = name.to_owned();
    account.push("-user");
    let home = parent.join(account);
    isolate_at(
        command,
        parent,
        &home,
        &home.join(".codex"),
        &home.join(".claude"),
    );
}

pub fn isolate(command: &mut Command, fixture: &Path) {
    let home = fixture.join("user-home");
    isolate_at(
        command,
        fixture,
        &home,
        &home.join(".codex"),
        &home.join(".claude"),
    );
}

pub fn isolate_at(command: &mut Command, fixture: &Path, home: &Path, codex: &Path, claude: &Path) {
    command.envs([
        ("HOME", home),
        ("USERPROFILE", home),
        ("CODEX_HOME", codex),
        ("CLAUDE_CONFIG_DIR", claude),
    ]);
    assert_isolated(command, fixture).unwrap_or_else(|error| panic!("{error}"));
    for directory in [home, codex, claude] {
        fs::create_dir_all(directory).unwrap_or_else(|error| {
            panic!(
                "could not create provider fixture directory {}: {error}",
                directory.display()
            )
        });
    }
}

pub fn assert_isolated(command: &Command, fixture: &Path) -> io::Result<()> {
    let root = fixture.canonicalize()?;
    if !fixture.is_absolute() || !root.is_dir() {
        return Err(outside("fixture root", fixture));
    }
    let under = |scratch: &Path| {
        scratch
            .canonicalize()
            .is_ok_and(|temp| root != temp && root.starts_with(temp))
    };
    let in_scratch = under(&env::temp_dir());
    #[cfg(unix)]
    let in_scratch = in_scratch || under(Path::new("/tmp"));
    if !in_scratch {
        return Err(outside("fixture root", fixture));
    }

    for (key, files) in [
        ("HOME", &[".claude.json"][..]),
        ("USERPROFILE", &[".claude.json"]),
        ("CODEX_HOME", &["config.toml", "auth.json"]),
        (
            "CLAUDE_CONFIG_DIR",
            &[".claude.json", "settings.json", ".credentials.json"],
        ),
    ] {
        let path = command
            .get_envs()
            .find_map(|(name, value)| {
                let matches = if cfg!(windows) {
                    name.eq_ignore_ascii_case(key)
                } else {
                    name == key
                };
                matches.then_some(value).flatten()
            })
            .map(Path::new)
            .ok_or_else(|| io::Error::other(format!("{key} is not set on the fixture command")))?;
        if !path.strip_prefix(fixture).is_ok_and(|relative| {
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        }) || !resolved_parent(path)?.starts_with(&root)
        {
            return Err(outside(key, path));
        }
        for file in files {
            let file = path.join(file);
            if !resolved_parent(&file)?.starts_with(&root) {
                return Err(outside(key, &file));
            }
        }
        if env::var_os(key).is_some_and(|inherited| {
            let inherited = PathBuf::from(inherited);
            path == inherited
                || path
                    .canonicalize()
                    .ok()
                    .zip(inherited.canonicalize().ok())
                    .is_some_and(|(fixture, account)| fixture == account)
        }) {
            return Err(outside(key, path));
        }
    }
    Ok(())
}

fn resolved_parent(path: &Path) -> io::Result<PathBuf> {
    for candidate in path.ancestors() {
        match fs::symlink_metadata(candidate) {
            Ok(_) => return candidate.canonicalize(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Err(outside("provider home", path))
}

fn outside(key: &str, path: &Path) -> io::Error {
    io::Error::other(format!(
        "{key} would use a path outside the private fixture: {}",
        path.display()
    ))
}
