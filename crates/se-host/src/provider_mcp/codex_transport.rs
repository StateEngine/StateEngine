//! Codex merges its user and project configuration files key by key, so a `command` in one
//! file and a `url` in another leave one `stateengine` server with both transports, which
//! Codex refuses without naming the files. This reads every file's `stateengine` entry once:
//! to report that split, to find entries whose `--home` or executable no longer exists, and
//! to remove a stray `url` from the stdio entry StateEngine itself registers.
use se_types::Result;
use std::path::{Path, PathBuf};

/// One configuration file's `[mcp_servers.stateengine]` table.
#[derive(Debug, PartialEq, Eq)]
pub struct Entry {
    pub file: PathBuf,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub url: bool,
}

impl Entry {
    /// The stdio entry `se init` registers: `se [--home DIR] mcp`.
    fn owned(&self) -> bool {
        let program = self.command.as_deref().map(Path::new);
        program
            .and_then(Path::file_stem)
            .is_some_and(|stem| stem == "se")
            && self.args.last().is_some_and(|last| last == "mcp")
    }
}

/// What the Codex configuration files say about the `stateengine` MCP server.
#[derive(Debug, PartialEq, Eq)]
pub enum Transports {
    /// Every file that exists was read; `files` lists them, `entries` their tables.
    Read {
        files: Vec<PathBuf>,
        entries: Vec<Entry>,
    },
    /// A file exists but could not be read or parsed, so the check is incomplete.
    Unreadable { file: PathBuf, reason: String },
}

impl Transports {
    /// The files setting `command` and `url` for the same server, possibly one file.
    pub fn split(&self) -> Option<(&Path, &Path)> {
        let Self::Read { entries, .. } = self else {
            return None;
        };
        let command = entries.iter().find(|entry| entry.command.is_some())?;
        let url = entries.iter().find(|entry| entry.url)?;
        Some((&command.file, &url.file))
    }

    /// The refusal text: both files and a step that removes the conflict.
    pub fn conflict(&self) -> Option<String> {
        let (command, url) = self.split()?;
        let (command, url) = (command.display(), url.display());
        let place = if command.to_string() == url.to_string() {
            format!("sets both `command` and `url` in {url}")
        } else {
            format!("sets `command` in {command} and `url` in {url}")
        };
        Some(format!(
            "Codex `[mcp_servers.stateengine]` {place}; Codex merges these into one server with \
             two transports and refuses it. Delete the `url` line, or that file's whole \
             `[mcp_servers.stateengine]` table, from {url}, then retry."
        ))
    }

    /// Entries whose `--home` directory or executable is gone, each with its repair.
    pub fn stale(&self) -> Vec<String> {
        let Self::Read { entries, .. } = self else {
            return Vec::new();
        };
        let mut problems = Vec::new();
        for entry in entries {
            let file = entry.file.display();
            let home = entry
                .args
                .windows(2)
                .find(|pair| pair[0] == "--home")
                .map(|pair| PathBuf::from(&pair[1]));
            if let Some(home) = home.filter(|home| !home.is_dir()) {
                problems.push(format!(
                    "{file} starts StateEngine with --home {}, which no longer exists. Run \
                     `codex mcp remove stateengine`, then `se init` again in your project to \
                     register it.",
                    home.display()
                ));
            }
            if let Some(command) = &entry.command
                && !executable_exists(command)
            {
                problems.push(format!(
                    "{file} starts the StateEngine MCP server with `{command}`, which is not \
                     installed or not on PATH. Install StateEngine or correct `command` there."
                ));
            }
        }
        problems
    }
}

/// Reads the user file under the Codex home and each project `.codex/config.toml` from
/// `start` up to its Git repository root.
pub fn observe(start: &Path) -> Result<Transports> {
    let home = crate::process::codex_server::mcp_codex_home()?;
    Ok(observe_files(&candidates(&home, start)))
}

/// Removes `url` from a table that is otherwise the stdio entry StateEngine registers, in
/// files read by `observe`. Other tables, including a user's own HTTP entry, are reported
/// rather than edited. Returns the files that changed.
pub fn strip_owned_urls(observed: &Transports) -> Result<Vec<PathBuf>> {
    let Transports::Read { entries, .. } = observed else {
        return Ok(Vec::new());
    };
    let mut changed = Vec::new();
    for entry in entries.iter().filter(|entry| entry.url && entry.owned()) {
        strip_url(&entry.file)?;
        changed.push(entry.file.clone());
    }
    Ok(changed)
}

fn strip_url(file: &Path) -> Result<()> {
    let refuse = |reason: String| {
        se_types::SeError::invalid(
            "Codex MCP configuration",
            &format!("{}: {reason}", file.display()),
        )
    };
    let metadata = std::fs::symlink_metadata(file).map_err(|e| refuse(e.to_string()))?;
    if !metadata.is_file() {
        return Err(refuse(
            "is not a regular file; delete its `url` line by hand".into(),
        ));
    }
    let text = std::fs::read_to_string(file).map_err(|e| refuse(e.to_string()))?;
    let mut document = text
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| refuse(e.message().to_owned()))?;
    let removed = document
        .get_mut("mcp_servers")
        .and_then(|servers| servers.get_mut("stateengine"))
        .and_then(toml_edit::Item::as_table_like_mut)
        .and_then(|table| table.remove("url"));
    if removed.is_none() {
        return Ok(());
    }
    // Replace by rename so a reader never sees half a file; keep the original permissions.
    let staging = file.with_extension("toml.stateengine-edit");
    std::fs::write(&staging, document.to_string()).map_err(|e| refuse(e.to_string()))?;
    let written = std::fs::set_permissions(&staging, metadata.permissions())
        .and_then(|()| std::fs::rename(&staging, file));
    if let Err(error) = written {
        let _ = std::fs::remove_file(&staging);
        return Err(refuse(error.to_string()));
    }
    Ok(())
}

fn executable_exists(command: &str) -> bool {
    let path = Path::new(command);
    if path.components().count() > 1 {
        return path.is_file();
    }
    let names: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| {
            names
                .iter()
                .any(|suffix| dir.join(format!("{command}{suffix}")).is_file())
        })
    })
}

fn candidates(codex_home: &Path, start: &Path) -> Vec<PathBuf> {
    let mut files = vec![codex_home.join("config.toml")];
    for dir in start.ancestors() {
        let file = dir.join(".codex").join("config.toml");
        if !files.contains(&file) {
            files.push(file);
        }
        if dir.join(".git").exists() {
            break;
        }
    }
    files
}

fn observe_files(candidates: &[PathBuf]) -> Transports {
    let (mut files, mut entries) = (Vec::new(), Vec::new());
    for file in candidates {
        let unreadable = |reason: String| Transports::Unreadable {
            file: file.clone(),
            reason,
        };
        let text = match std::fs::read_to_string(file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return unreadable(error.to_string()),
        };
        let table = match text.parse::<toml::Table>() {
            Ok(table) => table,
            Err(error) => return unreadable(error.message().to_owned()),
        };
        let server = table
            .get("mcp_servers")
            .and_then(|servers| servers.get("stateengine"))
            .and_then(toml::Value::as_table);
        if let Some(server) = server {
            entries.push(Entry {
                file: file.clone(),
                command: server
                    .get("command")
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned),
                args: server
                    .get("args")
                    .and_then(toml::Value::as_array)
                    .map(|args| {
                        args.iter()
                            .filter_map(|arg| arg.as_str().map(str::to_owned))
                            .collect()
                    })
                    .unwrap_or_default(),
                url: server.contains_key("url"),
            });
        }
        files.push(file.clone());
    }
    Transports::Read { files, entries }
}
