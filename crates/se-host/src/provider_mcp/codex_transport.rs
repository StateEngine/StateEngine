//! Codex merges its user and project configuration files key by key, so a `command` in one
//! file and a `url` in another leave one `stateengine` server with both transports, which
//! Codex refuses. This finds that split before Codex reports it without naming the files.
use se_types::Result;
use std::path::{Path, PathBuf};

/// What the Codex configuration files say about the `stateengine` MCP server's transport.
#[derive(Debug, PartialEq, Eq)]
pub enum Transports {
    /// No file sets both transports between them; `files` lists the files that were read.
    Consistent { files: Vec<PathBuf> },
    /// `command` and `url` are set for the same server, possibly in the same file.
    Conflict { command: PathBuf, url: PathBuf },
    /// A file exists but could not be read or parsed, so the check is incomplete.
    Unreadable { file: PathBuf, reason: String },
}

impl Transports {
    /// The refusal text: both files and a step that removes the conflict.
    pub fn conflict(&self) -> Option<String> {
        let Self::Conflict { command, url } = self else {
            return None;
        };
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
}

/// Reads the user file under the Codex home and each project `.codex/config.toml` from
/// `start` up to its Git repository root.
pub fn observe(start: &Path) -> Result<Transports> {
    let home = crate::process::codex_server::mcp_codex_home()?;
    Ok(observe_files(&candidates(&home, start)))
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
    let (mut command, mut url, mut files) = (None, None, Vec::new());
    for file in candidates {
        let text = match std::fs::read_to_string(file) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Transports::Unreadable {
                    file: file.clone(),
                    reason: error.to_string(),
                };
            }
        };
        let table = match text.parse::<toml::Table>() {
            Ok(table) => table,
            Err(error) => {
                return Transports::Unreadable {
                    file: file.clone(),
                    reason: error.message().to_owned(),
                };
            }
        };
        let server = table
            .get("mcp_servers")
            .and_then(|servers| servers.get("stateengine"))
            .and_then(toml::Value::as_table);
        if let Some(server) = server {
            if command.is_none() && server.contains_key("command") {
                command = Some(file.clone());
            }
            if url.is_none() && server.contains_key("url") {
                url = Some(file.clone());
            }
        }
        files.push(file.clone());
    }
    match (command, url) {
        (Some(command), Some(url)) => Transports::Conflict { command, url },
        _ => Transports::Consistent { files },
    }
}
