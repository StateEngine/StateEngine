//! Reads, without changing, the Codex files that can define the `stateengine` MCP server.
//! The user file under the Codex home is always loaded, so its entry is judged: a file that
//! cannot be read, a malformed table, a `command` beside a `url` (which Codex refuses), a
//! `--home` that is gone, or an executable that is missing. Project `.codex/config.toml`
//! files are inspected one by one, never merged with the user file: whether Codex loads one
//! depends on its own trust rules, so a project file defining the server is only reported.
use se_types::Result;
use std::path::{Path, PathBuf};

/// A well-formed `[mcp_servers.stateengine]` table.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    command: Option<String>,
    args: Vec<String>,
    url: bool,
}

/// What one file says about the server.
#[derive(Debug, PartialEq, Eq)]
enum State {
    Absent,
    Unreadable(String),
    /// The table exists, but a field has a type Codex cannot load.
    Malformed(String),
    NoEntry,
    Entry(Entry),
}

/// How a finding affects setup and diagnosis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// The user entry is broken, so `se init` registers nothing; doctor fails.
    Blocking,
    /// The user file could not be read, so `se init` registers nothing; doctor cannot measure.
    UnreadableUser,
    /// The user entry will not start; `se init` notes it and doctor fails.
    Problem,
    /// A project file could not be read; doctor cannot measure it.
    Unmeasured,
    /// A project file defines the server; whether Codex loads it is Codex's decision.
    Advisory,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub text: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Observation {
    user: (PathBuf, State),
    projects: Vec<(PathBuf, State)>,
}

impl Observation {
    /// The files that exist, user file first.
    pub fn files(&self) -> Vec<&Path> {
        std::iter::once(&self.user)
            .chain(&self.projects)
            .filter(|(_, state)| *state != State::Absent)
            .map(|(file, _)| file.as_path())
            .collect()
    }

    pub fn findings(&self) -> Vec<Finding> {
        let (file, state) = &self.user;
        let shown = file.display();
        let mut findings = match state {
            State::Unreadable(reason) => vec![Finding {
                severity: Severity::UnreadableUser,
                text: format!(
                    "{shown} could not be read ({reason}), so its Codex MCP entry is unknown. \
                     Repair or move that file, then run `se init` again in your project."
                ),
            }],
            State::Malformed(reason) => vec![Finding {
                severity: Severity::Blocking,
                text: format!(
                    "{shown} has a `[mcp_servers.stateengine]` table Codex cannot load: \
                     {reason}. Correct or delete that table there, then run `se init` again \
                     in your project."
                ),
            }],
            State::Entry(entry) => user_entry(file, entry),
            State::Absent | State::NoEntry => Vec::new(),
        };
        findings.extend(
            self.projects
                .iter()
                .filter_map(|(file, state)| project(file, state)),
        );
        findings
    }
}

/// Problems with the user file's entry, which `codex mcp remove stateengine` deletes.
fn user_entry(file: &Path, entry: &Entry) -> Vec<Finding> {
    let shown = file.display();
    let mut findings = Vec::new();
    if entry.command.is_some() && entry.url {
        findings.push(Finding {
            severity: Severity::Blocking,
            text: format!(
                "{shown} sets both `command` and `url` for `[mcp_servers.stateengine]`, which \
                 Codex refuses. Run `codex mcp remove stateengine`, then run `se init` again in \
                 your project."
            ),
        });
    }
    if let Some(home) = missing_home(entry) {
        findings.push(Finding {
            severity: Severity::Blocking,
            text: format!(
                "{shown} starts StateEngine with --home {}, which no longer exists. Run `codex \
                 mcp remove stateengine`, then run `se init` again in your project.",
                home.display()
            ),
        });
    }
    if let Some(command) = entry
        .command
        .as_deref()
        .filter(|command| !executable_exists(command))
    {
        findings.push(Finding {
            severity: Severity::Problem,
            text: format!(
                "{shown} starts the StateEngine MCP server with `{command}`, which is not \
                 installed, not on PATH or not executable. Install StateEngine, or run `codex mcp \
                 remove stateengine` and then `se init` again in your project."
            ),
        });
    }
    findings
}

/// A project file on its own: unreadable, or defining the server, named with what it sets.
fn project(file: &Path, state: &State) -> Option<Finding> {
    let shown = file.display();
    let detail = match state {
        State::Unreadable(reason) => {
            return Some(Finding {
                severity: Severity::Unmeasured,
                text: format!("{shown} could not be read ({reason}), so it was not checked."),
            });
        }
        State::Malformed(reason) => format!(" with a field Codex cannot load ({reason})"),
        State::Entry(entry) => {
            let mut details = Vec::new();
            if entry.url {
                details.push("sets `url`".to_owned());
            }
            if let Some(home) = missing_home(entry) {
                details.push(format!(
                    "uses --home {}, which no longer exists",
                    home.display()
                ));
            }
            if details.is_empty() {
                String::new()
            } else {
                format!(" and {}", details.join(" and "))
            }
        }
        State::Absent | State::NoEntry => return None,
    };
    Some(Finding {
        severity: Severity::Advisory,
        text: format!(
            "{shown} defines `[mcp_servers.stateengine]`{detail}. When Codex loads that project \
             file, it can override or conflict with the entry StateEngine registers; inspect \
             it, and remove that table from {shown} if StateEngine should use its own entry."
        ),
    })
}

fn missing_home(entry: &Entry) -> Option<PathBuf> {
    entry
        .args
        .windows(2)
        .find(|pair| pair[0] == "--home")
        .map(|pair| PathBuf::from(&pair[1]))
        .filter(|home| !home.is_dir())
}

/// Reads the user file under the Codex home and each project `.codex/config.toml` from
/// `start` up to its Git repository root.
pub fn observe(start: &Path) -> Result<Observation> {
    let home = crate::process::codex_server::mcp_codex_home()?;
    let user = home.join("config.toml");
    let projects = projects(start)
        .into_iter()
        .filter(|file| *file != user)
        .map(|file| {
            let state = inspect(&file);
            (file, state)
        })
        .collect();
    let state = inspect(&user);
    Ok(Observation {
        user: (user, state),
        projects,
    })
}

/// Configuration files are small; a larger one is refused rather than read in part.
const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// A bounded read of a regular file that never waits on a FIFO or device.
fn inspect(file: &Path) -> State {
    let bytes = match se_proc::file_access::read_bounded_regular_file(file, MAX_CONFIG_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return State::Absent,
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            return State::Unreadable(format!("it is larger than {MAX_CONFIG_BYTES} bytes"));
        }
        Err(error) => return State::Unreadable(error.to_string()),
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return State::Unreadable("it is not UTF-8 text".into());
    };
    let table = match text.parse::<toml::Table>() {
        Ok(table) => table,
        Err(error) => return State::Unreadable(format!("invalid TOML: {}", error.message())),
    };
    let Some(server) = table
        .get("mcp_servers")
        .and_then(|servers| servers.get("stateengine"))
    else {
        return State::NoEntry;
    };
    match entry(server) {
        Ok(entry) => State::Entry(entry),
        Err(reason) => State::Malformed(reason),
    }
}

/// The table's fields, refusing any of the wrong type rather than dropping it.
fn entry(server: &toml::Value) -> std::result::Result<Entry, String> {
    let server = server.as_table().ok_or("`stateengine` is not a table")?;
    let command = match server.get("command") {
        None => None,
        Some(toml::Value::String(command)) => Some(command.clone()),
        Some(_) => return Err("`command` is not a string".into()),
    };
    let args = match server.get("args") {
        None => Vec::new(),
        Some(toml::Value::Array(args)) => args
            .iter()
            .map(|arg| arg.as_str().map(str::to_owned))
            .collect::<Option<_>>()
            .ok_or("`args` holds a value that is not a string")?,
        Some(_) => return Err("`args` is not an array of strings".into()),
    };
    let url = match server.get("url") {
        None => false,
        Some(toml::Value::String(_)) => true,
        Some(_) => return Err("`url` is not a string".into()),
    };
    Ok(Entry { command, args, url })
}

/// A command Codex can start: a path with execute access, or a name found on PATH.
fn executable_exists(command: &str) -> bool {
    let runnable = |path: &Path| {
        path.is_file() && se_proc::file_access::require_executable_access(path).is_ok()
    };
    let path = Path::new(command);
    if path.components().count() > 1 {
        return runnable(path);
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
                .any(|suffix| runnable(&dir.join(format!("{command}{suffix}"))))
        })
    })
}

/// Project files from the repository root down to `start`.
fn projects(start: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in start.ancestors() {
        files.push(dir.join(".codex").join("config.toml"));
        if dir.join(".git").exists() {
            break;
        }
    }
    files.reverse();
    files
}
