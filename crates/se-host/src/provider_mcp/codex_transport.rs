//! Codex merges its user file with project `.codex/config.toml` files key by key, a deeper
//! folder overriding a shallower one, so a `command` in one file and a `url` in another leave
//! one `stateengine` server with both transports, which Codex refuses without naming the
//! files. This reads those files without changing them and merges the server the same way:
//! to name both files of such a split with its repair, and to find a merged entry whose
//! `--home` or executable no longer exists. Project files count only for a trusted checkout;
//! the split they would cause once trusted is only advised about.
use se_types::Result;
use std::path::{Path, PathBuf};

/// One merged key's value and the file that set it, the highest-precedence file that does.
#[derive(Debug, PartialEq, Eq)]
struct Set<T> {
    value: T,
    file: PathBuf,
}

/// The `stateengine` server as Codex merges it from the files it loads.
#[derive(Debug, Default, PartialEq, Eq)]
struct Server {
    command: Option<Set<String>>,
    args: Option<Set<Vec<String>>>,
    /// The file whose `url` the merged server keeps.
    url: Option<PathBuf>,
}

impl Server {
    fn merge(&mut self, file: &Path, table: &toml::Table) {
        if let Some(command) = table.get("command").and_then(toml::Value::as_str) {
            self.command = Some(Set {
                value: command.to_owned(),
                file: file.to_path_buf(),
            });
        }
        if let Some(args) = table.get("args").and_then(toml::Value::as_array) {
            self.args = Some(Set {
                value: args
                    .iter()
                    .filter_map(|arg| arg.as_str().map(str::to_owned))
                    .collect(),
                file: file.to_path_buf(),
            });
        }
        if table.contains_key("url") {
            self.url = Some(file.to_path_buf());
        }
    }

    /// The files that set `command` and `url` on one merged server, possibly one file.
    fn split(&self) -> Option<(&Path, &Path)> {
        Some((&self.command.as_ref()?.file, self.url.as_deref()?))
    }
}

/// What the Codex configuration files say about the `stateengine` MCP server.
#[derive(Debug, PartialEq, Eq)]
pub enum Transports {
    Read(Box<Config>),
    /// A file exists but could not be read or parsed, so nothing was checked.
    Unreadable {
        file: PathBuf,
        reason: String,
    },
}

/// Every existing configuration file was read.
#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    /// The files read, lowest precedence first.
    pub files: Vec<PathBuf>,
    user: PathBuf,
    /// The server Codex loads today.
    effective: Server,
    /// The server Codex would load if this checkout were trusted.
    trusted: Server,
}

impl Config {
    /// The files Codex loads that set `command` and `url` for one server.
    pub fn split(&self) -> Option<(&Path, &Path)> {
        self.effective.split()
    }

    /// The refusal text: both files and a step that removes the conflict.
    pub fn conflict(&self) -> Option<String> {
        let (command, url) = self.split()?;
        let place = if command == url {
            format!("sets both `command` and `url` in {}", url.display())
        } else {
            format!(
                "sets `command` in {} and `url` in {}",
                command.display(),
                url.display()
            )
        };
        Some(format!(
            "Codex `[mcp_servers.stateengine]` {place}; Codex merges these into one server with \
             two transports and refuses it. {}",
            self.repair(url)
        ))
    }

    /// A split that appears only once this untrusted checkout's project files count. Codex
    /// ignores them today, but will refuse the server once the checkout is trusted.
    pub fn advisory(&self) -> Option<String> {
        if self.split().is_some() {
            return None;
        }
        let (command, url) = self.trusted.split()?;
        Some(format!(
            "Codex `[mcp_servers.stateengine]` would set `command` in {} and `url` in {} once \
             this project is trusted, and Codex would then refuse the server. {}",
            command.display(),
            url.display(),
            self.repair(url)
        ))
    }

    fn repair(&self, url: &Path) -> String {
        if url == self.user {
            "Run `codex mcp remove stateengine`, then run `se init` again in your project.".into()
        } else {
            format!(
                "Delete the `[mcp_servers.stateengine]` table, or its `url` line, from {}, then \
                 run `se init` again in your project.",
                url.display()
            )
        }
    }

    /// Problems with the merged entry's `--home` directory or executable, each with its repair.
    pub fn stale(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let server = &self.effective;
        let home = server.args.as_ref().and_then(|args| {
            args.value
                .windows(2)
                .find(|pair| pair[0] == "--home")
                .map(|pair| (PathBuf::from(&pair[1]), &args.file))
        });
        if let Some((home, file)) = home.filter(|(home, _)| !home.is_dir()) {
            problems.push(format!(
                "{} starts StateEngine with --home {}, which no longer exists. Run `codex mcp \
                 remove stateengine`, then `se init` again in your project to register it.",
                file.display(),
                home.display()
            ));
        }
        if let Some(command) = &server.command
            && !executable_exists(&command.value)
        {
            problems.push(format!(
                "{} starts the StateEngine MCP server with `{}`, which is not installed, not on \
                 PATH or not executable. Install StateEngine or correct `command` there.",
                command.file.display(),
                command.value
            ));
        }
        problems
    }
}

/// Reads the user file under the Codex home and each project `.codex/config.toml` from
/// `start`'s Git repository root down to `start`.
pub fn observe(start: &Path) -> Result<Transports> {
    let home = crate::process::codex_server::mcp_codex_home()?;
    Ok(observe_files(
        &home.join("config.toml"),
        &projects(start),
        start,
    ))
}

/// Configuration files are small; a larger one is refused rather than read in part.
const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// A bounded read of a regular file that never waits on a FIFO or device; `None` if absent.
fn read(file: &Path) -> std::result::Result<Option<toml::Table>, String> {
    let bytes = match se_proc::file_access::read_bounded_regular_file(file, MAX_CONFIG_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            return Err(format!("is larger than {MAX_CONFIG_BYTES} bytes"));
        }
        Err(error) => return Err(error.to_string()),
    };
    let text = String::from_utf8(bytes).map_err(|_| "is not UTF-8 text".to_owned())?;
    text.parse::<toml::Table>()
        .map(Some)
        .map_err(|error| error.message().to_owned())
}

/// Whether the user file trusts `checkout`. The most specific `[projects."path"]` entry that
/// is the checkout or one of its ancestors decides, so an `untrusted` checkout inside a
/// trusted folder stays untrusted; at equal depth, `untrusted` wins.
fn trusted(user: &toml::Table, checkout: &Path) -> bool {
    let Some(projects) = user.get("projects").and_then(toml::Value::as_table) else {
        return false;
    };
    let real = std::fs::canonicalize(checkout).ok();
    let mut decided: Option<(usize, bool)> = None;
    for (path, settings) in projects {
        let trusted = match settings.get("trust_level").and_then(toml::Value::as_str) {
            Some("trusted") => true,
            Some("untrusted") => false,
            _ => continue,
        };
        let project = Path::new(path);
        let depth = if checkout.starts_with(project) {
            Some(project.components().count())
        } else {
            real.as_ref()
                .zip(std::fs::canonicalize(project).ok())
                .filter(|(real, project)| real.starts_with(project))
                .map(|(_, project)| project.components().count())
        };
        let Some(depth) = depth else { continue };
        if decided.is_none_or(|(best, _)| depth > best || (depth == best && !trusted)) {
            decided = Some((depth, trusted));
        }
    }
    decided.is_some_and(|(_, trusted)| trusted)
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

/// Project files from the repository root down to `start`, lowest precedence first.
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

fn observe_files(user: &Path, projects: &[PathBuf], checkout: &Path) -> Transports {
    let mut config = Config {
        files: Vec::new(),
        user: user.to_path_buf(),
        effective: Server::default(),
        trusted: Server::default(),
    };
    let mut project_files_load = false;
    for (index, file) in std::iter::once(user)
        .chain(projects.iter().map(PathBuf::as_path))
        .enumerate()
    {
        if index > 0 && file == user {
            continue;
        }
        let table = match read(file) {
            Ok(Some(table)) => table,
            Ok(None) => continue,
            Err(reason) => {
                return Transports::Unreadable {
                    file: file.to_path_buf(),
                    reason,
                };
            }
        };
        if index == 0 {
            project_files_load = trusted(&table, checkout);
        }
        let server = table
            .get("mcp_servers")
            .and_then(|servers| servers.get("stateengine"))
            .and_then(toml::Value::as_table);
        if let Some(server) = server {
            config.trusted.merge(file, server);
            if index == 0 || project_files_load {
                config.effective.merge(file, server);
            }
        }
        config.files.push(file.to_path_buf());
    }
    Transports::Read(Box::new(config))
}
