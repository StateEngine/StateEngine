//! Register the static MCP entry using each harness's own configuration command.
use crate::adoption::Kind;
use se_config::config_policy::{Provider, provider_config_dirs, unusable_config_dir};
use se_types::{Result, SeError};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, process::Command};

pub mod codex_transport;

const LIMIT: u64 = 65_536;

/// Registers the MCP entry for the agent's own provider only; other providers' files stay untouched.
pub fn configure(
    root: &Path,
    configuration: &se_config::config_policy::ConfigFile,
    provider: se_types::Provider,
    alternate_home: Option<&Path>,
) -> Result<Vec<String>> {
    let home = alternate_home
        .map(|path| {
            se_core::ops::AgentCommand::home_argument(path)
                .ok_or_else(|| failure(se_core::ops::AgentCommand::HOME_UNAVAILABLE))
        })
        .transpose()?;
    let args = home.map_or_else(|| vec!["mcp"], |home| vec!["--home", home, "mcp"]);
    let kind = match provider {
        se_types::Provider::Claude => Kind::Claude,
        se_types::Provider::Codex => Kind::Codex,
        // Other harnesses receive StateEngine's tools at launch; no provider file is edited.
        _ => return Ok(Vec::new()),
    };
    let mut changed = Vec::new();
    if kind == Kind::Codex {
        let observed = codex_transport::observe(root)?;
        let stripped = codex_transport::strip_owned_urls(&observed)?;
        changed.extend(stripped.iter().map(|file| {
            format!(
                "removed a conflicting `url` from StateEngine's Codex MCP entry in {}",
                file.display()
            )
        }));
        let observed = if stripped.is_empty() {
            observed
        } else {
            codex_transport::observe(root)?
        };
        if let Some(conflict) = observed.conflict() {
            return Err(failure(&conflict));
        }
        changed.extend(observed.advisory().map(|note| format!("note: {note}")));
        // Codex has one user-wide MCP list: a custom home written to the shared login would
        // serve every project and break once that home is gone. An explicit CODEX_HOME is a
        // login chosen for this setup, so it is registered and checked as usual.
        if alternate_home.is_some() && std::env::var_os("CODEX_HOME").is_none() {
            changed.push(manual(
                kind,
                &args,
                "Codex MCP settings apply to every project; to use this home with Codex",
            )?);
            return Ok(changed);
        }
    }
    let command = configuration.provider_command(kind.provider().into());
    let path = Path::new(command);
    if !path.is_absolute() && path.components().count() == 1 && std::env::var_os("PATH").is_none() {
        changed.push(missing(kind, &args)?);
        return Ok(changed);
    }
    match crate::resolve_provider_executable(configuration, kind.provider().into(), None, None) {
        Ok(executable) if install(root, &executable, kind, &args)? => {
            changed.push(format!("configured {} MCP", kind.label()));
        }
        Ok(_) => (),
        Err(error)
            if matches!(
                error.body.detail(),
                se_types::Detail::ProviderCliNotFound(_)
            ) =>
        {
            changed.push(missing(kind, &args)?);
        }
        Err(error) => return Err(error),
    }
    Ok(changed)
}

fn missing(kind: Kind, args: &[&str]) -> Result<String> {
    manual(kind, args, &format!("Install {}, then", kind.label()))
}

fn manual(kind: Kind, args: &[&str], lead: &str) -> Result<String> {
    let prefix = match kind {
        Kind::Claude => "claude mcp add --scope local stateengine -- se",
        Kind::Codex => "codex mcp add stateengine -- se",
    };
    let words = args
        .iter()
        .map(|arg| {
            se_core::ops::AgentCommand::quoted_word(arg).ok_or_else(|| {
                failure("the selected home cannot be represented in a setup command")
            })
        })
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    let prompt = if cfg!(windows) {
        "in PowerShell run"
    } else {
        "run"
    };
    Ok(format!("{lead} {prompt}: {prefix} {words}"))
}

pub fn install(root: &Path, executable: &Path, kind: Kind, entry: &[&str]) -> Result<bool> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| failure(&format!("could not start the setup runtime: {error}")))?;
    // Resolved once: the same checked bindings go to listing, registration and readback.
    let config = provider_config_dirs().map_err(|reason| failure(&reason))?;
    for (provider, name, dir) in &config {
        let reason =
            (*provider == kind.policy()).then(|| unusable_config_dir(name, dir, kind.label()));
        if let Some(reason) = reason.flatten() {
            return Err(failure(&reason));
        }
    }
    let setup = Setup {
        root,
        executable,
        kind,
        config: &config,
    };
    runtime.block_on(async {
        if configured(setup, entry).await? {
            return Ok(false);
        }
        let mut args: Vec<&str> = match kind {
            Kind::Claude => vec!["mcp", "add", "--scope", "local", "stateengine", "--", "se"],
            Kind::Codex => vec!["mcp", "add", "stateengine", "--", "se"],
        };
        args.extend_from_slice(entry);
        let output = run(setup, &args).await?;
        if !output.status.success() {
            return Err(refused(kind, "mcp add", &output));
        }
        if !configured(setup, entry).await? {
            return Err(failure("the harness did not confirm the saved MCP entry"));
        }
        Ok(true)
    })
}

/// One harness's setup commands: where they run, and the bindings `install` checked.
#[derive(Clone, Copy)]
struct Setup<'a> {
    root: &'a Path,
    executable: &'a Path,
    kind: Kind,
    config: &'a [(Provider, &'static str, std::path::PathBuf)],
}
async fn configured(setup: Setup<'_>, entry: &[&str]) -> Result<bool> {
    let kind = setup.kind;
    match kind {
        Kind::Claude => {
            let output = run(setup, &["mcp", "get", "stateengine"]).await?;
            if !output.status.success() {
                if output
                    .stderr
                    .starts_with(b"No MCP server named \"stateengine\".")
                {
                    return Ok(false);
                }
                return Err(refused(kind, "mcp get", &output));
            }
            let text = std::str::from_utf8(&output.stdout)
                .map_err(|_| failure("the harness returned unreadable MCP configuration"))?;
            let field = |name: &str| text.lines().find_map(|line| line.trim().strip_prefix(name));
            if field("Status: ").is_some_and(|status| {
                status.contains("Rejected")
                    || status.contains("Disabled")
                    || status.contains("Blocked")
            }) {
                return Err(failure(
                    "the existing stateengine server is rejected or disabled; preserve that choice",
                ));
            }
            if field("Type: ") != Some("stdio")
                || field("Command: ") != Some("se")
                || field("Args: ") != Some(entry.join(" ").as_str())
            {
                return Err(failure(
                    "a different stateengine MCP entry already exists; preserve or remove it before retrying",
                ));
            }
            let mut lines = text.lines();
            let environment = lines.find(|line| line.trim() == "Environment:");
            if environment.is_some() && lines.next().is_some_and(|line| !line.trim().is_empty()) {
                return Err(failure(
                    "the existing stateengine entry has an environment; preserve or remove it before retrying",
                ));
            }
            match field("Scope: ") {
                Some(scope) if scope.starts_with("Project config") => Ok(false),
                Some(scope)
                    if scope.starts_with("Local config") || scope.starts_with("User config") =>
                {
                    Ok(true)
                }
                _ => Err(failure(
                    "the harness did not report the existing entry's scope",
                )),
            }
        }
        Kind::Codex => {
            let output = run(setup, &["mcp", "list", "--json"]).await?;
            if !output.status.success() {
                return Err(refused(kind, "mcp list", &output));
            }
            let rows: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
                .map_err(|_| failure("the harness returned unreadable MCP configuration"))?;
            let mut matches = rows
                .iter()
                .filter(|row| row.get("name").and_then(|v| v.as_str()) == Some("stateengine"));
            let Some(row) = matches.next() else {
                return Ok(false);
            };
            let transport = &row["transport"];
            if matches.next().is_some()
                || row["enabled"] != true
                || transport["type"] != "stdio"
                || transport["command"] != "se"
                || transport["args"] != serde_json::json!(entry)
                || !transport["cwd"].is_null()
                || !transport["env"].is_null()
                || !(transport["env_vars"].is_null()
                    || transport["env_vars"] == serde_json::json!([]))
            {
                return Err(failure(
                    "a different stateengine MCP entry already exists; preserve or remove it before retrying",
                ));
            }
            Ok(true)
        }
    }
}

async fn run(setup: Setup<'_>, args: &[&str]) -> Result<std::process::Output> {
    let mut command = Command::from(se_proc::background_command(setup.executable));
    // Harness commands run in `root`, so they get the absolute paths `install` checked.
    command.envs(setup.config.iter().map(|(_, name, dir)| (name, dir)));
    command
        .args(args)
        .current_dir(setup.root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| failure(&format!("could not start harness setup: {error}")))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| failure("harness stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| failure("harness stderr is unavailable"))?;
    let collected = tokio::time::timeout(Duration::from_secs(30), async {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut stdout = stdout.take(LIMIT + 1);
        let mut stderr = stderr.take(LIMIT + 1);
        let (status, _, _) = tokio::try_join!(
            child.wait(),
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err)
        )?;
        Ok::<_, std::io::Error>(std::process::Output {
            status,
            stdout: out,
            stderr: err,
        })
    })
    .await;
    let output = match collected {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            stop(&mut child).await?;
            return Err(failure(&format!(
                "could not observe harness setup: {error}"
            )));
        }
        Err(_) => {
            stop(&mut child).await?;
            return Err(failure(
                "harness setup timed out; retry the original command",
            ));
        }
    };
    if output.stdout.len() as u64 > LIMIT || output.stderr.len() as u64 > LIMIT {
        return Err(failure(
            "harness setup output exceeded its observation budget",
        ));
    }
    Ok(output)
}

async fn stop(child: &mut tokio::process::Child) -> Result<()> {
    if child
        .try_wait()
        .map_err(|error| failure(&format!("could not observe harness exit: {error}")))?
        .is_none()
    {
        child
            .kill()
            .await
            .map_err(|error| failure(&format!("could not stop harness setup: {error}")))?;
    }
    Ok(())
}

/// A refusal named by fixed operation and exit only; the harness's words go to this terminal.
fn refused(kind: Kind, operation: &str, output: &std::process::Output) -> SeError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if let Some(line) = stderr.lines().find(|line| !line.trim().is_empty()) {
        let shown = line.trim().chars().filter(|c| !c.is_control());
        let shown: String = shown.take(200).collect();
        eprintln!("{} said: {shown}", kind.label());
    }
    let (label, name, status) = (kind.label(), kind.name(), output.status);
    failure(&format!("{label} `{name} {operation}` failed ({status})"))
}
fn failure(reason: &str) -> SeError {
    SeError::invalid("MCP setup", reason)
}
