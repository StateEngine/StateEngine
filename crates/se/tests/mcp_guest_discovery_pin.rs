//! Reviewer-owned pin: a harness's server health check must leave no host
//! running, and the host-less guest catalogue must equal the host-served one.
//! No provider account is used; the provider is a synthetic stand-in that
//! really starts the registered server and lists its tools, as a real
//! harness's `mcp get` readback does.
#![cfg(target_os = "linux")]

#[path = "support/installation_claim_guard.rs"]
mod installation_claim_guard;
#[path = "../../test-support/provider_home.rs"]
mod provider_home;
#[path = "../../se-host/tests/support/wave2_host_fixture.rs"]
mod support;
use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn Error>>;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("cannot remove owned fixture: {error}");
        }
    }
}

/// Process ids whose command line names this state home, read from /proc.
fn processes_naming(home: &Path) -> Result<Vec<(u32, String)>, Box<dyn Error>> {
    let needle = home.to_str().ok_or("non-UTF8 home")?.as_bytes().to_vec();
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        if cmdline
            .windows(needle.len())
            .any(|w| w == needle.as_slice())
        {
            found.push((pid, String::from_utf8_lossy(&cmdline).replace('\0', " ")));
        }
    }
    Ok(found)
}

fn stub_provider(root: &Path, se: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let path = root.join("claude-stub");
    // `mcp get` behaves like a harness health check: it spawns the saved
    // command, performs the MCP handshake and a tool listing, then closes it.
    let script = format!(
        r#"#!/bin/sh
entry_file="$CLAUDE_CONFIG_DIR/synthetic-mcp-entry"
if [ "$*" = "--version" ]; then echo "2.1.318 (Claude Code)"; exit 0; fi
if [ "$*" = "mcp get stateengine" ]; then
  if [ ! -f "$entry_file" ]; then echo 'No MCP server named "stateengine".' >&2; exit 1; fi
  entry=$(cat "$entry_file")
  reply=$(printf '%s\n%s\n%s\n' \
    '{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2024-11-05","capabilities":{{}},"clientInfo":{{"name":"synthetic-health-check","version":"1"}}}}}}' \
    '{{"jsonrpc":"2.0","method":"notifications/initialized"}}' \
    '{{"jsonrpc":"2.0","id":2,"method":"tools/list"}}' | "{se}" $entry 2>/dev/null)
  case "$reply" in *'"tools"'*) status=Connected;; *) status=Failed;; esac
  printf 'stateengine:\n  Scope: Local config (private to you in this project)\n  Status: %s\n  Type: stdio\n  Command: se\n  Args: %s\n  Environment:\n' "$status" "$entry"
  exit 0
fi
if [ "$1 $2 $3 $4 $5 $6 $7" = "mcp add --scope local stateengine -- se" ]; then
  shift 7; printf '%s' "$*" > "$entry_file"; exit 0
fi
exit 91
"#,
        se = se.display()
    );
    fs::write(&path, script)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

fn run(
    se: &Path,
    root: &Path,
    config: &Path,
    home: &Path,
    repo: &Path,
    args: &[&str],
) -> Result<String, Box<dyn Error>> {
    let owner = root.join("owner");
    let mut command = Command::new(se);
    command.env_clear();
    provider_home::isolate_at(
        &mut command,
        root,
        &owner,
        &owner.join(".codex"),
        &owner.join("claude"),
    );
    let output = command
        .env("XDG_CONFIG_HOME", owner.join("config"))
        .env("SE_CONFIG", config)
        .args(["--json", "--home"])
        .arg(home)
        .args(args)
        .current_dir(repo)
        .output()?;
    assert!(
        output.status.success(),
        "{args:?}: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

/// Bug: a harness's server check started a host under the harness's own
/// environment, which later served launches without the account credential.
#[test]
fn init_readback_leaves_no_host_running() -> Check {
    let _account = installation_claim_guard::acquire()?;
    let root = std::env::temp_dir().join(format!(
        "se-guest-pin-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir_all(root.join("owner/claude"))?;
    let scratch = Scratch(root.clone());
    let (home, repo) = (root.join("state"), root.join("repo"));
    fs::create_dir(&repo)?;
    let se = PathBuf::from(env!("CARGO_BIN_EXE_se"));
    let provider = stub_provider(&root, &se)?;
    let config = root.join("state-engine.toml");
    fs::write(
        &config,
        format!(
            "version = 1\n[providers.claude]\ncommand = {:?}\n",
            provider.to_str().ok_or("path")?
        ),
    )?;
    let result = (|| -> Check {
        run(
            &se,
            &root,
            &config,
            &home,
            &repo,
            &[
                "init",
                "--provider",
                "claude",
                "--key",
                "synthetic-guest-pin",
            ],
        )?;
        let entry = fs::read_to_string(root.join("owner/claude/synthetic-mcp-entry"))?;
        assert!(
            entry.ends_with("mcp"),
            "setup did not register the server: {entry}"
        );
        let status = run(&se, &root, &config, &home, &repo, &["status"])?;
        let status: serde_json::Value = serde_json::from_str(&status)?;
        let state = status
            .pointer("/value/runtime/state")
            .or_else(|| status.pointer("/runtime/state"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("runtime state absent: {status}"))?;
        assert_eq!(state, "stopped", "init's readback left a host running");
        let left = processes_naming(&home)?;
        assert!(
            left.is_empty(),
            "processes still name the state home: {left:?}"
        );
        Ok(())
    })();
    if result.is_err() {
        // Best effort: stop whatever the failed run started, by the product's own door.
        let _ = run(&se, &root, &config, &home, &repo, &["stop", "--yes"]);
    }
    drop(scratch);
    result
}

// ---- host-less guest catalogue equals the host-served catalogue ----

mod served {
    use super::support;
    use super::support::*;
    use se_host::*;
    use se_store::*;
    use serde_json::{Value, json};
    use std::{collections::BTreeSet, path::Path, process::Stdio, time::Duration};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn stdio_list(
        home: &Path,
        capability: Option<&str>,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_se"));
        command.args(["--home"]).arg(home).args(["mcp", "--stdio"]);
        for (name, _) in std::env::vars_os() {
            let text = name.to_string_lossy();
            if text.starts_with("SE_")
                || text.starts_with("STATEENGINE_")
                || text.starts_with("SECODE_")
                || matches!(text.as_ref(), "CLAUDECODE" | "CODEX_THREAD_ID" | "CODEX_CI")
            {
                command.env_remove(name);
            }
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let mut input = child.stdin.take().ok_or("stdio input absent")?;
        let params = capability.map_or_else(
            || json!({}),
            |c| json!({"_meta":{"stateengine.session-capability-v1":c}}),
        );
        for request in [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
                "protocolVersion":"2024-11-05","capabilities":{},
                "clientInfo":{"name":"synthetic-discovery-client","version":"1"}}}),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":params}),
        ] {
            input.write_all(&serde_json::to_vec(&request)?).await?;
            input.write_all(b"\n").await?;
        }
        drop(input);
        let stdout = child.stdout.take().ok_or("stdio output absent")?;
        let mut bytes = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(20),
            stdout.take(1_048_577).read_to_end(&mut bytes),
        )
        .await??;
        let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
        require(status.success(), format!("stdio process failed: {status}"))?;
        let replies = bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(serde_json::from_slice::<Value>)
            .collect::<Result<Vec<_>, _>>()?;
        require(
            replies.len() == 2,
            format!("unexpected stdio replies: {replies:?}"),
        )?;
        require(
            replies[0]["result"]["protocolVersion"].is_string(),
            "initialize failed",
        )?;
        Ok(replies[1].clone())
    }

    fn catalogue(reply: &Value) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
        let tools = reply["result"]["tools"]
            .as_array()
            .ok_or_else(|| format!("no tools: {reply}"))?;
        require(!tools.is_empty(), "empty catalogue")?;
        let names: BTreeSet<_> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        require(names.len() == tools.len(), "duplicate or unnamed tool")?;
        Ok(tools.clone())
    }

    /// Seed one active session with a synthetic capability and close the writer.
    fn seed_session(f: &Fixture, session: &se_types::SessionId, capability: &str) -> Check {
        let (mut writer, lease) = direct(f)?;
        let now = now()?;
        let mut events = vec![
            EventBody::ProfileSaved {
                agent: f.b.clone(),
                profile: se_store::Profile {
                    provider_settings: Default::default(),
                    provider: Provider::Claude,
                    model: None,
                    permission: PermissionProfile::WorkspaceWrite,
                    harness: None,
                    named_profile: "default".into(),
                    effort: None,
                },
                expected: Expected::Absent,
            },
            support::session::prepared(f, session, &f.b),
            support::session::activated(session)?,
        ];
        let issued = credential(
            session,
            "session",
            capability,
            now + 300_000_000,
            now + 60_000_000,
        )?;
        let EventBody::CredentialIssued { credential: id, .. } = &issued else {
            return Err("credential shape".into());
        };
        let id = *id;
        events.push(issued);
        events.push(EventBody::CredentialActivated {
            credential: id,
            session: session.clone(),
            expected: revision(1)?,
            first_request: Some(support::session::record()?),
        });
        let request = Some(fixture::request("guest-pin-fixture")?);
        writer.append(f.batch(f.owner_project(), request, events)?, &*lease)?;
        writer.close()?;
        Ok(())
    }

    /// Both catalogues, fetched against the running host, must be identical.
    async fn compare(home: &Path, capability: &str) -> Check {
        // Served by the running host for an authenticated session.
        let served = catalogue(&stdio_list(home, Some(capability)).await?)?;
        // Answered by a guest with no session: must be identical.
        let guest = catalogue(&stdio_list(home, None).await?)?;
        require(
            guest == served,
            "host-less guest catalogue differs from the host-served catalogue",
        )
    }

    async fn run_host(
        initialized: HostProcessInitialization,
        f: &Fixture,
        handle: tokio::runtime::Handle,
        capability: &str,
    ) -> Check {
        let mut host =
            HostedRuntime::prepare(initialized, start(f)?, handle.clone(), &bound()?).await?;
        host.configure(se_config::config_policy::ConfigFile::default())?;
        let se = Path::new(env!("CARGO_BIN_EXE_se")).to_path_buf();
        host.install_native_atlas()?;
        let options = ProcessOptions {
            helper_executable: se_types::NativePath::from_local(se)?,
            linux_delegation: se_proc::LinuxDelegation::CurrentScope,
            maximum_sessions: 2,
            restore_deadline_ms: ProcessOptions::DEFAULT_RESTORE_DEADLINE_MS,
            stop_grace_ms: None,
        };
        let (_coordinator, reconciliation) =
            LaunchCoordinator::install(&mut host, options, &bound()?).await?;
        require(
            reconciliation.unproved.is_empty(),
            "native reconciliation debt",
        )?;
        let listener = host.listen(handle, &bound()?).await?;
        let stop = host.local_stop();
        let client = async {
            let result = compare(&f.options.state_directory, capability).await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let _ = exit.finish(&bound()?).await;
        result
    }

    #[test]
    fn guest_catalogue_equals_the_host_served_catalogue() -> Check {
        let initialized = initialize_host_process()?;
        let f = Fixture::new()?;
        seed(&f)?;
        let session = support::session::session()?;
        let capability = format!("sec1.{session}.{}", "A".repeat(43));
        seed_session(&f, &session, &capability)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(2)
            .build()?;
        runtime.block_on(run_host(
            initialized,
            &f,
            runtime.handle().clone(),
            &capability,
        ))
    }
}
