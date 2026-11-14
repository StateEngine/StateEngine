//! The stdio door memoizes a capability's bound principal. The memo must never
//! stand in for host admission: a capability that expires while its door stays
//! up is refused on every later call (caller field or not), and a failed first
//! identity read is never remembered as a binding.
#![cfg(any(target_os = "linux", windows))]
use se_host::*;
use se_store::*;
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[path = "../../se-host/tests/support/wave2_host_fixture.rs"]
mod support;
use support::*;

struct Door {
    child: tokio::process::Child,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: BufReader<tokio::process::ChildStdout>,
    next_id: u64,
}
impl Door {
    async fn spawn(home: &Path) -> Result<Self, Box<dyn std::error::Error>> {
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
        let stdin = child.stdin.take().ok_or("stdio input absent")?;
        let stdout = child.stdout.take().ok_or("stdio output absent")?;
        let mut door = Self {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            next_id: 0,
        };
        let init = door
            .request(
                "initialize",
                json!({"protocolVersion":"2024-11-05","capabilities":{},
                       "clientInfo":{"name":"synthetic-caller-client","version":"1"}}),
            )
            .await?;
        require(
            init["result"]["protocolVersion"].is_string(),
            format!("initialize failed: {init}"),
        )?;
        door.notify("notifications/initialized").await?;
        Ok(door)
    }
    async fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        self.next_id += 1;
        let frame = json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params});
        let stdin = self.stdin.as_mut().ok_or("stdio input closed")?;
        stdin.write_all(&serde_json::to_vec(&frame)?).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        let mut line = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(20),
            self.stdout.read_until(b'\n', &mut line),
        )
        .await??;
        let reply: Value = serde_json::from_slice(&line)?;
        require(
            reply["id"] == self.next_id,
            format!("reply id mismatch: {reply}"),
        )?;
        Ok(reply)
    }
    async fn notify(&mut self, method: &str) -> Result<(), Box<dyn std::error::Error>> {
        let frame = json!({"jsonrpc":"2.0","method":method});
        let stdin = self.stdin.as_mut().ok_or("stdio input closed")?;
        stdin.write_all(&serde_json::to_vec(&frame)?).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;
        Ok(())
    }
    async fn tool(
        &mut self,
        name: &str,
        arguments: Value,
        capability: &str,
    ) -> Result<Value, Box<dyn std::error::Error>> {
        let params = json!({"name": name, "arguments": arguments,
            "_meta":{"stateengine.session-capability-v1": capability}});
        self.request("tools/call", params).await
    }
    async fn close(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.stdin.take();
        let status = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await??;
        require(status.success(), format!("stdio process failed: {status}"))?;
        Ok(())
    }
}

const LIFE_US: i64 = 25_000_000;
const WRONG_AGENT: &str = "ag_00000000-0000-0000-0000-000000000000";

/// One synthetic active session credential for agent `b`, expiring `life_us` from now.
fn provision(f: &Fixture, life_us: i64) -> Result<String, Box<dyn std::error::Error>> {
    let (mut writer, lease) = direct(f)?;
    let session = support::session::session()?;
    // Canonical capability shape, entirely synthetic, naming this session.
    let capability = format!("sec1.{session}.{}", "B".repeat(43));
    let now = now()?;
    let mut events = vec![
        EventBody::ProfileSaved {
            agent: f.b.clone(),
            profile: se_store::Profile {
                provider: Provider::Claude,
                model: None,
                harness: None,
                permission: PermissionProfile::WorkspaceWrite,
                named_profile: "default".into(),
                effort: None,
            },
            expected: Expected::Absent,
        },
        support::session::prepared(f, &session, &f.b),
        support::session::activated(&session)?,
    ];
    let issued = credential(
        &session,
        "session",
        &capability,
        now + life_us,
        now + (life_us / 2).min(60_000_000),
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
        first_request: support::session::record()?,
    });
    writer.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("stale-capability-fixture")?),
            events,
        )?,
        &*lease,
    )?;
    writer.close()?;
    drop(lease);
    Ok(capability)
}

fn is_error(reply: &Value) -> bool {
    reply["result"]["isError"] == true
}

fn text(reply: &Value) -> &str {
    reply["result"]["content"][0]["text"].as_str().unwrap_or("")
}

fn runtime() -> Result<tokio::runtime::Runtime, Box<dyn std::error::Error>> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?)
}

#[test]
fn expired_capability_is_refused_after_its_principal_was_memoized() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let capability = provision(&f, LIFE_US)?;
    let expires_at = now()? + LIFE_US;
    let bound_agent = f.b.as_str().to_owned();
    let runtime = runtime()?;
    runtime.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, runtime.handle().clone(), &bound()?)
                .await?;
        host.configure(se_core::config_policy::ConfigFile::default())?;
        let listener = host.listen(runtime.handle().clone(), &bound()?).await?;
        let stop = host.local_stop();
        let state_dir = f.options.state_directory.clone();
        let client = async {
            let result = stale(&state_dir, &capability, &bound_agent, expires_at).await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        result?;
        require(
            report.transport_closed && report.endpoint_retired && report.errors.is_empty(),
            "runtime shutdown incomplete",
        )
    })
}

async fn stale(state_dir: &Path, capability: &str, agent: &str, expires_at: i64) -> Check {
    let mut door = Door::spawn(state_dir).await?;
    // Warm the session channel with a call that reads no principal.
    let mut warm = false;
    for _ in 0..5 {
        let reply = door
            .tool("stateengine_whoami", json!({}), capability)
            .await?;
        if !is_error(&reply) {
            warm = true;
            break;
        }
    }
    require(warm, "setup: the host never answered a live capability")?;
    let live = door
        .tool("stateengine_whoami", json!({"agent_id": agent}), capability)
        .await?;
    require(
        !is_error(&live),
        format!("setup: a live capability was refused (slow start?): {live}"),
    )?;
    // The principal is now memoized in the door. Let the credential expire
    // while the door process stays up.
    while now()? <= expires_at + 300_000 {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let matching = door
        .tool("stateengine_whoami", json!({"agent_id": agent}), capability)
        .await?;
    require(
        is_error(&matching),
        format!("expired capability passed a matching caller assertion: {matching}"),
    )?;
    require(
        text(&matching).contains("expired"),
        format!("the refusal must come from host admission and name the expiry: {matching}"),
    )?;
    let bare = door
        .tool("stateengine_whoami", json!({}), capability)
        .await?;
    require(
        is_error(&bare) && text(&bare).contains("expired"),
        format!("expired capability ran an operation: {bare}"),
    )?;
    let wrong = door
        .tool(
            "stateengine_whoami",
            json!({"agent_id": WRONG_AGENT}),
            capability,
        )
        .await?;
    require(
        is_error(&wrong),
        format!("expired capability with a wrong caller field succeeded: {wrong}"),
    )?;
    door.close().await?;
    Ok(())
}

#[test]
fn failed_first_identity_read_is_not_remembered() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let capability = provision(&f, 300_000_000)?;
    let bound_agent = f.b.as_str().to_owned();
    let state_dir = f.options.state_directory.clone();
    let runtime = runtime()?;
    runtime.block_on(async {
        // The door is up before any host: its first identity read must fail.
        let mut door = Door::spawn(&state_dir).await?;
        let early = door
            .tool(
                "stateengine_whoami",
                json!({"agent_id": bound_agent}),
                &capability,
            )
            .await?;
        require(
            is_error(&early),
            format!("a door with no host succeeded: {early}"),
        )?;
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, runtime.handle().clone(), &bound()?)
                .await?;
        host.configure(se_core::config_policy::ConfigFile::default())?;
        let listener = host.listen(runtime.handle().clone(), &bound()?).await?;
        let stop = host.local_stop();
        let client = async {
            let result = recovered(&mut door, &capability, &bound_agent).await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        result?;
        require(
            report.transport_closed && report.endpoint_retired && report.errors.is_empty(),
            "runtime shutdown incomplete",
        )
    })
}

async fn recovered(door: &mut Door, capability: &str, agent: &str) -> Check {
    // A cold connect under load may time out once; a remembered failure never recovers.
    let mut last = Value::Null;
    let mut recovered = false;
    for _ in 0..5 {
        last = door
            .tool("stateengine_whoami", json!({"agent_id": agent}), capability)
            .await?;
        if !is_error(&last) {
            recovered = true;
            break;
        }
    }
    require(
        recovered,
        format!("the door never recovered after the host came up (failure remembered?): {last}"),
    )?;
    let wrong = door
        .tool(
            "stateengine_whoami",
            json!({"agent_id": WRONG_AGENT}),
            capability,
        )
        .await?;
    require(
        is_error(&wrong) && text(&wrong).contains("MCP caller assertion"),
        format!("a recovered door lost its caller assertion: {wrong}"),
    )?;
    door.close().await?;
    Ok(())
}
