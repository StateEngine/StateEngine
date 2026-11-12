//! The stdio door's caller-assertion check must track the authenticated
//! binding: a matching field is accepted and stripped, a mismatching field is
//! refused with the bound value, and repeated calls on one door keep working.
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

#[test]
fn stdio_caller_assertion_tracks_the_authenticated_binding() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let (mut writer, lease) = direct(&f)?;
    let session = support::session::session()?;
    // Canonical capability shape, entirely synthetic, and never written to output.
    let capability = format!("sec1.{session}.{}", "A".repeat(43));
    let now = now()?;
    let mut events = vec![
        EventBody::ProfileSaved {
            agent: f.b.clone(),
            profile: se_store::Profile {
                provider: Provider::Claude,
                model: None,
                permission: PermissionProfile::WorkspaceWrite,
                named_profile: "default".into(),
                effort: None,
            },
            expected: Expected::Absent,
        },
        support::session::prepared(&f, &session, &f.b),
        support::session::activated(&session)?,
    ];
    let issued = credential(
        &session,
        "session",
        &capability,
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
        first_request: support::session::record()?,
    });
    writer.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("caller-assertion-fixture")?),
            events,
        )?,
        &*lease,
    )?;
    writer.close()?;
    drop(lease);
    let bound_agent = f.b.as_str().to_owned();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    runtime.block_on(async {
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, runtime.handle().clone(), &bound()?)
                .await?;
        host.configure(se_core::config_policy::ConfigFile::default())?;
        let listener = host.listen(runtime.handle().clone(), &bound()?).await?;
        let stop = host.local_stop();
        let state_dir = f.options.state_directory.clone();
        let client = async {
            let result = caller_assertions(&state_dir, &capability, &bound_agent).await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        let clean = report.transport_closed
            && report.endpoint_retired
            && matches!(report.storage, se_types::Read::Present { .. })
            && report.pending.is_empty()
            && report.errors.is_empty();
        if let Err(error) = result {
            return Err(format!(
                "{error}; shutdown complete={clean}, pending={:?}",
                report.pending
            )
            .into());
        }
        require(
            clean,
            format!("runtime shutdown incomplete: pending={:?}", report.pending),
        )
    })
}

async fn caller_assertions(state_dir: &Path, capability: &str, bound_agent: &str) -> Check {
    let mut door = Door::spawn(state_dir).await?;
    let baseline = door
        .tool("stateengine_whoami", json!({}), capability)
        .await?;
    require(
        baseline["result"]["isError"] == false,
        format!("baseline whoami failed: {baseline}"),
    )?;
    let wrong = door
        .tool(
            "stateengine_whoami",
            json!({"agent_id":"ag_00000000-0000-0000-0000-000000000000"}),
            capability,
        )
        .await?;
    require(
        wrong["result"]["isError"] == true,
        format!("mismatched agent_id was accepted: {wrong}"),
    )?;
    let text = wrong["result"]["content"][0]["text"].as_str().unwrap_or("");
    require(
        text.contains("MCP caller assertion"),
        format!("refusal does not name the caller assertion: {wrong}"),
    )?;
    let right = door
        .tool(
            "stateengine_whoami",
            json!({"agent_id": bound_agent}),
            capability,
        )
        .await?;
    require(
        right["result"]["isError"] == false,
        format!("matching agent_id was refused: {right}"),
    )?;
    require(
        right["result"]["structuredContent"] == baseline["result"]["structuredContent"],
        "matching assertion changed the result",
    )?;
    let again = door
        .tool(
            "stateengine_whoami",
            json!({"agent_id": bound_agent}),
            capability,
        )
        .await?;
    require(
        again["result"]["isError"] == false,
        format!("repeated call on the same door failed: {again}"),
    )?;
    door.close().await?;
    Ok(())
}
