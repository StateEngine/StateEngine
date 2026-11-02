//! Protects: G1 / 70 §2.1 — an initialized owner home and ambient owner access
//! never supply a missing or invalid per-call capability on the real stdio door.
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, ChildStdin, Command, Output, Stdio},
    sync::mpsc::{Receiver, sync_channel},
    time::{Duration, Instant},
};
type Check = Result<(), Box<dyn std::error::Error>>;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;

fn command(image: &Path, home: &Path) -> Command {
    let mut command = Command::new(image);
    command.arg("--home").arg(home);
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
    command
}
fn checked(output: Output) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if !output.status.success() {
        return Err(format!(
            "public CLI failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}
struct Rpc {
    child: Child,
    input: Option<ChildStdin>,
    replies: Receiver<Result<serde_json::Value, String>>,
}
impl Rpc {
    fn open(image: &Path, home: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = command(image, home)
            .args(["mcp", "--stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().ok_or("MCP stdin absent")?;
        let stdout = child.stdout.take().ok_or("MCP stdout absent")?;
        let (sender, replies) = sync_channel(4);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                let result = (&mut reader).take(1_048_577).read_until(b'\n', &mut line);
                match result {
                    Ok(0) => break,
                    Ok(_) if line.len() <= 1_048_576 => {
                        if sender
                            .send(serde_json::from_slice(&line).map_err(|error| error.to_string()))
                            .is_err()
                        {
                            break;
                        }
                    }
                    other => {
                        let _ =
                            sender.send(Err(format!("bounded MCP frame read failed: {other:?}")));
                        break;
                    }
                }
            }
        });
        Ok(Self {
            child,
            input: Some(input),
            replies,
        })
    }
    fn send(&mut self, value: serde_json::Value) -> Check {
        let input = self.input.as_mut().ok_or("MCP input closed")?;
        serde_json::to_writer(&mut *input, &value)?;
        input.write_all(b"\n")?;
        input.flush()?;
        Ok(())
    }
    fn call(
        &mut self,
        id: u64,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        self.send(serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if Instant::now() >= deadline {
                return Err("MCP response deadline expired".into());
            }
            let reply = self
                .replies
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))??;
            if reply.get("id").is_none() {
                continue;
            }
            assert_eq!(reply["id"], id, "MCP returned an unrelated response");
            assert_eq!(reply["jsonrpc"], "2.0");
            return Ok(reply);
        }
    }
}
impl Drop for Rpc {
    fn drop(&mut self) {
        drop(self.input.take());
        let until = Instant::now() + Duration::from_secs(1);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < until => {
                    std::thread::park_timeout(Duration::from_millis(10))
                }
                _ => break,
            }
        }
        // This unreaped Child is the exact process we spawned; its PID cannot be reused.
        if let Err(error) = self
            .child
            .kill()
            .and_then(|()| self.child.wait().map(|_| ()))
        {
            eprintln!(
                "MCP judge retains exact owned child {}: {error}",
                self.child.id()
            );
        }
    }
}

/// Protects: G1 — real stdio MCP refuses missing/invalid identity instead of owner fallback.
#[test]
fn stdio_tools_never_inherit_the_initialized_owners_authority() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let f = std::mem::ManuallyDrop::new(fixture::Fixture::new()?);
    println!(
        "stdio judge private home (retained on failure): {}",
        f.home.display()
    );
    let home = &f.options.state_directory;
    let image = Path::new(env!("CARGO_BIN_EXE_se"));
    let repo = f.home.join("repository");
    std::fs::create_dir(&repo)?;
    checked(
        command(image, home)
            .args(["--json", "init", "--repo"])
            .arg(&repo)
            .output()?,
    )?;
    // Positive owner control: this same home really has readable private agent state.
    checked(
        command(image, home)
            .args(["--json", "agent", "show", "main"])
            .current_dir(&repo)
            .output()?,
    )?;
    let mut rpc = Rpc::open(image, home)?;
    let initialized = rpc.call(1, "initialize", serde_json::json!({"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"independent-authority-judge","version":"1"}}))?;
    assert!(
        initialized["result"]["protocolVersion"].is_string(),
        "initialize failed: {initialized}"
    );
    rpc.send(serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
    let ping = rpc.call(2, "ping", serde_json::json!({}))?;
    assert!(
        ping.get("result").is_some(),
        "anonymous ping failed: {ping}"
    );
    for (id, params) in [
        (
            3,
            serde_json::json!({"name":"stateengine_status","arguments":{}}),
        ),
        (
            4,
            serde_json::json!({"name":"stateengine_status","arguments":{},"_meta":{"stateengine.session-capability-v1":"sec1.invalid.invalid"}}),
        ),
    ] {
        let reply = rpc.call(id, "tools/call", params)?;
        let typed_refusal = reply
            .get("error")
            .or_else(|| (reply["result"]["isError"] == true).then_some(&reply["result"]))
            .ok_or_else(|| format!("tool without verified session returned success: {reply}"))?;
        let text = typed_refusal.to_string();
        assert!(
            text.contains("session-required") || text.contains("capability-invalid"),
            "identity refusal lost its reason: {reply}"
        );
    }
    drop(rpc);
    drop(std::mem::ManuallyDrop::into_inner(f));
    Ok(())
}
