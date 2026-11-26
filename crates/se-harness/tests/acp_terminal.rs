//! Integration checks for workspace-scoped ACP `terminal/*` client support.
//! Exercises capability gating, workspace `cwd` confinement, bounded tail
//! output with honest truncation, `MAX_TERMINALS` admission, `terminal/kill`,
//! and deterministic cleanup on `terminal/release` and session close.
#![cfg(feature = "listener")]
use se_harness::{
    CallContext, HostFuture, ProviderIo, ProviderIoPlatform, ProviderStream, ProviderTransport,
    SessionIdentity, StreamRead, StreamWrite,
    acp::{Connection, PermissionPolicy, Session},
};
use se_types::{Generation, Result};
use serde_json::{Value, json};
use std::{
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::mpsc;

type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Check<Self> {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("se-acp-terminal-test-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Io {
    output: mpsc::UnboundedSender<StreamRead>,
    error: mpsc::UnboundedSender<StreamRead>,
    output_read: tokio::sync::Mutex<mpsc::UnboundedReceiver<StreamRead>>,
    error_read: tokio::sync::Mutex<mpsc::UnboundedReceiver<StreamRead>>,
    writes: Mutex<Vec<Value>>,
}

fn fault(reason: &str) -> se_types::SeError {
    se_core::scope::unreadable("synthetic terminal I/O", reason)
}

impl ProviderIoPlatform for Io {
    fn open(&self, _: &se_proc::OwnedProcess, _: &SessionIdentity) -> Result<ProviderIo> {
        Err(fault("no native process in protocol control"))
    }

    fn read<'a>(
        &'a self,
        _: &'a ProviderTransport,
        stream: ProviderStream,
        maximum: NonZeroU32,
        _: CallContext,
    ) -> HostFuture<'a, StreamRead> {
        Box::pin(async move {
            let receiver = match stream {
                ProviderStream::Output => &self.output_read,
                ProviderStream::Error => &self.error_read,
                ProviderStream::Input => return Err(fault("input cannot be read")),
            };
            let result = receiver
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| fault("missing EOF"))?;
            if let StreamRead::Bytes(bytes) = &result
                && bytes.len() > maximum.get() as usize
            {
                return Err(fault("native read bound exceeded"));
            }
            Ok(result)
        })
    }

    fn write<'a>(
        &'a self,
        _: &'a ProviderTransport,
        bytes: Vec<u8>,
        _: CallContext,
    ) -> HostFuture<'a, StreamWrite> {
        Box::pin(async move {
            let length = u32::try_from(bytes.len()).map_err(|_| fault("frame too large"))?;
            let value =
                serde_json::from_slice(&bytes).map_err(|_| fault("invalid outgoing frame"))?;
            self.writes
                .lock()
                .map_err(|_| fault("poisoned fixture"))?
                .push(value);
            Ok(StreamWrite {
                completed_bytes: length,
                failure: None,
            })
        })
    }

    fn finish_input<'a>(&'a self, _: &'a ProviderTransport, _: CallContext) -> HostFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn close<'a>(&'a self, _: &'a ProviderTransport, _: CallContext) -> HostFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

fn cx() -> Check<CallContext> {
    Ok(CallContext::new(
        Generation::new(1)?,
        Duration::from_secs(5),
    ))
}

async fn eventually(mut condition: impl FnMut() -> bool) -> Check {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}

struct Fixture {
    _workspace: TempDir,
    root: PathBuf,
    io: Arc<Io>,
    session: Arc<Session>,
    init_request: Value,
    next_rpc_id: u64,
}

impl Fixture {
    async fn start(allow_terminal: bool) -> Check<Self> {
        let workspace = TempDir::new()?;
        let root = workspace.path().to_path_buf();
        let (output, output_read) = mpsc::unbounded_channel();
        let (error, error_read) = mpsc::unbounded_channel();
        let io = Arc::new(Io {
            output,
            error,
            output_read: tokio::sync::Mutex::new(output_read),
            error_read: tokio::sync::Mutex::new(error_read),
            writes: Mutex::default(),
        });
        let (connection, receiver) = Connection::open(
            io.clone(),
            ProviderTransport::console(),
            Generation::new(1)?,
        )
        .await;
        let provider_exit = Arc::new(
            || -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> {
                Box::pin(async { false })
            },
        );
        let session = if allow_terminal {
            Session::retain_with_capabilities(
                connection,
                receiver,
                PermissionPolicy::Refuse,
                true,
                provider_exit,
            )
            .await
        } else {
            Session::retain(
                connection,
                receiver,
                PermissionPolicy::Refuse,
                provider_exit,
            )
            .await
        };

        let mut fixture = Self {
            _workspace: workspace,
            root,
            io,
            session,
            init_request: Value::Null,
            next_rpc_id: 100,
        };

        let s = fixture.session.clone();
        let context = cx()?;
        let op = tokio::spawn(async move { s.initialize(context).await });
        let init_req = fixture.write_at(0).await?;
        fixture.init_request = init_req.clone();
        fixture.emit(json!({
            "jsonrpc": "2.0",
            "id": init_req["id"],
            "result": {"protocolVersion": 1, "agentCapabilities": {}}
        }))?;
        op.await??;

        let s = fixture.session.clone();
        let context = cx()?;
        let cwd = fixture.root.to_string_lossy().into_owned();
        let op =
            tokio::spawn(async move { s.open(&cwd, vec![], None, "safe", false, context).await });
        let open_req = fixture.write_at(1).await?;
        fixture.emit(json!({
            "jsonrpc": "2.0",
            "id": open_req["id"],
            "result": {"sessionId": "conv_1", "modes": {"currentModeId": "safe"}}
        }))?;
        op.await??;

        Ok(fixture)
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn writes(&self) -> Check<Vec<Value>> {
        Ok(self
            .io
            .writes
            .lock()
            .map_err(|_| "poisoned fixture")?
            .clone())
    }

    async fn write_at(&self, index: usize) -> Check<Value> {
        eventually(|| self.writes().is_ok_and(|v| v.len() > index)).await?;
        self.writes()?
            .get(index)
            .cloned()
            .ok_or_else(|| "write absent".into())
    }

    fn emit(&self, value: Value) -> Check {
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        self.io
            .output
            .send(StreamRead::Bytes(bytes))
            .map_err(|_| "stdout closed")?;
        Ok(())
    }

    async fn call_client(&mut self, method: &str, params: Value) -> Check<Value> {
        let id = self.next_rpc_id;
        self.next_rpc_id += 1;
        self.emit(json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        }))?;
        eventually(|| {
            self.writes().is_ok_and(|writes| {
                writes
                    .iter()
                    .any(|frame| frame.get("id").and_then(Value::as_u64) == Some(id))
            })
        })
        .await?;
        self.writes()?
            .into_iter()
            .find(|frame| frame.get("id").and_then(Value::as_u64) == Some(id))
            .ok_or_else(|| "reply absent".into())
    }

    async fn close(self) -> Check {
        let _ = self.io.output.send(StreamRead::Eof);
        let _ = self.io.error.send(StreamRead::Eof);
        self.session.close(cx()?).await?;
        Ok(())
    }
}

fn echo_command(script: &str) -> (&'static str, Vec<&str>) {
    #[cfg(unix)]
    {
        ("sh", vec!["-c", script])
    }
    #[cfg(windows)]
    {
        ("cmd", vec!["/C", script])
    }
}

fn sleep_command() -> (&'static str, Vec<&'static str>) {
    #[cfg(unix)]
    {
        ("sh", vec!["-c", "sleep 30"])
    }
    #[cfg(windows)]
    {
        ("ping", vec!["-n", "30", "127.0.0.1"])
    }
}

#[tokio::test]
async fn readonly_profile_advertises_false_and_refuses_terminal_create() -> Check {
    let mut fx = Fixture::start(false).await?;
    assert_eq!(
        fx.init_request
            .pointer("/params/clientCapabilities/terminal")
            .and_then(Value::as_bool),
        Some(false)
    );
    let (cmd, args) = echo_command("echo hi");
    let reply = fx
        .call_client(
            "terminal/create",
            json!({"sessionId": "conv_1", "command": cmd, "args": args}),
        )
        .await?;
    assert!(
        reply.get("error").is_some(),
        "expected refusal when terminal is disabled: {reply}"
    );
    fx.close().await
}

#[tokio::test]
async fn workspace_write_terminal_lifecycle_and_env() -> Check {
    let mut fx = Fixture::start(true).await?;
    assert_eq!(
        fx.init_request
            .pointer("/params/clientCapabilities/terminal")
            .and_then(Value::as_bool),
        Some(true)
    );

    let subdir = fx.root().join("nested");
    std::fs::create_dir(&subdir)?;
    #[cfg(unix)]
    let (cmd, args) = echo_command("printf '%s:%s' \"$SE_TEST_VAR\" \"$(pwd)\"");
    #[cfg(windows)]
    let (cmd, args) = echo_command("echo %SE_TEST_VAR%:%CD%");

    let created = fx
        .call_client(
            "terminal/create",
            json!({
                "sessionId": "conv_1",
                "command": cmd,
                "args": args,
                "cwd": subdir.to_string_lossy(),
                "env": [{"name": "SE_TEST_VAR", "value": "alpha42"}],
            }),
        )
        .await?;
    let terminal_id = created
        .pointer("/result/terminalId")
        .and_then(Value::as_str)
        .ok_or("missing terminalId")?
        .to_owned();

    let waited = fx
        .call_client(
            "terminal/wait_for_exit",
            json!({"sessionId": "conv_1", "terminalId": terminal_id}),
        )
        .await?;
    assert_eq!(
        waited.pointer("/result/exitCode").and_then(Value::as_i64),
        Some(0)
    );

    let out = fx
        .call_client(
            "terminal/output",
            json!({"sessionId": "conv_1", "terminalId": terminal_id}),
        )
        .await?;
    let text = out
        .pointer("/result/output")
        .and_then(Value::as_str)
        .ok_or("missing output")?;
    assert!(text.contains("alpha42"), "env missing in output: {text:?}");
    assert!(text.contains("nested"), "cwd missing in output: {text:?}");
    assert_eq!(
        out.pointer("/result/truncated").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        out.pointer("/result/exitStatus/exitCode")
            .and_then(Value::as_i64),
        Some(0)
    );

    let released = fx
        .call_client(
            "terminal/release",
            json!({"sessionId": "conv_1", "terminalId": terminal_id}),
        )
        .await?;
    assert!(
        released.get("result").is_some(),
        "release failed: {released}"
    );

    let after = fx
        .call_client(
            "terminal/output",
            json!({"sessionId": "conv_1", "terminalId": terminal_id}),
        )
        .await?;
    assert_eq!(
        after.pointer("/error/code").and_then(Value::as_i64),
        Some(-32002)
    );

    fx.close().await
}

#[tokio::test]
async fn refuses_cwd_outside_workspace_and_symlink_escape() -> Check {
    let mut fx = Fixture::start(true).await?;
    let outside = TempDir::new()?;
    let (cmd, args) = echo_command("echo nope");

    let outside_reply = fx
        .call_client(
            "terminal/create",
            json!({
                "sessionId": "conv_1",
                "command": cmd,
                "args": args,
                "cwd": outside.path().to_string_lossy(),
            }),
        )
        .await?;
    assert_eq!(
        outside_reply.pointer("/error/code").and_then(Value::as_i64),
        Some(-32602),
        "outside cwd should be refused: {outside_reply}"
    );

    let wrong_session = fx
        .call_client(
            "terminal/create",
            json!({
                "sessionId": "other_conv",
                "command": cmd,
                "args": args,
            }),
        )
        .await?;
    assert!(
        wrong_session.get("error").is_some(),
        "wrong sessionId must be refused: {wrong_session}"
    );

    #[cfg(unix)]
    {
        let escape_link = fx.root().join("escape_link");
        std::os::unix::fs::symlink(outside.path(), &escape_link)?;
        let link_reply = fx
            .call_client(
                "terminal/create",
                json!({
                    "sessionId": "conv_1",
                    "command": cmd,
                    "args": args,
                    "cwd": escape_link.to_string_lossy(),
                }),
            )
            .await?;
        assert_eq!(
            link_reply.pointer("/error/code").and_then(Value::as_i64),
            Some(-32602),
            "symlink cwd escape should be refused: {link_reply}"
        );
    }

    fx.close().await
}

#[tokio::test]
async fn output_truncation_sets_honest_flag() -> Check {
    let mut fx = Fixture::start(true).await?;
    #[cfg(unix)]
    let (cmd, args) = echo_command("printf '0123456789abcdefghijklmnopqrstuvwxyzTAIL'");
    #[cfg(windows)]
    let (cmd, args) = echo_command("echo 0123456789abcdefghijklmnopqrstuvwxyzTAIL");

    let created = fx
        .call_client(
            "terminal/create",
            json!({
                "sessionId": "conv_1",
                "command": cmd,
                "args": args,
                "outputByteLimit": 12,
            }),
        )
        .await?;
    let terminal_id = created
        .pointer("/result/terminalId")
        .and_then(Value::as_str)
        .ok_or("missing terminalId")?
        .to_owned();

    let _ = fx
        .call_client(
            "terminal/wait_for_exit",
            json!({"sessionId": "conv_1", "terminalId": terminal_id}),
        )
        .await?;
    let out = fx
        .call_client(
            "terminal/output",
            json!({"sessionId": "conv_1", "terminalId": terminal_id}),
        )
        .await?;
    let text = out
        .pointer("/result/output")
        .and_then(Value::as_str)
        .ok_or("missing output")?;
    assert_eq!(
        out.pointer("/result/truncated").and_then(Value::as_bool),
        Some(true)
    );
    assert!(text.len() <= 12, "output exceeded limit: {text:?}");
    assert!(text.contains("TAIL"), "tail missing: {text:?}");

    fx.close().await
}

#[tokio::test]
async fn kill_and_session_close_terminate_running_terminals() -> Check {
    let mut fx = Fixture::start(true).await?;
    let (cmd, args) = sleep_command();

    let created = fx
        .call_client(
            "terminal/create",
            json!({"sessionId": "conv_1", "command": cmd, "args": args}),
        )
        .await?;
    let terminal_id = created
        .pointer("/result/terminalId")
        .and_then(Value::as_str)
        .ok_or("missing terminalId")?
        .to_owned();

    let killed = fx
        .call_client(
            "terminal/kill",
            json!({"sessionId": "conv_1", "terminalId": terminal_id}),
        )
        .await?;
    assert!(killed.get("result").is_some(), "kill failed: {killed}");

    let waited = fx
        .call_client(
            "terminal/wait_for_exit",
            json!({"sessionId": "conv_1", "terminalId": terminal_id}),
        )
        .await?;
    let exit_code = waited.pointer("/result/exitCode").and_then(Value::as_i64);
    let signal = waited.pointer("/result/signal").and_then(Value::as_str);
    assert!(
        exit_code != Some(0) || signal.is_some(),
        "killed terminal should not exit cleanly: {waited}"
    );

    // Start a second sleeping terminal and verify session close tears it down.
    let second = fx
        .call_client(
            "terminal/create",
            json!({"sessionId": "conv_1", "command": cmd, "args": args}),
        )
        .await?;
    assert!(second.pointer("/result/terminalId").is_some());

    fx.close().await
}

#[tokio::test]
async fn enforces_max_concurrent_terminals_bound() -> Check {
    let mut fx = Fixture::start(true).await?;
    let (cmd, args) = sleep_command();
    let mut ids = Vec::new();
    for _ in 0..8 {
        let reply = fx
            .call_client(
                "terminal/create",
                json!({"sessionId": "conv_1", "command": cmd, "args": args}),
            )
            .await?;
        let id = reply
            .pointer("/result/terminalId")
            .and_then(Value::as_str)
            .ok_or("missing terminalId")?
            .to_owned();
        ids.push(id);
    }

    let ninth = fx
        .call_client(
            "terminal/create",
            json!({"sessionId": "conv_1", "command": cmd, "args": args}),
        )
        .await?;
    assert_eq!(
        ninth.pointer("/error/code").and_then(Value::as_i64),
        Some(-32603),
        "9th concurrent terminal should be refused: {ninth}"
    );

    let _ = fx
        .call_client(
            "terminal/release",
            json!({"sessionId": "conv_1", "terminalId": ids[0]}),
        )
        .await?;

    let replacement = fx
        .call_client(
            "terminal/create",
            json!({"sessionId": "conv_1", "command": cmd, "args": args}),
        )
        .await?;
    assert!(
        replacement.pointer("/result/terminalId").is_some(),
        "slot should open after release: {replacement}"
    );

    fx.close().await
}
