//! Independent session controls drive the production connection's wire reader.
//! Synthetic native I/O does not qualify a provider, process scope or sandbox.
use crate::{
    CallContext, HostFuture, ProviderIo, ProviderIoPlatform, ProviderStream, ProviderTransport,
    SessionIdentity, StreamRead, StreamWrite,
    acp::{CapturedMessage, Connection, PermissionPolicy, Session},
};
use se_types::{Generation, Result};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{Semaphore, mpsc};
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
enum Plan {
    Complete,
    Zero,
    Partial,
    Held(Arc<Semaphore>),
}
struct Io {
    output: mpsc::UnboundedSender<StreamRead>,
    error: mpsc::UnboundedSender<StreamRead>,
    output_read: tokio::sync::Mutex<mpsc::UnboundedReceiver<StreamRead>>,
    error_read: tokio::sync::Mutex<mpsc::UnboundedReceiver<StreamRead>>,
    writes: Mutex<Vec<Value>>,
    plans: Mutex<VecDeque<Plan>>,
}
fn fault(reason: &str) -> se_types::SeError {
    se_core::scope::unreadable("synthetic session I/O", reason)
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
        cx: CallContext,
    ) -> HostFuture<'a, StreamWrite> {
        Box::pin(async move {
            let value =
                serde_json::from_slice(&bytes).map_err(|_| fault("invalid outgoing frame"))?;
            self.writes
                .lock()
                .map_err(|_| fault("poisoned fixture"))?
                .push(value);
            let plan = self
                .plans
                .lock()
                .map_err(|_| fault("poisoned fixture"))?
                .pop_front()
                .unwrap_or(Plan::Complete);
            let complete = match plan {
                Plan::Complete => true,
                Plan::Zero => {
                    return Ok(StreamWrite {
                        completed_bytes: 0,
                        failure: Some(fault("synthetic zero-byte refusal").body),
                    });
                }
                Plan::Partial => false,
                Plan::Held(gate) => tokio::time::timeout(cx.timeout, gate.acquire())
                    .await
                    .is_ok_and(|v| v.is_ok()),
            };
            Ok(StreamWrite {
                completed_bytes: if complete {
                    u32::try_from(bytes.len()).map_err(|_| fault("frame too large"))?
                } else {
                    1
                },
                failure: (!complete).then(|| fault("synthetic incomplete write").body),
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
        Duration::from_secs(3),
    ))
}
async fn eventually(mut condition: impl FnMut() -> bool) -> Check {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    Ok(())
}
struct Fixture {
    io: Arc<Io>,
    connection: Arc<Connection>,
    session: Arc<Session>,
    emitted: u64,
}
impl Fixture {
    async fn new(policy: PermissionPolicy) -> Check<Self> {
        let (output, output_read) = mpsc::unbounded_channel();
        let (error, error_read) = mpsc::unbounded_channel();
        let io = Arc::new(Io {
            output,
            error,
            output_read: tokio::sync::Mutex::new(output_read),
            error_read: tokio::sync::Mutex::new(error_read),
            writes: Mutex::default(),
            plans: Mutex::default(),
        });
        let (connection, receiver) = Connection::open(
            io.clone(),
            ProviderTransport::console(),
            Generation::new(1)?,
        )
        .await;
        let session = Session::retain(connection.clone(), receiver, policy).await;
        Ok(Self {
            io,
            connection,
            session,
            emitted: 0,
        })
    }
    fn writes(&self) -> Check<Vec<Value>> {
        Ok(self
            .io
            .writes
            .lock()
            .map_err(|_| "poisoned fixture")?
            .clone())
    }
    async fn write(&self, index: usize) -> Check<Value> {
        eventually(|| self.writes().is_ok_and(|v| v.len() > index)).await?;
        self.writes()?
            .get(index)
            .cloned()
            .ok_or_else(|| "write absent".into())
    }
    fn emit(&mut self, value: Value) -> Check {
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        for chunk in bytes.chunks(65536) {
            self.io
                .output
                .send(StreamRead::Bytes(chunk.to_vec()))
                .map_err(|_| "stdout closed")?;
        }
        self.emitted += 1;
        Ok(())
    }
    async fn settle(&self) -> Check {
        eventually(|| {
            self.session
                .observe()
                .is_ok_and(|s| s.processed >= self.emitted)
        })
        .await
    }
    async fn initialize(&mut self, capabilities: Value) -> Check {
        let session = self.session.clone();
        let context = cx()?;
        let operation = tokio::spawn(async move { session.initialize(context).await });
        let request = self.write(0).await?;
        assert_eq!(request["method"], "initialize");
        assert_eq!(request["params"]["clientCapabilities"]["terminal"], false);
        self.emit(json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":1,"agentCapabilities":capabilities}}))?;
        operation.await??;
        Ok(())
    }
    async fn open(
        &mut self,
        previous: Option<Vec<CapturedMessage>>,
        replay: Vec<Value>,
        mode: &str,
    ) -> Check<bool> {
        let session = self.session.clone();
        let context = cx()?;
        let index = self.writes()?.len();
        let operation = tokio::spawn(async move {
            session
                .open(
                    "/synthetic/workspace",
                    vec![],
                    previous.map(|history| ("conversation", history)),
                    "safe",
                    context,
                )
                .await
        });
        let request = self.write(index).await?;
        assert!(matches!(
            request["method"].as_str(),
            Some("session/new" | "session/load")
        ));
        for update in replay {
            self.update(update)?;
        }
        self.emit(json!({"jsonrpc":"2.0","id":request["id"],"result":{"sessionId":"conversation","modes":{"currentModeId":mode}}}))?;
        Ok(operation.await?.is_ok())
    }
    async fn ready(policy: PermissionPolicy) -> Check<Self> {
        let mut f = Self::new(policy).await?;
        f.initialize(json!({"loadSession":true,"mcpCapabilities":{"http":true}}))
            .await?;
        assert!(f.open(None, vec![], "safe").await?);
        Ok(f)
    }
    fn update(&mut self, update: Value) -> Check {
        self.emit(json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"conversation","update":update}}))
    }
    async fn prompt(&self, key: &str) -> Check<u64> {
        Ok(self
            .session
            .prompt(key.into(), "original input".into(), cx()?)
            .await?)
    }
    async fn complete(&mut self, request: u64, reason: &str) -> Check {
        self.emit(json!({"jsonrpc":"2.0","id":request,"result":{"stopReason":reason}}))?;
        self.settle().await
    }
    async fn stop(self) -> Check {
        let _ = self.io.output.send(StreamRead::Eof);
        let _ = self.io.error.send(StreamRead::Eof);
        self.session.close(cx()?).await?;
        Ok(())
    }
}
fn chunk(kind: &str, text: &str) -> Value {
    json!({"sessionUpdate":kind,"content":{"type":"text","text":text}})
}
async fn open_with_mode(
    f: &mut Fixture,
    required: &'static str,
    reported: Option<&str>,
) -> Check<se_types::Result<String>> {
    let session = f.session.clone();
    let index = f.writes()?.len();
    let context = cx()?;
    let run = tokio::spawn(async move {
        session
            .open("/synthetic/workspace", vec![], None, required, context)
            .await
    });
    let request = f.write(index).await?;
    let mut result = json!({"sessionId":"conversation"});
    if let Some(mode) = reported {
        result["modes"] = json!({"currentModeId":mode});
    }
    f.emit(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))?;
    Ok(run.await?)
}

#[tokio::test]
async fn omitted_mode_accepts_an_agent_with_no_mode_support() -> Check {
    let mut f = Fixture::new(PermissionPolicy::Refuse).await?;
    f.initialize(json!({"mcpCapabilities":{"http":true}}))
        .await?;
    assert_eq!(open_with_mode(&mut f, "", None).await??, "conversation");
    let id = f.prompt("modeless-work").await?;
    f.update(chunk("agent_message_chunk", "modeless answer"))?;
    f.complete(id, "end_turn").await?;
    assert!(
        f.session
            .completed(id)?
            .messages
            .iter()
            .any(|m| m.text == "modeless answer")
    );
    f.stop().await
}

#[tokio::test]
async fn four_uncaptured_turns_refuse_zero_bytes_then_the_same_key_can_retry() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
    let mut completed = Vec::new();
    for n in 0..4 {
        let id = f.prompt(&format!("turn-{n}")).await?;
        f.complete(id, "end_turn").await?;
        completed.push(id);
    }
    let before = f.writes()?.len();
    let failure = f
        .session
        .prompt_tracked("retained-mail".into(), "work".into(), cx()?)
        .await
        .err()
        .ok_or("capture backlog must refuse")?;
    assert_eq!(failure.completed_bytes, Some(0));
    assert_eq!(f.writes()?.len(), before);
    assert!(f.session.observe()?.active_input.is_none());
    f.session.acknowledge(completed[0])?;
    let id = f
        .session
        .prompt_tracked("retained-mail".into(), "work".into(), cx()?)
        .await
        .map_err(|e| e.error)?;
    f.complete(id, "end_turn").await?;
    assert_eq!(f.session.completed(id)?.input_key, "retained-mail");
    f.stop().await
}

#[tokio::test]
async fn admission_timeout_reports_no_write_and_does_not_own_the_retry_key() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
    let gate = Arc::new(Semaphore::new(0));
    f.io.plans
        .lock()
        .map_err(|_| "poisoned fixture")?
        .push_back(Plan::Held(gate.clone()));
    let session = f.session.clone();
    let index = f.writes()?.len();
    let context = cx()?;
    let first = tokio::spawn(async move {
        session
            .prompt_tracked("incumbent".into(), "first".into(), context)
            .await
            .map_err(|e| e.error)
    });
    f.write(index).await?;
    let failure = f
        .session
        .prompt_tracked(
            "retained-mail".into(),
            "next".into(),
            CallContext::new(Generation::new(1)?, Duration::from_millis(20)),
        )
        .await
        .err()
        .ok_or("busy input must refuse")?;
    assert_eq!(failure.completed_bytes, Some(0));
    assert_eq!(f.writes()?.len(), index + 1);
    gate.add_permits(1);
    let id = first.await??;
    f.complete(id, "end_turn").await?;
    f.session.acknowledge(id)?;
    let retry = f
        .session
        .prompt_tracked("retained-mail".into(), "next".into(), cx()?)
        .await
        .map_err(|e| e.error)?;
    f.complete(retry, "end_turn").await?;
    assert_eq!(f.session.completed(retry)?.input_key, "retained-mail");
    f.stop().await
}

#[tokio::test]
async fn zero_byte_native_failure_releases_intent_and_reports_certainty() -> Check {
    let f = Fixture::ready(PermissionPolicy::Refuse).await?;
    f.io.plans
        .lock()
        .map_err(|_| "poisoned fixture")?
        .push_back(Plan::Zero);
    let failure = f
        .session
        .prompt_tracked("zero-byte".into(), "work".into(), cx()?)
        .await
        .err()
        .ok_or("zero writer failure must refuse")?;
    assert_eq!(failure.completed_bytes, Some(0));
    assert!(f.session.observe()?.active_input.is_none());
    assert!(f.connection.diagnostics()?.failure.is_some());
    f.stop().await
}

#[tokio::test]
async fn partial_native_failure_preserves_original_input_and_never_reoffers_it() -> Check {
    let f = Fixture::ready(PermissionPolicy::Refuse).await?;
    f.io.plans
        .lock()
        .map_err(|_| "poisoned fixture")?
        .push_back(Plan::Partial);
    let failure = f
        .session
        .prompt_tracked("partial".into(), "work".into(), cx()?)
        .await
        .err()
        .ok_or("partial writer failure must refuse")?;
    assert_eq!(failure.completed_bytes, Some(1));
    assert_eq!(
        f.session.observe()?.active_input.as_deref(),
        Some("partial")
    );
    let before = f.writes()?.len();
    assert!(
        f.session
            .prompt_tracked("partial".into(), "work".into(), cx()?)
            .await
            .is_err()
    );
    assert_eq!(f.writes()?.len(), before);
    f.stop().await
}

#[tokio::test]
async fn missing_load_capability_names_the_real_new_conversation_option() -> Check {
    let mut f = Fixture::new(PermissionPolicy::Refuse).await?;
    f.initialize(json!({"mcpCapabilities":{"http":true}}))
        .await?;
    let before = f.writes()?.len();
    let failure = f
        .session
        .open(
            "/synthetic/workspace",
            vec![],
            Some(("conversation", vec![])),
            "",
            cx()?,
        )
        .await
        .err()
        .ok_or("load must refuse")?;
    let text = failure.to_string();
    assert!(text.contains("--new"));
    assert!(!text.contains("--fresh"));
    assert_eq!(f.writes()?.len(), before);
    f.stop().await
}

#[tokio::test]
async fn unsupported_http_mcp_names_configured_entrypoint_before_session_write() -> Check {
    let mut f = Fixture::new(PermissionPolicy::Refuse).await?;
    f.initialize(json!({})).await?;
    let before = f.writes()?.len();
    let failure = f
        .session
        .open(
            "/synthetic/workspace",
            vec![json!({"type":"http"})],
            None,
            "",
            cx()?,
        )
        .await
        .err()
        .ok_or("HTTP MCP must refuse")?;
    let text = failure.to_string();
    assert!(text.contains("providers.acp.command") && text.contains("acp.arguments"));
    assert_eq!(f.writes()?.len(), before);
    f.stop().await
}

#[tokio::test]
async fn configured_mode_refusal_names_the_expected_and_reported_modes() -> Check {
    let mut f = Fixture::new(PermissionPolicy::Refuse).await?;
    f.initialize(json!({})).await?;
    let failure = open_with_mode(&mut f, "required-mode", Some("reported-mode"))
        .await?
        .err()
        .ok_or("mode mismatch must refuse")?;
    let text = failure.to_string();
    assert!(
        text.contains("required-mode")
            && text.contains("reported-mode")
            && text.contains("acp.mode")
    );
    f.stop().await
}

#[tokio::test]
async fn protocol_refusal_reports_the_actual_offered_version() -> Check {
    let mut f = Fixture::new(PermissionPolicy::Refuse).await?;
    let session = f.session.clone();
    let context = cx()?;
    let task = tokio::spawn(async move { session.initialize(context).await });
    let request = f.write(0).await?;
    f.emit(json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":7,"agentCapabilities":{}}}))?;
    let failure = task.await?.err().ok_or("protocol mismatch must refuse")?;
    let text = failure.to_string();
    assert!(text.contains("7") && text.contains("version 1"));
    f.stop().await
}

#[tokio::test]
async fn settled_input_keys_remain_owned_with_an_honest_zero_byte_refusal() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
    let id = f.prompt("original-key").await?;
    f.complete(id, "end_turn").await?;
    f.session.acknowledge(id)?;
    let before = f.writes()?.len();
    let failure = f
        .session
        .prompt_tracked("original-key".into(), "repeat".into(), cx()?)
        .await
        .err()
        .ok_or("accepted key must not replay")?;
    assert_eq!(failure.completed_bytes, Some(0));
    assert_eq!(f.writes()?.len(), before);
    assert!(f.session.observe()?.active_input.is_none());
    f.stop().await
}
