//! Independent session controls drive the production connection's wire reader.
//! Synthetic native I/O does not qualify a provider, process scope or sandbox.
use crate::{
    CallContext, HostFuture, ProviderIo, ProviderIoPlatform, ProviderStream, ProviderTransport,
    SessionIdentity, StreamRead, StreamWrite,
    acp::{CapturedMessage, Connection, PermissionPolicy, Session, TurnItem},
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
    fn permission(&mut self, id: Value, options: Value, conversation: &str) -> Check {
        self.emit(json!({"jsonrpc":"2.0","id":id,"method":"session/request_permission","params":{"sessionId":conversation,"toolCall":{"toolCallId":"tool","title":"Synthetic action"},"options":options}}))
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
fn options() -> Value {
    json!([
        {"optionId":"allow-long","name":"Always","kind":"allow_always"},
        {"optionId":"allow-short","name":"Once","kind":"allow_once"},
        {"optionId":"deny-long","name":"Never","kind":"reject_always"},
        {"optionId":"deny-short","name":"Reject","kind":"reject_once"}
    ])
}

#[tokio::test]
async fn session_seals_chronology_and_preserves_original_input_until_terminal() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
    let id = f.prompt("input-one").await?;
    f.update(chunk("user_message_chunk", "original input"))?;
    f.update(chunk("agent_message_chunk", "before λ"))?;
    f.update(json!({"sessionUpdate":"tool_call","toolCallId":"tool","status":"in_progress"}))?;
    f.update(json!({"sessionUpdate":"tool_call_update","toolCallId":"tool","status":"completed"}))?;
    f.update(chunk("agent_message_chunk", "after"))?;
    f.settle().await?;
    assert!(f.session.completed(id).is_err());
    assert_eq!(
        f.session.observe()?.active_input.as_deref(),
        Some("input-one")
    );
    assert!(
        f.session
            .prompt("next".into(), "another".into(), cx()?)
            .await
            .is_err()
    );
    f.complete(id, "end_turn").await?;
    let turn = f.session.completed(id)?;
    assert_eq!(
        (turn.input_key.as_str(), turn.input.as_str()),
        ("input-one", "original input")
    );
    assert_eq!(
        turn.messages
            .iter()
            .map(|m| m.text.as_str())
            .collect::<Vec<_>>(),
        vec!["before λ", "after"]
    );
    assert!(matches!(
        turn.order.as_slice(),
        [
            TurnItem::Message { index: 0 },
            TurnItem::Tool { index: 0 },
            TurnItem::Tool { index: 1 },
            TurnItem::Message { index: 1 }
        ]
    ));
    assert!(f.session.acknowledge(id + 1).is_err());
    f.session.acknowledge(id)?;
    assert!(
        f.prompt("input-one").await.is_err(),
        "acknowledgement cannot replay the old input key"
    );
    f.stop().await
}

#[tokio::test]
async fn session_load_requires_exact_history_and_excludes_it_from_new_capture() -> Check {
    for mismatch in [false, true] {
        let mut f = Fixture::new(PermissionPolicy::Refuse).await?;
        f.initialize(json!({"loadSession":true})).await?;
        let history = vec![
            CapturedMessage {
                role: "user".into(),
                text: "old question".into(),
            },
            CapturedMessage {
                role: "assistant".into(),
                text: "old answer".into(),
            },
        ];
        let replay = vec![
            chunk("user_message_chunk", "old question"),
            chunk(
                "agent_message_chunk",
                if mismatch { "different" } else { "old answer" },
            ),
        ];
        assert_eq!(f.open(Some(history), replay, "safe").await?, !mismatch);
        if mismatch {
            assert!(f.prompt("fresh").await.is_err());
            assert_eq!(
                f.writes()?.len(),
                2,
                "failed load must not fall back to a new session"
            );
        } else {
            assert!(f.session.observe()?.provisional_text.is_none());
            let id = f.prompt("fresh").await?;
            f.update(chunk("agent_message_chunk", "fresh answer"))?;
            f.complete(id, "end_turn").await?;
            assert_eq!(
                f.session.completed(id)?.messages,
                vec![CapturedMessage {
                    role: "assistant".into(),
                    text: "fresh answer".into()
                }]
            );
        }
        f.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn session_mode_and_capability_refusals_never_offer_a_prompt() -> Check {
    let mut f = Fixture::new(PermissionPolicy::Refuse).await?;
    f.initialize(json!({})).await?;
    assert!(
        f.session
            .open(
                "/synthetic",
                vec![json!({"type":"http","url":"http://127.0.0.1:1/mcp"})],
                None,
                "safe",
                cx()?
            )
            .await
            .is_err()
    );
    assert_eq!(f.writes()?.len(), 1);
    assert!(
        f.session
            .open(
                "/synthetic",
                vec![],
                Some(("conversation", vec![])),
                "safe",
                cx()?
            )
            .await
            .is_err()
    );
    assert_eq!(f.writes()?.len(), 1);
    assert!(!f.open(None, vec![], "unexpected").await?);
    assert!(f.prompt("fresh").await.is_err());
    f.stop().await
}

#[tokio::test]
async fn session_saved_approval_controls_original_permission_choices() -> Check {
    use se_core::config_policy::Approval;
    for (approval, expected) in [
        (Approval::Never, "allow-short"),
        (Approval::OnRequest, "deny-short"),
    ] {
        let mut f = Fixture::ready(PermissionPolicy::from_saved_approval(approval)).await?;
        let id = f.prompt("permission-turn").await?;
        let index = f.writes()?.len();
        f.permission(json!("peer-permission"), options(), "conversation")?;
        let response = f.write(index).await?;
        f.settle().await?;
        assert_eq!(response["id"], "peer-permission");
        assert_eq!(response["result"]["outcome"]["optionId"], expected);
        assert_eq!(
            f.session.observe()?.permission_refusal.is_some(),
            expected == "deny-short"
        );
        assert!(
            f.session
                .observe()?
                .policy_notice
                .contains("no execution sandbox")
        );
        f.complete(id, "end_turn").await?;
        f.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn session_cancellation_refuses_late_permissions_and_resets_for_next_turn() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::NeverAsk).await?;
    let id = f.prompt("cancel-first").await?;
    f.session.cancel(cx()?).await?;
    assert!(f.session.cancel(cx()?).await.is_err());
    let index = f.writes()?.len();
    f.permission(json!(1), options(), "conversation")?;
    assert_eq!(
        f.write(index).await?["result"]["outcome"]["outcome"],
        "cancelled"
    );
    f.settle().await?;
    f.complete(id, "cancelled").await?;
    f.session.acknowledge(id)?;
    let second = f.prompt("cancel-second").await?;
    let index = f.writes()?.len();
    f.permission(json!(2), options(), "conversation")?;
    assert_eq!(
        f.write(index).await?["result"]["outcome"]["optionId"],
        "allow-short"
    );
    f.settle().await?;
    f.complete(second, "end_turn").await?;
    assert!(!f.session.observe()?.cancelling);
    f.stop().await
}

#[tokio::test]
async fn session_foreign_or_invalid_updates_keep_the_original_input_uncertain() -> Check {
    for variant in [
        "foreign",
        "partial-echo",
        "unfinished-tool",
        "unsupported",
        "mode-change",
    ] {
        let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
        let id = f.prompt("original").await?;
        match variant {
            "foreign" => f.emit(json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"other","update":chunk("agent_message_chunk", "foreign")}}))?,
            "partial-echo" => f.update(chunk("user_message_chunk", "original"))?,
            "unfinished-tool" => f.update(json!({"sessionUpdate":"tool_call","toolCallId":"tool","status":"in_progress"}))?,
            "mode-change" => f.update(json!({"sessionUpdate":"current_mode_update","currentModeId":"unsafe"}))?,
            _ => f.update(json!({"sessionUpdate":"agent_message_chunk","content":{"type":"image","data":"synthetic"}}))?,
        }
        f.complete(id, "end_turn").await?;
        assert!(f.session.observe()?.failure.is_some(), "{variant}");
        assert_eq!(
            f.session.observe()?.active_input.as_deref(),
            Some("original")
        );
        assert!(f.session.completed(id).is_err());
        assert!(f.prompt("replacement").await.is_err());
        f.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn session_partial_prompt_write_is_retained_and_never_reoffered() -> Check {
    let f = Fixture::ready(PermissionPolicy::Refuse).await?;
    f.io.plans
        .lock()
        .map_err(|_| "fixture poisoned")?
        .push_back(Plan::Partial);
    assert!(f.prompt("uncertain").await.is_err());
    assert_eq!(
        f.session.observe()?.active_input.as_deref(),
        Some("uncertain")
    );
    assert!(f.prompt("uncertain").await.is_err());
    assert!(f.prompt("new-key").await.is_err());
    assert_eq!(
        f.writes()?
            .iter()
            .filter(|v| v["method"] == "session/prompt")
            .count(),
        1
    );
    f.stop().await
}

#[tokio::test]
async fn session_complete_turn_survives_protocol_eof_and_drains_before_close() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
    let id = f.prompt("terminal").await?;
    f.update(chunk("agent_message_chunk", "final answer"))?;
    f.complete(id, "end_turn").await?;
    f.io.output
        .send(StreamRead::Eof)
        .map_err(|_| "stdout closed")?;
    eventually(|| f.connection.diagnostics().is_ok_and(|v| v.stdout_terminal)).await?;
    f.session.drain(&cx()?).await?;
    assert_eq!(f.session.completed(id)?.messages[0].text, "final answer");
    let terminal = f.connection.diagnostics()?;
    assert!(terminal.stdout_terminal && terminal.stdout_complete);
    assert!(
        f.session.observe()?.failure.is_none(),
        "clean complete EOF after a finished turn is a normal end"
    );
    f.stop().await
}

#[tokio::test]
async fn session_eof_with_input_in_flight_keeps_the_original_input_failed() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
    let id = f.prompt("unfinished-eof").await?;
    f.update(chunk("agent_message_chunk", "incomplete prefix"))?;
    f.settle().await?;
    f.io.output
        .send(StreamRead::Eof)
        .map_err(|_| "stdout closed")?;
    eventually(|| f.connection.diagnostics().is_ok_and(|v| v.stdout_terminal)).await?;
    let terminal = f.connection.diagnostics()?;
    assert!(
        terminal.stdout_complete,
        "framing completed even though the turn did not"
    );
    assert!(f.session.observe()?.failure.is_some());
    assert_eq!(
        f.session.observe()?.active_input.as_deref(),
        Some("unfinished-eof")
    );
    assert!(
        f.session.completed(id).is_err(),
        "a prefix cannot become a completed turn"
    );
    assert!(f.session.drain(&cx()?).await.is_err());
    let writes = f.writes()?.len();
    assert!(f.prompt("replacement-after-eof").await.is_err());
    assert_eq!(f.writes()?.len(), writes);
    f.stop().await
}

#[tokio::test]
async fn session_permission_write_stays_owned_until_its_native_write_finishes() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::NeverAsk).await?;
    let id = f.prompt("held-permission").await?;
    let gate = Arc::new(Semaphore::new(0));
    f.io.plans
        .lock()
        .map_err(|_| "fixture poisoned")?
        .push_back(Plan::Held(gate.clone()));
    let index = f.writes()?.len();
    f.permission(json!("held"), options(), "conversation")?;
    f.write(index).await?;
    f.emit(json!({"jsonrpc":"2.0","id":id,"result":{"stopReason":"end_turn"}}))?;
    assert!(f.prompt("replacement").await.is_err());
    assert!(f.session.observe()?.permissions[0].response_uncertain);
    gate.add_permits(1);
    f.settle().await?;
    assert_eq!(f.session.completed(id)?.input_key, "held-permission");
    assert!(f.session.observe()?.permissions.is_empty());
    assert_eq!(f.writes()?.iter().filter(|v| v["id"] == "held").count(), 1);
    f.stop().await
}

#[tokio::test]
async fn session_preview_reports_unicode_omission_without_truncating_completed_text() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
    let id = f.prompt("long-answer").await?;
    let text = "λ".repeat(5000);
    f.update(chunk("agent_message_chunk", &text))?;
    f.settle().await?;
    let preview = f
        .session
        .observe()?
        .provisional_text
        .ok_or("preview absent")?;
    assert_eq!(preview.total_bytes, 10000);
    assert_eq!(preview.omitted_bytes + preview.text.len() as u64, 10000);
    assert!(preview.text.len() <= 8192);
    assert!(text.ends_with(&preview.text));
    f.complete(id, "end_turn").await?;
    assert_eq!(f.session.completed(id)?.messages[0].text, text);
    f.stop().await
}

#[tokio::test]
async fn session_permission_without_eligible_choice_is_cancelled_and_disclosed() -> Check {
    for policy in [PermissionPolicy::NeverAsk, PermissionPolicy::Refuse] {
        let mut f = Fixture::ready(policy).await?;
        let id = f.prompt("permission").await?;
        let index = f.writes()?.len();
        let kind = if matches!(policy, PermissionPolicy::NeverAsk) {
            "reject_once"
        } else {
            "allow_once"
        };
        f.permission(
            json!(7),
            json!([{"optionId":"only","name":"Only offered option","kind":kind}]),
            "conversation",
        )?;
        let response = f.write(index).await?;
        f.settle().await?;
        assert_eq!(response["result"]["outcome"]["outcome"], "cancelled");
        assert!(response["result"]["_meta"]["stateengine.dev/refusal_reason"].is_string());
        assert!(f.session.observe()?.permission_refusal.is_some());
        f.complete(id, "end_turn").await?;
        f.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn session_malformed_or_foreign_permission_is_never_approved() -> Check {
    for variant in ["foreign", "duplicate-option", "unknown-kind", "oversized"] {
        let mut f = Fixture::ready(PermissionPolicy::NeverAsk).await?;
        f.prompt("permission").await?;
        let index = f.writes()?.len();
        let offered = match variant {
            "duplicate-option" => json!([
                {"optionId":"same","name":"Once","kind":"allow_once"},
                {"optionId":"same","name":"Always","kind":"allow_always"}
            ]),
            "unknown-kind" => {
                json!([{"optionId":"unknown","name":"Unknown","kind":"future-allow"}])
            }
            "oversized" => {
                json!([{"optionId":"large","name":"x".repeat(70000),"kind":"allow_once"}])
            }
            _ => options(),
        };
        f.permission(
            json!(1),
            offered,
            if variant == "foreign" {
                "other"
            } else {
                "conversation"
            },
        )?;
        f.settle().await?;
        assert!(f.session.observe()?.failure.is_some(), "{variant}");
        assert_eq!(
            f.writes()?.len(),
            index,
            "{variant} must not produce an approval"
        );
        assert_eq!(
            f.session.observe()?.active_input.as_deref(),
            Some("permission")
        );
        f.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn session_completed_queue_is_bounded_and_acknowledged_in_original_order() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
    let mut ids = Vec::new();
    for i in 0..4 {
        let id = f.prompt(&format!("key-{i}")).await?;
        f.complete(id, "end_turn").await?;
        ids.push(id);
    }
    let index = f.writes()?.len();
    assert!(f.prompt("fifth").await.is_err());
    assert_eq!(f.writes()?.len(), index);
    assert!(f.session.acknowledge(ids[1]).is_err());
    f.session.acknowledge(ids[0])?;
    let id = f.prompt("fifth").await?;
    f.complete(id, "end_turn").await?;
    assert_eq!(
        f.session.observe()?.completed,
        vec![ids[1], ids[2], ids[3], id]
    );
    f.stop().await
}

#[tokio::test]
async fn session_abandoned_prompt_wait_does_not_reoffer_or_discard_its_late_reply() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
    let gate = Arc::new(Semaphore::new(0));
    f.io.plans
        .lock()
        .map_err(|_| "fixture poisoned")?
        .push_back(Plan::Held(gate.clone()));
    let session = f.session.clone();
    let context = cx()?;
    let index = f.writes()?.len();
    let operation = tokio::spawn(async move {
        session
            .prompt("original".into(), "original input".into(), context)
            .await
    });
    let request = f.write(index).await?;
    operation.abort();
    assert!(operation.await.is_err());
    assert!(f.prompt("replacement").await.is_err());
    gate.add_permits(1);
    let id = request["id"].as_u64().ok_or("numeric request absent")?;
    f.update(chunk("agent_message_chunk", "late answer"))?;
    f.complete(id, "end_turn").await?;
    assert_eq!(f.session.completed(id)?.input_key, "original");
    assert_eq!(
        f.writes()?
            .iter()
            .filter(|v| v["method"] == "session/prompt")
            .count(),
        1
    );
    f.stop().await
}

#[tokio::test]
async fn session_concurrent_prompt_wait_keeps_its_original_admission_deadline() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
    let gate = Arc::new(Semaphore::new(0));
    f.io.plans
        .lock()
        .map_err(|_| "fixture poisoned")?
        .push_back(Plan::Held(gate.clone()));
    let session = f.session.clone();
    let context = cx()?;
    let index = f.writes()?.len();
    let first = tokio::spawn(async move {
        session
            .prompt("first".into(), "original input".into(), context)
            .await
    });
    let request = f.write(index).await?;
    let context = CallContext::new(Generation::new(1)?, Duration::from_millis(25));
    assert!(
        f.session
            .prompt("second".into(), "other input".into(), context)
            .await
            .is_err()
    );
    assert_eq!(f.writes()?.len(), index + 1);
    assert_eq!(f.session.observe()?.active_input.as_deref(), Some("first"));
    gate.add_permits(1);
    let id = first.await??;
    assert_eq!(request["id"], id);
    f.complete(id, "end_turn").await?;
    f.stop().await
}

#[tokio::test]
async fn session_aggregate_turn_overflow_never_seals_a_complete_prefix() -> Check {
    let mut f = Fixture::ready(PermissionPolicy::Refuse).await?;
    let id = f.prompt("bounded-turn").await?;
    let text = "x".repeat(300000);
    for _ in 0..29 {
        f.update(chunk("agent_message_chunk", &text))?;
        f.settle().await?;
    }
    f.complete(id, "end_turn").await?;
    assert!(f.session.observe()?.failure.is_some());
    assert!(f.session.completed(id).is_err());
    assert_eq!(
        f.session.observe()?.active_input.as_deref(),
        Some("bounded-turn")
    );
    f.stop().await
}
