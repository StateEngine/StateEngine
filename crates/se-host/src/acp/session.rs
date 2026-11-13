//! One retained ACP conversation with a serialized input boundary and an owned
//! update pump. Replayed history never enters the new-turn capture queue.
mod events;
use super::{
    Connection, Incoming, Message, OfferFailure, failure,
    permission::{Permission, PermissionPolicy, PermissionRefusal, PermissionView},
    turn::{CapturedMessage, CompletedTurn, Turn, text},
};
use crate::CallContext;
use se_types::{ErrorBody, Result, SeError};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{mpsc, watch};

/// Owns protocol state only. The coordinator still owns native containment,
/// the durable input journal and canonical capture/readback.
pub struct Session {
    connection: Arc<Connection>,
    state: Mutex<State>,
    input: tokio::sync::Mutex<()>,
    changed: watch::Sender<u64>,
    pump: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    closing: AtomicBool,
    policy: PermissionPolicy,
    owner_wake: OnceLock<Arc<tokio::sync::Notify>>,
}
#[derive(Clone)]
pub struct Observation {
    pub policy_notice: &'static str,
    pub permission_refusal: Option<PermissionRefusal>,
    pub conversation: Option<String>,
    pub active_input: Option<String>,
    pub cancelling: bool,
    pub current_mode: Option<String>,
    pub permissions: Vec<PermissionView>,
    pub completed: Vec<u64>,
    pub provisional_text: Option<super::turn::ProvisionalText>,
    pub failure: Option<ErrorBody>,
    pub processed: u64,
}
#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
struct State {
    permission_refusal: Option<PermissionRefusal>,
    initializing: bool,
    initialized: bool,
    required_mode: Option<String>,
    current_mode: Option<String>,
    capabilities: Value,
    conversation: Option<String>,
    opening: bool,
    loading: Option<Vec<CapturedMessage>>,
    replay: Vec<CapturedMessage>,
    replay_bytes: usize,
    provisional_conversation: Option<String>,
    active: Option<Turn>,
    completed: Vec<CompletedTurn>,
    used_keys: BTreeSet<String>,
    permissions: BTreeMap<u64, Permission>,
    next_permission: u64,
    cancelling: bool,
    cancel_written: bool,
    processed: u64,
    failure: Option<ErrorBody>,
}
impl Session {
    pub async fn retain(
        connection: Arc<Connection>,
        receiver: mpsc::Receiver<Incoming>,
        policy: PermissionPolicy,
    ) -> Arc<Self> {
        let session = Arc::new(Self {
            connection,
            state: Mutex::new(State::default()),
            input: tokio::sync::Mutex::new(()),
            changed: watch::channel(0).0,
            pump: tokio::sync::Mutex::new(None),
            closing: AtomicBool::new(false),
            policy,
            owner_wake: OnceLock::new(),
        });
        let owned = session.clone();
        *session.pump.lock().await = Some(tokio::spawn(async move {
            owned.consume(receiver).await;
        }));
        session
    }
    /// Coalesce terminal/permission/failure updates into the native owner's wake.
    pub fn arm(&self, wake: &Arc<tokio::sync::Notify>) -> Result<()> {
        if self.owner_wake.set(wake.clone()).is_err()
            && self
                .owner_wake
                .get()
                .is_none_or(|old| !Arc::ptr_eq(old, wake))
        {
            return Err(failure("ACP wake", "the original native owner differs"));
        }
        self.notify_owner();
        Ok(())
    }
    fn notify_owner(&self) {
        if let Some(wake) = self.owner_wake.get() {
            wake.notify_one();
        }
    }
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }
    pub fn observe(&self) -> Result<Observation> {
        let state = self
            .state
            .lock()
            .map_err(|_| failure("ACP session", "poisoned state"))?;
        let transport = self.connection.diagnostics()?;
        Ok(Observation {
            policy_notice: self.policy.notice(),
            permission_refusal: state.permission_refusal.clone(),
            conversation: state.conversation.clone(),
            active_input: state.active.as_ref().map(|v| v.input_key.clone()),
            cancelling: state.cancelling,
            current_mode: state.current_mode.clone(),
            permissions: state.permissions.values().map(|v| v.view.clone()).collect(),
            completed: state.completed.iter().map(|v| v.request).collect(),
            provisional_text: state.active.as_ref().map(Turn::preview),
            failure: state.failure.clone().or(transport.failure),
            processed: state.processed,
        })
    }
    pub async fn initialize(&self, cx: CallContext) -> Result<()> {
        let until = super::connection::until(&cx)?;
        let _input = tokio::time::timeout_at(until, self.input.lock())
            .await
            .map_err(|_| failure("ACP input queue", "original admission deadline expired"))?;
        {
            let mut state = self.lock()?;
            ready(&state)?;
            if state.initializing || state.initialized {
                return Err(failure(
                    "ACP initialization",
                    "original handshake already owned; do not replay",
                ));
            }
            state.initializing = true;
        }
        self.connection.request("initialize", json!({"protocolVersion":1,
            "clientInfo":{"name":"stateengine","version":env!("CARGO_PKG_VERSION")},
            "clientCapabilities":{"fs":{"readTextFile":false,"writeTextFile":false},"terminal":false}}),remaining(&cx,until)?).await?;
        self.synchronize(until).await?;
        ready(&*self.lock()?)?;
        Ok(())
    }
    /// The caller supplies native absolute cwd and its protected MCP descriptor.
    /// Loading requires the full previously committed text projection, not a new session fallback.
    pub async fn open(
        &self,
        cwd: &str,
        mcp_servers: Vec<Value>,
        previous: Option<(&str, Vec<CapturedMessage>)>,
        required_mode: &str,
        cx: CallContext,
    ) -> Result<String> {
        let until = super::connection::until(&cx)?;
        let _input = tokio::time::timeout_at(until, self.input.lock())
            .await
            .map_err(|_| failure("ACP input queue", "original admission deadline expired"))?;
        let (method, params) = {
            let mut state = self.lock()?;
            ready(&state)?;
            if !state.initialized || state.opening || state.conversation.is_some() {
                return Err(failure(
                    "ACP session",
                    "initialize one unused connection before opening",
                ));
            }
            if mcp_servers
                .iter()
                .any(|v| v.get("type").and_then(Value::as_str) == Some("http"))
                && state
                    .capabilities
                    .pointer("/mcpCapabilities/http")
                    .and_then(Value::as_bool)
                    != Some(true)
            {
                return Err(failure(
                    "ACP MCP",
                    "The agent did not advertise authenticated HTTP MCP support. Configure the selected harness command and arguments to an ACP v1 agent with HTTP MCP support, then retry launch.",
                ));
            }
            state.required_mode = if required_mode.is_empty() {
                None
            } else {
                Some(valid_id(required_mode)?.into())
            };
            state.opening = true;
            match previous {
                Some((id, expected)) => {
                    if state
                        .capabilities
                        .get("loadSession")
                        .and_then(Value::as_bool)
                        != Some(true)
                    {
                        state.opening = false;
                        return Err(failure(
                            "ACP resume",
                            "The agent does not advertise loadSession. Use --new to start a separate conversation, or configure an agent that can load the saved conversation. No new input was offered.",
                        ));
                    }
                    valid_id(id)?;
                    state.provisional_conversation = Some(id.into());
                    state.loading = Some(normalize(expected));
                    (
                        "session/load",
                        json!({"sessionId":id,"cwd":cwd,"mcpServers":mcp_servers}),
                    )
                }
                None => ("session/new", json!({"cwd":cwd,"mcpServers":mcp_servers})),
            }
        };
        self.connection
            .request(method, params, remaining(&cx, until)?)
            .await?;
        self.synchronize(until).await?;
        let state = self.lock()?;
        ready(&state)?;
        state.conversation.clone().ok_or_else(|| {
            failure(
                "ACP session",
                "session response did not establish its identity",
            )
        })
    }
    /// Offers one input once. The request ID proves neither durable provider
    /// acceptance nor canonical capture; keep its original key on uncertainty.
    pub async fn prompt(&self, key: String, text: String, cx: CallContext) -> Result<u64> {
        self.prompt_tracked(key, text, cx)
            .await
            .map_err(|e| e.error)
    }
    /// A definite zero-byte failure releases this key for the caller's retained
    /// mail offer. Partial or unobserved writes retain the original intent.
    pub async fn prompt_tracked(
        &self,
        key: String,
        text: String,
        cx: CallContext,
    ) -> std::result::Result<u64, OfferFailure> {
        let until = super::connection::until(&cx)?;
        let _input = tokio::time::timeout_at(until, self.input.lock())
            .await
            .map_err(|_| failure("ACP input queue", "The admission wait expired before writing. Inspect status, let the current input settle, then retry this retained offer."))?;
        let id = {
            let mut state = self.lock()?;
            ready(&state)?;
            if state.active.is_some()
                || state.cancelling
                || state.completed.len() >= 4
                || !state.permissions.is_empty()
            {
                return Err(failure(
                    "ACP input",
                    "Prior input, capture or permission remains unsettled. Inspect status and resolve any permission request; retry this retained offer after capture settles. No new bytes were written.",
                ).into());
            }
            if state.used_keys.contains(&key) {
                return Err(failure(
                    "ACP input",
                    "The original input key is already owned. Inspect status and captured history for its outcome; do not replay it. Offer a new task only after the original input settles.",
                ).into());
            }
            if state.used_keys.len() >= 4096 {
                return Err(failure("ACP input", "The connection's 4096-input budget is exhausted. Stop the agent normally, then launch it again to resume the saved conversation on a fresh connection.").into());
            }
            let id = state
                .conversation
                .clone()
                .ok_or_else(|| failure("ACP input", "No loaded conversation exists. Launch the agent and wait for readiness before offering this input."))?;
            let turn = Turn::new(key.clone(), text.clone())?;
            state.used_keys.insert(key.clone());
            state.active = Some(turn);
            state.permission_refusal = None;
            state.cancelling = false;
            state.cancel_written = false;
            id
        };
        self.signal();
        // Publish intent before stdio; only a witnessed zero-byte outcome can
        // release it. Dropped caller waits leave that intent intact.
        let offered = match remaining(&cx, until) {
            Ok(cx) => {
                self.connection
                    .offer_tracked(
                        "session/prompt",
                        json!({"sessionId":id,"prompt":[{"type":"text","text":text}]}),
                        cx,
                    )
                    .await
            }
            Err(error) => Err(error.into()),
        };
        match offered {
            Ok(id) => {
                let mut state = self.lock().map_err(OfferFailure::uncertain)?;
                if let Some(turn) = state.active.as_mut() {
                    turn.request = Some(id);
                }
                Ok(id)
            }
            Err(offer_error) => {
                let mut state = self.lock().map_err(OfferFailure::uncertain)?;
                if offer_error.completed_bytes == Some(0) {
                    if state
                        .active
                        .as_ref()
                        .is_some_and(|turn| turn.input_key == key)
                    {
                        state.active = None;
                        state.used_keys.remove(&key);
                    }
                } else {
                    state
                        .failure
                        .get_or_insert_with(|| offer_error.error.body.clone());
                }
                drop(state);
                self.signal();
                Err(offer_error)
            }
        }
    }
    pub async fn cancel(&self, cx: CallContext) -> Result<()> {
        let until = super::connection::until(&cx)?;
        let _input = tokio::time::timeout_at(until, self.input.lock())
            .await
            .map_err(|_| failure("ACP cancellation", "input queue remains owned"))?;
        let (conversation, requests) = {
            let mut state = self.lock()?;
            if state.active.is_none() {
                return Ok(());
            }
            if state.cancelling {
                return Err(failure(
                    "ACP cancellation",
                    "original cancellation remains owned; observe its outcome without replay",
                ));
            }
            state.cancelling = true;
            state.cancel_written = false;
            (
                state
                    .conversation
                    .clone()
                    .ok_or_else(|| failure("ACP cancellation", "conversation absent"))?,
                state
                    .permissions
                    .iter_mut()
                    .filter(|(_, permission)| !permission.view.response_uncertain)
                    .map(|(request, permission)| {
                        // Publish cancellation choices together before crossing stdio;
                        // a concurrent answer cannot approve after cancellation begins.
                        Ok((*request, permission.id.clone(), permission.select(None)?))
                    })
                    .collect::<Result<Vec<_>>>()?,
            )
        };
        self.signal();
        for (request, id, response) in requests {
            self.connection
                .respond(id, response, remaining(&cx, until)?)
                .await?;
            self.lock()?.permissions.remove(&request);
        }
        self.connection
            .notify(
                "session/cancel",
                json!({"sessionId":conversation}),
                remaining(&cx, until)?,
            )
            .await?;
        let mut state = self.lock()?;
        state.cancel_written = true;
        if state.active.is_none() {
            state.cancelling = false;
        }
        drop(state);
        self.signal();
        Ok(())
    }
    pub fn completed(&self, request: u64) -> Result<CompletedTurn> {
        self.lock()?
            .completed
            .iter()
            .find(|v| v.request == request)
            .cloned()
            .ok_or_else(|| failure("ACP capture", "original completed turn is absent"))
    }
    /// Called after outside canonical readback, never merely after a write.
    pub fn acknowledge(&self, request: u64) -> Result<()> {
        self.remove_completed(request)
    }
    /// The caller has the owner’s explicit capture opt-out. No persisted reply
    /// or delivery witness is claimed when releasing this in-memory payload.
    pub fn discard_after_capture_opt_out(&self, request: u64) -> Result<()> {
        self.remove_completed(request)
    }
    fn remove_completed(&self, request: u64) -> Result<()> {
        let mut state = self.lock()?;
        if state.completed.first().is_none_or(|v| v.request != request) {
            return Err(failure(
                "ACP capture",
                "acknowledge only the original first completed turn",
            ));
        }
        state.completed.remove(0);
        Ok(())
    }
    /// Native scope exit must already be witnessed by the caller. Draining
    /// stdout and processing all queued updates precedes final capture/close.
    pub async fn drain(&self, cx: &CallContext) -> Result<()> {
        let until = super::connection::until(cx)?;
        let mut changed = self.connection.subscribe();
        loop {
            let observation = self.connection.diagnostics()?;
            if observation.stdout_terminal {
                self.synchronize(until).await?;
                if !observation.stdout_complete {
                    return Err(failure(
                        "ACP capture",
                        "stdout did not reach a complete protocol EOF",
                    ));
                }
                ready(&*self.lock()?)?;
                if self.lock()?.active.is_some() {
                    return Err(failure(
                        "ACP capture",
                        "original prompt never reached a terminal reply",
                    ));
                }
                return Ok(());
            }
            tokio::time::timeout_at(until, changed.changed())
                .await
                .map_err(|_| failure("ACP drain", "stdout still owned after wait bound"))?
                .map_err(|_| failure("ACP drain", "stream observation closed"))?;
        }
    }
    pub async fn finish_input(&self, cx: CallContext) -> Result<()> {
        self.connection.finish_input(cx).await
    }
    pub async fn close(&self, cx: CallContext) -> Result<()> {
        let until = super::connection::until(&cx)?;
        self.connection.close(remaining(&cx, until)?).await?;
        self.synchronize(until).await?;
        self.closing.store(true, Ordering::Release);
        self.signal();
        let mut pump = tokio::time::timeout_at(until, self.pump.lock())
            .await
            .map_err(|_| failure("ACP close", "original update-task join remains busy"))?;
        if let Some(task) = pump.as_mut() {
            tokio::time::timeout_at(until, task)
                .await
                .map_err(|_| failure("ACP close", "update task remains retained"))?
                .map_err(|_| failure("ACP close", "update task panicked"))?;
        }
        *pump = None;
        Ok(())
    }
    async fn synchronize(&self, until: tokio::time::Instant) -> Result<()> {
        let target = self.connection.diagnostics()?.events_queued;
        let mut changed = self.subscribe();
        loop {
            if self.lock()?.processed >= target {
                return Ok(());
            }
            tokio::time::timeout_at(until, changed.changed())
                .await
                .map_err(|_| failure("ACP updates", "queued updates remain unprocessed"))?
                .map_err(|_| failure("ACP updates", "observer closed"))?;
        }
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| failure("ACP session", "poisoned state"))
    }
    fn fail(&self, body: ErrorBody) -> Result<()> {
        self.lock()?.failure.get_or_insert(body);
        self.notify_owner();
        self.signal();
        Ok(())
    }
    fn signal(&self) {
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }
}

fn ready(state: &State) -> Result<()> {
    state
        .failure
        .clone()
        .map_or(Ok(()), |error| Err(SeError::from(error)))
}
fn valid_id(id: &str) -> Result<&str> {
    if id.is_empty() || id.len() > 512 {
        Err(failure(
            "ACP session",
            "bounded conversation identity required",
        ))
    } else {
        Ok(id)
    }
}
fn session_matches(state: &State, params: &Value) -> Result<()> {
    let expected = state
        .conversation
        .as_ref()
        .or(state.provisional_conversation.as_ref());
    if expected.map(String::as_str) != params.get("sessionId").and_then(Value::as_str) {
        return Err(failure(
            "ACP session",
            "update or request belongs to another conversation",
        ));
    }
    Ok(())
}
fn append(messages: &mut Vec<CapturedMessage>, role: &str, text: &str) {
    if text.is_empty() {
        return;
    }
    if let Some(last) = messages.last_mut()
        && last.role == role
    {
        last.text.push_str(text);
    } else {
        messages.push(CapturedMessage {
            role: role.into(),
            text: text.into(),
        });
    }
}
fn normalize(messages: Vec<CapturedMessage>) -> Vec<CapturedMessage> {
    let mut result = Vec::new();
    for message in messages {
        append(&mut result, &message.role, &message.text);
    }
    result
}

fn remaining(cx: &CallContext, until: tokio::time::Instant) -> Result<CallContext> {
    Ok(CallContext {
        generation: cx.generation,
        timeout: until
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or_else(|| failure("ACP deadline", "original call deadline expired"))?,
        cancellation: cx.cancellation.clone(),
    })
}
