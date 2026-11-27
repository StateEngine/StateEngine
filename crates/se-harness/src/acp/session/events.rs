//! Inbound protocol state transitions; no streamed prefix is a sealed turn.
use super::*;
impl Session {
    pub(super) async fn consume(self: Arc<Self>, mut receiver: mpsc::Receiver<Incoming>) {
        let mut changed = self.subscribe();
        let mut transport = self.connection.subscribe();
        loop {
            tokio::select! {
                value = receiver.recv() => {
                    let Some(value)=value else { break; };
                    let notify = !matches!(&value.message, Message::Update(_));
                    let handled = match value.message {
                        // A workspace file call never holds up this pump; it changes no conversation
                        // state, so it counts as processed once admitted. It is admitted here, in order, only for the
                        // established conversation; calls beyond the bound are refused.
                        Message::Request { id, method, params } if self.client.handles(&method) => {
                            match self.admit(&params) {
                                Ok(permit) => {
                                    tokio::spawn(self.clone().client_call(permit, method, id, params));
                                    Ok(())
                                }
                                Err(refusal) => self.connection.answer(id, Err((refusal.code, refusal.message)), CallContext::new(self.connection.generation(), std::time::Duration::from_secs(10))).await,
                            }
                        }
                        message => self.event(message).await,
                    };
                    if let Err(error) = handled { let _=self.fail(error.body); }
                    if let Ok(mut state)=self.lock() { state.processed=value.sequence; }
                    self.signal();
                    if notify { self.notify_owner(); }
                }
                _ = changed.changed() => { if self.closing.load(Ordering::Acquire) { break; } }
                _ = transport.changed() => {
                    self.signal();
                    if self.connection.diagnostics().is_ok_and(|v| v.failure.is_some() || v.stdout_terminal) { self.notify_owner(); }
                },
            }
        }
    }
    /// Admits a client call that names the established conversation exactly.
    fn admit(
        &self,
        params: &Value,
    ) -> std::result::Result<tokio::sync::OwnedSemaphorePermit, Refusal> {
        self.lock()
            .and_then(|state| {
                ready(&state)?;
                established(&state, params)
            })
            .map_err(|error| Refusal {
                code: -32602,
                message: error.body.message(),
            })?;
        self.client.admit()
    }
    /// Answers one admitted client call from the agent.
    async fn client_call(
        self: Arc<Self>,
        _permit: tokio::sync::OwnedSemaphorePermit,
        method: String,
        id: Value,
        params: Value,
    ) {
        let outcome = self
            .client
            .call(method, params)
            .await
            .map_err(|refusal| (refusal.code, refusal.message));
        let cx = CallContext::new(
            self.connection.generation(),
            std::time::Duration::from_secs(10),
        );
        let sent = self.connection.answer(id, outcome, cx).await;
        if let Err(error) = sent
            && !self.closing.load(Ordering::Acquire)
        {
            let _ = self.fail(error.body);
            self.signal();
        }
    }
    async fn event(&self, message: Message) -> Result<()> {
        match message {
            Message::Update(params) => self.update(params),
            Message::Response {
                id,
                method,
                outcome,
            } => self.response(id, method, outcome),
            Message::Request { id, method, params } => {
                if method != "session/request_permission" {
                    return self
                        .connection
                        .unsupported(
                            id,
                            CallContext::new(
                                self.connection.generation(),
                                std::time::Duration::from_secs(10),
                            ),
                        )
                        .await;
                }
                let (request, automatic) = {
                    let mut state = self.lock()?;
                    ready(&state)?;
                    session_matches(&state, &params)?;
                    if state.active.is_none()
                        || state.permissions.len() >= 32
                        || state.permissions.values().any(|v| v.id == id)
                    {
                        return Err(failure(
                            "ACP permission",
                            "no active prompt, duplicate request or permission bound exceeded",
                        ));
                    }
                    state.next_permission = state
                        .next_permission
                        .checked_add(1)
                        .ok_or_else(|| failure("ACP permission", "identity space exhausted"))?;
                    let request = state.next_permission;
                    let mut permission = Permission::parse(request, id, &params)?;
                    let tool = params
                        .pointer("/toolCall/toolCallId")
                        .and_then(Value::as_str)
                        .filter(|v| !v.is_empty() && v.len() <= 512);
                    if let (Some(tool), Some(active)) = (tool, state.active.as_mut()) {
                        active.permission_tool(tool)?;
                    }
                    let (response, reason) = if state.cancelling != Cancellation::None {
                        (
                            json!({"outcome":{"outcome":"cancelled"}}),
                            Some("Cancellation owns this prompt; this tool call was refused."),
                        )
                    } else {
                        permission.automatic(self.policy)
                    };
                    let option = response
                        .pointer("/outcome/optionId")
                        .and_then(Value::as_str);
                    let mut response = permission.select(option)?;
                    if let Some(reason) = reason {
                        state.permission_refusal = Some(PermissionRefusal { request, reason });
                        response["_meta"] = json!({"stateengine.dev/refusal_reason":reason});
                    }
                    let automatic = (permission.id.clone(), response);
                    state.permissions.insert(request, permission);
                    (request, automatic)
                };
                self.signal();
                let (id, response) = automatic;
                self.connection
                    .respond(
                        id,
                        response,
                        CallContext::new(
                            self.connection.generation(),
                            std::time::Duration::from_secs(10),
                        ),
                    )
                    .await?;
                self.lock()?.permissions.remove(&request);
                self.signal();
                Ok(())
            }
        }
    }
    fn update(&self, params: Value) -> Result<()> {
        let mut state = self.lock()?;
        ready(&state)?;
        let id = valid_id(
            params
                .get("sessionId")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )?;
        if state.opening && state.provisional_conversation.is_none() {
            state.provisional_conversation = Some(id.into());
        }
        session_matches(&state, &params)?;
        let update = params
            .get("update")
            .ok_or_else(|| failure("ACP update", "update absent"))?;
        match update.get("sessionUpdate").and_then(Value::as_str) {
            Some("current_mode_update") => update_mode(&mut state, update)?,
            Some("usage_update") => update_usage(&mut state, update),
            _ => {}
        }
        if state.loading.is_some() {
            update_history(&mut state, update)?;
        } else if let Some(active) = state.active.as_mut() {
            active.update(update)?;
        } else if update
            .get("sessionUpdate")
            .and_then(Value::as_str)
            .is_none_or(carries_content)
        {
            return Err(failure(
                "ACP updates",
                "conversation content outside an owned prompt or replay",
            ));
        }
        Ok(())
    }
    fn response(&self, id: u64, method: &str, outcome: Result<Value>) -> Result<()> {
        let result = outcome?;
        let mut state = self.lock()?;
        ready(&state)?;
        match method {
            "initialize" => response_initialize(&mut state, result)?,
            "session/new" | "session/load" => response_session(&mut state, method, result)?,
            "session/prompt" => response_prompt(&mut state, id, result)?,
            _ => {}
        }
        Ok(())
    }
}

fn update_mode(state: &mut State, update: &Value) -> Result<()> {
    let mode = update.get("currentModeId").and_then(Value::as_str);
    if let Some(mode) = mode {
        valid_id(mode)?;
    }
    if state
        .required_mode
        .as_deref()
        .is_some_and(|required| Some(required) != mode)
    {
        return Err(failure(
            "ACP policy",
            format!(
                "Configured native mode {:?}, but the agent changed to {:?}. The original input remains owned; inspect its captured outcome before stopping normally. Update or omit mode in [harnesses.NAME.permissions.PROFILE], or acp.mode for a legacy agent, for the next launch.",
                state.required_mode, mode
            ),
        ));
    }
    state.current_mode = mode.map(str::to_owned);
    Ok(())
}

/// `used` is what the session's context holds and `size` its whole window; both
/// are required, so an update missing either reports nothing.
fn update_usage(state: &mut State, update: &Value) {
    if let (Some(used), Some(size)) = (
        update.get("used").and_then(Value::as_u64),
        update.get("size").and_then(Value::as_u64),
    ) {
        state.context = Some(crate::harness::context_usage::ContextUsage::now(
            used,
            Some(size),
        ));
    }
}

fn update_history(state: &mut State, update: &Value) -> Result<()> {
    let kind = update
        .get("sessionUpdate")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if matches!(kind, "agent_message_chunk" | "user_message_chunk") {
        let role = if kind == "agent_message_chunk" {
            "assistant"
        } else {
            "user"
        };
        let text = text(update.get("content"))?;
        let overhead = if text.is_empty()
            || state
                .replay
                .last()
                .is_some_and(|message| message.role == role)
        {
            0
        } else {
            role.len() + std::mem::size_of::<CapturedMessage>()
        };
        state.replay_bytes = state
            .replay_bytes
            .checked_add(text.len())
            .and_then(|bytes| bytes.checked_add(overhead))
            .filter(|bytes| *bytes <= 8 * 1024 * 1024)
            .ok_or_else(|| {
                failure(
                    "ACP replay",
                    "eight-MiB history bound exceeded; no prefix accepted",
                )
            })?;
        append(&mut state.replay, role, text);
    } else if kind.is_empty() {
        return Err(failure("ACP replay", "update variant is absent"));
    }
    // Other content is not compared on resume; metadata and vendor
    // extensions carry no conversation text.
    Ok(())
}

/// Variants that carry conversation content, which only an owned prompt or
/// replay may produce. Metadata and vendor extensions are ignored.
fn carries_content(kind: &str) -> bool {
    matches!(
        kind,
        "agent_message_chunk"
            | "user_message_chunk"
            | "agent_thought_chunk"
            | "tool_call"
            | "tool_call_update"
            | "plan"
    )
}

fn response_initialize(state: &mut State, result: Value) -> Result<()> {
    if state.handshake != Handshake::Initializing {
        return Err(failure(
            "ACP initialization",
            "The original handshake is not active; stop this agent and retry launch with a fresh connection.",
        ));
    }
    let version = result.get("protocolVersion").and_then(Value::as_u64);
    if version != Some(1) {
        return Err(failure(
            "ACP initialization",
            format!(
                "The agent offered protocolVersion {version:?}; ACP version 1 is required. Configure command and arguments in the selected [harnesses.NAME] entry, or providers.acp.command and acp.arguments for a legacy agent, to an ACP v1 entrypoint, then retry launch."
            ),
        ));
    }
    state.capabilities = result
        .get("agentCapabilities")
        .cloned()
        .unwrap_or_else(|| json!({}));
    state.handshake = Handshake::Initialized;

    Ok(())
}

fn response_session(state: &mut State, method: &str, result: Value) -> Result<()> {
    if !state.opening {
        return Err(failure("ACP session", "unexpected session response"));
    }
    let conversation = if method == "session/new" {
        valid_id(
            result
                .get("sessionId")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )?
        .to_owned()
    } else {
        state
            .provisional_conversation
            .clone()
            .ok_or_else(|| failure("ACP resume", "original conversation absent"))?
    };
    if state
        .provisional_conversation
        .as_ref()
        .is_some_and(|v| v != &conversation)
    {
        return Err(failure(
            "ACP session",
            "response and update identities differ",
        ));
    }
    if let Some(expected) = state.loading.as_ref()
        && !same_history(expected, &state.replay)
    {
        return Err(failure(
            "ACP replay",
            "Loaded history differs from committed text; no input was offered. Restore the complete original capture or omit --resume to start a separate conversation.",
        ));
    }
    let mode = result
        .pointer("/modes/currentModeId")
        .and_then(Value::as_str);
    if let Some(mode) = mode {
        valid_id(mode)?;
    }
    if state
        .required_mode
        .as_deref()
        .is_some_and(|required| Some(required) != mode)
    {
        return Err(failure(
            "ACP policy",
            format!(
                "Configured native mode {:?}, but the agent reported {:?}. Select its reported mode or omit mode in [harnesses.NAME.permissions.PROFILE], or acp.mode for a legacy agent, to use its default, then retry launch. No input was offered.",
                state.required_mode, mode
            ),
        ));
    }
    state.current_mode = mode.map(str::to_owned);
    state.loading = None;
    state.replay.clear();
    state.replay_bytes = 0;
    state.opening = false;
    state.conversation = Some(conversation);

    Ok(())
}

fn response_prompt(state: &mut State, id: u64, result: Value) -> Result<()> {
    if state
        .permissions
        .values()
        .any(|p| !p.view.response_uncertain)
    {
        return Err(failure(
            "ACP completion",
            "permission responses remain unsettled",
        ));
    }
    let turn = state
        .active
        .as_ref()
        .ok_or_else(|| failure("ACP completion", "original offered input absent"))?;
    if turn.request.is_some_and(|request| request != id) {
        return Err(failure("ACP completion", "original request differs"));
    }
    // A validation failure must retain the original input as uncertain.
    let completed = turn.seal(id, &result)?;
    state.active = None;
    state.phase_started = Some(std::time::Instant::now());
    if state.cancelling == Cancellation::Written {
        state.cancelling = Cancellation::None;
    }
    // A terminal prompt does not prove our permission reply finished.
    // Keep uncertain responses until their owned writer confirms them;
    // they continue to block a new prompt or reuse of the same ID.
    state.completed.push(completed);

    Ok(())
}
