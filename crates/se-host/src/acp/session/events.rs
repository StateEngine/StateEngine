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
                    if let Err(error) = self.event(value.message).await { let _=self.fail(error.body); }
                    if let Ok(mut state)=self.lock() { state.processed=value.sequence; }
                    self.signal();
                }
                _ = changed.changed() => { if self.closing.load(Ordering::Acquire) { break; } }
                _ = transport.changed() => self.signal(),
            }
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
                    let automatic = if state.cancelling {
                        Some(json!({"outcome":{"outcome":"cancelled"}}))
                    } else {
                        permission.automatic(self.policy)
                    };
                    let automatic = automatic
                        .map(|response| {
                            let option = response
                                .pointer("/outcome/optionId")
                                .and_then(Value::as_str);
                            let response = permission.select(option)?;
                            Ok::<_, SeError>((permission.id.clone(), response))
                        })
                        .transpose()?;
                    state.permissions.insert(request, permission);
                    (request, automatic)
                };
                self.signal();
                if let Some((id, response)) = automatic {
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
                }
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
        if update.get("sessionUpdate").and_then(Value::as_str) == Some("current_mode_update") {
            let mode = update.get("currentModeId").and_then(Value::as_str);
            if mode != state.required_mode.as_deref() {
                return Err(failure(
                    "ACP policy",
                    "required mode changed; original input remains owned",
                ));
            }
            state.current_mode = mode.map(str::to_owned);
        }
        if state.loading.is_some() {
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
            } else if !matches!(
                kind,
                "tool_call"
                    | "tool_call_update"
                    | "agent_thought_chunk"
                    | "plan"
                    | "available_commands_update"
                    | "current_mode_update"
                    | "config_option_update"
                    | "session_info_update"
                    | "usage_update"
            ) {
                return Err(failure("ACP replay", "unsupported history content"));
            }
        } else if let Some(active) = state.active.as_mut() {
            active.update(update)?;
        } else if !matches!(
            update.get("sessionUpdate").and_then(Value::as_str),
            Some(
                "available_commands_update"
                    | "current_mode_update"
                    | "config_option_update"
                    | "session_info_update"
                    | "usage_update"
            )
        ) {
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
            "initialize" => {
                if !state.initializing
                    || result.get("protocolVersion").and_then(Value::as_u64) != Some(1)
                {
                    return Err(failure(
                        "ACP initialization",
                        "original protocol-version-1 handshake required",
                    ));
                }
                state.capabilities = result
                    .get("agentCapabilities")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                state.initialized = true;
                state.initializing = false;
            }
            "session/new" | "session/load" => {
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
                    && *expected != state.replay
                {
                    return Err(failure(
                        "ACP replay",
                        "loaded history differs from committed text; no input offered",
                    ));
                }
                let mode = result
                    .pointer("/modes/currentModeId")
                    .and_then(Value::as_str);
                if mode != state.required_mode.as_deref() {
                    return Err(failure(
                        "ACP policy",
                        "agent did not echo the required qualified mode; no input offered",
                    ));
                }
                state.current_mode = mode.map(str::to_owned);
                state.loading = None;
                state.replay.clear();
                state.replay_bytes = 0;
                state.opening = false;
                state.conversation = Some(conversation);
            }
            "session/prompt" => {
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
                if state.cancel_written {
                    state.cancelling = false;
                }
                state.permissions.clear();
                state.completed.push(completed);
            }
            _ => {}
        }
        Ok(())
    }
}
