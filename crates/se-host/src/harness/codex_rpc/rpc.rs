//! Correlated bidirectional RPC. Every request ID is fresh; a timed-out write
//! remains uncertain and never causes an automatic retry of user input.
use super::*;
use tokio::sync::oneshot;

impl Binding {
    pub(super) async fn request(
        &self,
        method: &str,
        params: Value,
        cx: &CallContext,
    ) -> Result<Value> {
        let until = tokio::time::Instant::now() + cx.timeout;
        let (id, frame, reply) = {
            let mut state = self.state.lock().map_err(|_| poisoned())?;
            if let Some(error) = &state.failure {
                return Err(error.clone().into());
            }
            if state.pending.len() >= 16 {
                return Err(SeError::invalid(
                    "Codex RPC capacity",
                    "resolve retained requests before another operation",
                ));
            }
            let (id, frame) = state.sequence.request(method, params)?;
            let wire::RequestId::Number(id) = id else {
                return Err(poisoned());
            };
            let (send, receive) = oneshot::channel();
            state.pending.insert(id, send);
            (id, frame, receive)
        };
        let written = async {
            let mut sender = self.sender.lock().await;
            sender
                .send(
                    frame,
                    context(
                        cx.generation,
                        until.saturating_duration_since(tokio::time::Instant::now()),
                    ),
                )
                .await
        };
        match tokio::time::timeout_at(until, written).await {
            Ok(Ok(())) => (),
            Ok(Err(error)) => {
                self.fail(error.body.clone().into());
                return Err(error);
            }
            Err(_) => {
                let error = incompatible(
                    "RPC write timed out; acceptance is unknown",
                    "Preserve the original input and native binding; do not resend blindly.",
                );
                self.fail(error.body.clone().into());
                return Err(error);
            }
        }
        match tokio::time::timeout_at(until, reply).await {
            Ok(Ok(result)) => result.map_err(SeError::from),
            Ok(Err(_)) => Err(se_core::scope::unreadable(
                "Codex RPC response",
                "the retained dispatcher closed before a correlated response",
            )),
            Err(_) => Err(se_core::scope::unreadable(
                "Codex RPC response",
                &format!(
                    "request {id} timed out; its original input remains uncertain and is not automatically retried"
                ),
            )),
        }
    }
    pub(super) async fn notify(&self, method: &str, params: Value, cx: &CallContext) -> Result<()> {
        let frame = wire::notification(method, params)?;
        tokio::time::timeout(cx.timeout, async {
            self.sender
                .lock()
                .await
                .send(frame, context(cx.generation, cx.timeout))
                .await
        })
        .await
        .map_err(|_| {
            incompatible(
                "RPC notification write timed out",
                "Inspect the original provider binding.",
            )
        })?
    }
}
pub(super) async fn read(
    weak: std::sync::Weak<Binding>,
    mut receiver: channel::Receiver,
    generation: se_types::Generation,
) {
    loop {
        let next = receiver
            .next(context(generation, Duration::from_secs(86400)))
            .await;
        let Some(binding) = weak.upgrade() else {
            return;
        };
        let result = match next {
            Ok(Some(wire::Message::Response {
                id: wire::RequestId::Number(id),
                result,
            })) => {
                let reply = binding
                    .state
                    .lock()
                    .map_err(|_| poisoned())
                    .map(|mut state| state.pending.remove(&id));
                match reply {
                    Ok(Some(reply)) => {
                        let _ = reply.send(result.map_err(|failure| {
                            let reason = if failure.message.len() <= 2048 {
                                format!("provider refused request ({}): {}", failure.code, failure.message)
                            } else {
                                format!("provider refused request ({}); its diagnostic exceeds 2048 bytes ({} bytes)", failure.code, failure.message.len())
                            };
                            incompatible(&reason, "Inspect the provider/profile and retry only after resolving the original input.").body
                        }));
                        Ok(())
                    }
                    Ok(None) => Err(SeError::invalid(
                        "Codex response",
                        "an outstanding exact request ID",
                    )),
                    Err(error) => Err(error),
                }
            }
            Ok(Some(wire::Message::Response { .. })) => Err(SeError::invalid(
                "Codex response",
                "the binding's numeric request ID",
            )),
            Ok(Some(wire::Message::Notification { method, params })) => {
                binding.observe(method, params)
            }
            Ok(Some(wire::Message::Request { id, .. })) => {
                let refused = wire::refusal(
                    &id,
                    "This headless connection cannot approve actions or answer interactive requests",
                );
                match refused {
                    Ok(frame) => {
                        binding
                            .sender
                            .lock()
                            .await
                            .send(frame, context(generation, Duration::from_secs(5)))
                            .await
                    }
                    Err(error) => Err(error),
                }
            }
            Ok(None) => Err(se_core::scope::unreadable(
                "Codex RPC",
                "provider connection closed",
            )),
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            binding.fail(error);
            return;
        }
    }
}
