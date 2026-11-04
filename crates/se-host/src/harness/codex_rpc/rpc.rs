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
                            let reason = diagnostic(failure.code, &failure.message, &binding.diagnostic_secrets);
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

fn diagnostic(code: i64, message: &str, secrets: &[se_types::Secret]) -> String {
    if message.len() > 2048 {
        return format!(
            "provider refused request ({code}); its diagnostic exceeds 2048 bytes ({} bytes)",
            message.len()
        );
    }
    let mut safe = message.to_owned();
    for secret in secrets {
        if let Ok(value) = std::str::from_utf8(secret.expose()) {
            safe = safe.replace(value, "[redacted]");
        }
    }
    format!("provider refused request ({code}): {safe}")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_errors_preserve_the_reason_without_reflecting_launch_capabilities() -> Result<()> {
        let secrets = [
            se_types::Secret::new(b"test-http-bearer".to_vec())?,
            se_types::Secret::new(b"test-session-pin".to_vec())?,
        ];
        let actual = diagnostic(
            -32602,
            "invalid headers: Bearer test-http-bearer and test-session-pin",
            &secrets,
        );
        assert!(actual.contains("invalid headers") && actual.contains("-32602"));
        assert!(!actual.contains("test-http-bearer") && !actual.contains("test-session-pin"));
        let oversized = diagnostic(-32000, &"x".repeat(2049), &secrets);
        assert!(oversized.contains("2049 bytes") && !oversized.contains(&"x".repeat(32)));
        Ok(())
    }
}
