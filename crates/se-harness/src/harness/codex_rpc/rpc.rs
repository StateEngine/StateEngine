//! Correlated bidirectional RPC. Every request ID is fresh; a timed-out write
//! remains uncertain and never causes an automatic retry of user input.
use super::*;
use tokio::sync::oneshot;

/// The numeric code is provider classification; the diagnostic is presentation.
#[derive(Debug)]
pub struct RequestFailure {
    pub code: Option<i64>,
    pub error: SeError,
}
impl From<SeError> for RequestFailure {
    fn from(error: SeError) -> Self {
        Self { code: None, error }
    }
}
struct Pending<'a> {
    state: &'a Mutex<state::State>,
    id: i64,
}
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.pending.remove(&self.id);
        }
    }
}

impl Binding {
    pub(super) async fn request(
        &self,
        method: &str,
        params: Value,
        cx: &CallContext,
    ) -> Result<Value> {
        self.request_classified(method, params, cx)
            .await
            .map_err(|failure| failure.error)
    }
    pub(super) async fn request_classified(
        &self,
        method: &str,
        params: Value,
        cx: &CallContext,
    ) -> std::result::Result<Value, RequestFailure> {
        let until = tokio::time::Instant::now() + cx.timeout;
        let (id, frame, reply) = {
            let mut state = self.state.lock().map_err(|_| poisoned())?;
            if let Some(error) = &state.failure {
                return Err(SeError::from(error.clone()).into());
            }
            if state.pending.len() >= 16 {
                return Err(SeError::invalid(
                    "Codex RPC capacity",
                    "resolve retained requests before another operation",
                )
                .into());
            }
            let (id, frame) = state.sequence.request(method, params)?;
            let wire::RequestId::Number(id) = id else {
                return Err(poisoned().into());
            };
            let (send, receive) = oneshot::channel();
            state.pending.insert(id, send);
            (id, frame, receive)
        };
        let _pending = Pending {
            state: &self.state,
            id,
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
                return Err(error.into());
            }
            Err(_) => {
                let error = incompatible(
                    "RPC write timed out; acceptance is unknown",
                    "Preserve the original input and native binding; do not resend blindly.",
                );
                self.fail(error.body.clone().into());
                return Err(error.into());
            }
        }
        match tokio::time::timeout_at(until, reply).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(se_core::scope::unreadable(
                "Codex RPC response",
                "the retained dispatcher closed before a correlated response",
            ).into()),
            Err(_) => Err(se_core::scope::unreadable(
                "Codex RPC response",
                &format!(
                    "request {id} timed out; its original input remains uncertain and is not automatically retried"
                ),
            ).into()),
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
            Ok(Some((
                wire::Message::Response {
                    id: wire::RequestId::Number(id),
                    result,
                },
                _,
            ))) => {
                let reply = binding
                    .state
                    .lock()
                    .map_err(|_| poisoned())
                    .map(|mut state| (state.pending.remove(&id), state.sequence.issued(id)));
                match reply {
                    Ok((Some(reply), _)) => {
                        let _ = reply.send(result.map_err(|failure| {
                            let reason = diagnostic(failure.code, &failure.message);
                            RequestFailure { code: Some(failure.code), error: incompatible(&reason, "Inspect the provider/profile and retry only after resolving the original input.") }
                        }));
                        Ok(())
                    }
                    Ok((None, true)) => Ok(()),
                    Ok((None, false)) => Err(SeError::invalid(
                        "Codex response",
                        "an outstanding exact request ID",
                    )),
                    Err(error) => Err(error),
                }
            }
            Ok(Some((wire::Message::Response { .. }, _))) => Err(SeError::invalid(
                "Codex response",
                "the binding's numeric request ID",
            )),
            Ok(Some((wire::Message::Notification { method, params }, observed_at))) => {
                binding.observe_at(method, params, observed_at)
            }
            // The remote TUI is subscribed to the same thread and answers its
            // interactive requests. This observer must not race it with a refusal.
            Ok(Some((wire::Message::Request { .. }, _))) if binding.attended => Ok(()),
            Ok(Some((wire::Message::Request { id, .. }, _))) => {
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

// Provider text can contain encoded, escaped or partial credentials, so exact
// substring replacement cannot make it safe. Retain classification, never the
// untrusted text or data, in durable/public diagnostics.
fn diagnostic(code: i64, message: &str) -> String {
    format!(
        "provider refused request ({code}); untrusted diagnostic withheld ({} bytes)",
        message.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dropping_request_waiters_releases_capacity_without_reusing_ids() -> Result<()> {
        let state = Mutex::new(state::State::default());
        for _ in 0..40 {
            let (id, _) = state
                .lock()
                .map_err(|_| poisoned())?
                .sequence
                .request("thread/read", json!({}))?;
            let wire::RequestId::Number(id) = id else {
                panic!("numeric id required")
            };
            let (send, _receive) = oneshot::channel();
            state
                .lock()
                .map_err(|_| poisoned())?
                .pending
                .insert(id, send);
            let pending = Pending { state: &state, id };
            assert_eq!(state.lock().map_err(|_| poisoned())?.pending.len(), 1);
            drop(pending);
            assert!(state.lock().map_err(|_| poisoned())?.pending.is_empty());
            assert!(state.lock().map_err(|_| poisoned())?.sequence.issued(id));
            assert!(
                !state
                    .lock()
                    .map_err(|_| poisoned())?
                    .sequence
                    .issued(id + 1)
            );
        }
        Ok(())
    }
    #[test]
    fn provider_diagnostics_never_reflect_credentials_or_their_encodings() {
        for message in [
            "Bearer test-http-bearer",
            "test%2Dhttp%2Dbearer",
            "dGVzdC1odHRwLWJlYXJlcg==",
            "test-http",
        ] {
            let actual = diagnostic(-32602, message);
            assert!(actual.contains("-32602") && actual.contains("withheld"));
            assert!(!actual.contains(message));
        }
    }
}
