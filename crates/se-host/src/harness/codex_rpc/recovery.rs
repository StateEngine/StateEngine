//! Reconnect only a natively adopted lifecycle's original private endpoint.
//! Resume subscribes to the existing thread; no turn/start or launch is replayed.
use super::*;
impl CodexHarness {
    pub(crate) async fn recover(
        &self,
        identity: &crate::SessionIdentity,
        conversation: &ProviderSessionId,
        transcript: Option<&crate::TranscriptPin>,
        attended: bool,
        cx: CallContext,
    ) -> Result<HarnessBinding> {
        #[cfg(not(unix))]
        {
            let _ = (identity, conversation, transcript, attended, cx);
            Err(se_core::scope::unreadable(
                "Codex restart control",
                "the original stdio connection cannot be reopened on this platform; preserve the session and use its exact public stop/resume command",
            ))
        }
        #[cfg(unix)]
        {
            let deadline = crate::client::lease::Deadline::idle()?.stage(cx.timeout)?;
            let session = identity.session.clone();
            let record = self.directory(&session)?.join("codex-runtime.json");
            let socket = self
                .pool
                .run_owned(&deadline, move || Self::retained_socket(&record, &session))
                .await?;
            let binding = self
                .connect(
                    ProviderTransport::console(),
                    Some(&socket),
                    attended,
                    Some(conversation.clone()),
                    &context(cx.generation, deadline.remaining()?),
                )
                .await?;
            let result = async {
                binding
                    .request(
                        "initialize",
                        input::initialize(),
                        &context(cx.generation, deadline.remaining()?),
                    )
                    .await?;
                binding
                    .notify(
                        "initialized",
                        json!({}),
                        &context(cx.generation, deadline.remaining()?),
                    )
                    .await?;
                let response = binding
                    .request(
                        "thread/resume",
                        json!({"threadId":conversation.as_str()}),
                        &context(cx.generation, deadline.remaining()?),
                    )
                    .await?;
                if response.pointer("/thread/id").and_then(Value::as_str)
                    != Some(conversation.as_str())
                {
                    return Err(SeError::invalid(
                        "Codex restart thread",
                        "the exact original conversation",
                    ));
                }
                if let Some(pin) = transcript {
                    let path = response
                        .pointer("/thread/path")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            SeError::invalid(
                                "Codex restart rollout",
                                "the provider-reported persistent path",
                            )
                        })?;
                    if pin.identity != *identity
                        || pin.conversation != *conversation
                        || pin.path.to_local()? != Path::new(path)
                    {
                        return Err(SeError::invalid(
                            "Codex restart rollout",
                            "the original protected path, conversation and session",
                        ));
                    }
                    *binding.rollout.lock().map_err(|_| poisoned())? = Some(pin.path.clone());
                }
                // The response and queued notifications form a single ordered
                // handoff. Completion received during resume cannot leave a
                // phantom active turn or permit input to the wrong turn.
                binding
                    .state
                    .lock()
                    .map_err(|_| poisoned())?
                    .restore(&response)?;
                let record = self
                    .directory(&identity.session)?
                    .join("codex-runtime.json");
                let session = identity.session.clone();
                self.pool
                    .run_owned(&deadline, move || {
                        if Self::retained_socket(&record, &session)? != socket {
                            return Err(SeError::invalid(
                                "Codex restart endpoint",
                                "the original private address",
                            ));
                        }
                        Ok(())
                    })
                    .await?;
                deadline.remaining()?;
                binding.completion.nudge();
                Ok(())
            }
            .await;
            if let Err(error) = result {
                let _ = close(&binding, &cx).await;
                return Err(error);
            }
            Ok(HarnessBinding {
                claude: None,
                codex: Some(binding),
                secode: None,
                _private: (),
            })
        }
    }
}
