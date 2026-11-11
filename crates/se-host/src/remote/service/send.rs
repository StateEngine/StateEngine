use super::*;
use se_core::store_error::store_error;
impl Service {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) async fn send(
        &self,
        request: auth::AuthorizedRemoteRequest,
    ) -> Result<RemoteSendResult> {
        self.router.check_open()?;
        let (admission, input, attribution, permit) = request.into_parts();
        let RemoteRequest::Send(input) = input else {
            return Err(SeError::invalid(
                "remote send",
                "an authorized send request",
            ));
        };
        let target = input.target.clone();
        let grant = admission.grant().grant.clone();
        let revision = admission.grant().authority_revision;
        let key = input.idempotency_key.clone();
        let store_key = se_core::remote::request_key(&attribution, &key)?;
        let store = self.store.clone();
        let batch = self
            .blocking(move || {
                let now = session::now()?;
                let millis = u64::try_from(now / 1000)
                    .map_err(|_| SeError::invalid("send clock", "nonnegative Unix time"))?;
                let facts = se_core::remote::RemoteSendFacts {
                    store: store.info.clone(),
                    generation: store.generation,
                    occurred_at_us: now,
                    message: se_types::MessageId::from_parts(millis, session::entropy()?)?,
                    sent_event: session::event_id(now)?,
                    attribution_event: session::event_id(now)?,
                };
                se_core::remote::plan_send(admission, input, attribution, facts)
            })
            .await?;
        let identity = crate::runtime::WriteIdentity {
            operation: "remote.send",
            natural_key: None,
            key: Some(key.clone()),
            natural_events: vec![],
        };
        let deadline =
            crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
                timeout: Duration::from_secs(30),
                expected_generation: Some(self.router.execution.generation),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            })?;
        // The existing completion observer survives a dropped remote socket and
        // notifies ordinary recipient mail only after the actual store commit.
        let receipt = crate::runtime::submit::remote(
            &self.router.execution,
            batch,
            &identity,
            &deadline,
            permit,
        )
        .await?;
        let known = crate::runtime::CommittedWrite {
            operation: "remote.send".into(),
            key: Some(key.clone()),
            natural_events: vec![],
            committed_events: receipt.events.clone(),
        };
        let store = self.store.clone();
        let service = self.clone();
        let result = self
            .blocking(move || {
                if receipt.request_key.as_ref() != Some(&store_key) {
                    return Err(SeError::invalid("send receipt", "the original request key"));
                }
                let at = session::now()?;
                let original = store.read(|phase| {
                    phase.remote_send_receipt(&grant, revision, &target, &receipt, at)
                })?;
                // Bind the position to its exact send target and original grant. It
                // cannot be opened as a list/watch cursor or expose a global count.
                let associated = serde_json::to_vec(&serde_json::json!({
                    "schema": "stateengine.remote-send-receipt/v1",
                    "host": original.attribution.host,
                    "store": store.info.id,
                    "incarnation": store.info.incarnation,
                    "grant": grant,
                    "authority_revision": revision,
                    "target": target,
                }))
                .map_err(|_| {
                    SeError::invalid("send receipt binding", "serializable scoped facts")
                })?;
                let payload = se_store::remote::position_payload(&receipt.first)
                    .map_err(|e| store_error(&e))?;
                let position = service.cursors.sealed_receipt(&payload, &associated)?;
                let commit = se_types::Commit {
                    event_id: receipt.primary_event,
                    position,
                    idempotency_key: key,
                    value: original.message,
                    effects: se_types::EffectStatus::NotRequired,
                };
                let receipt = match receipt.state {
                    se_store::CommitState::Committed => se_types::Receipt::Committed { commit },
                    se_store::CommitState::Replayed | se_store::CommitState::NaturalKeyReplay => {
                        se_types::Receipt::Replayed { original: commit }
                    }
                };
                Ok(RemoteSendResult {
                    schema: RemoteSendResult::SCHEMA.into(),
                    body: RemoteSendBody {
                        receipt,
                        attribution: original.attribution,
                        delivery: original.delivery,
                    },
                })
            })
            .await;
        result.map_err(|error| known.response_error(error))
    }
}
