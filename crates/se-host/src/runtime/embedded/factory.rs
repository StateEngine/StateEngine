//! Stable-key restart through retained resources, without invoking an old Host.
use super::*;
#[derive(Default)]
pub(super) struct Retained {
    generations: Vec<Arc<Generation>>,
    restarts: Vec<Restart>,
}
struct Restart {
    from: api::Generation,
    key: api::IdempotencyKey,
    reason: api::RestartReason,
    opened: Option<api::Read<api::OpenedHost>>,
}
impl EmbeddedFactory {
    pub(super) fn remember(&self, generation: Arc<Generation>) -> api::Result<Arc<Generation>> {
        let mut retained = self
            .retained
            .lock()
            .map_err(|_| unavailable("factory generation registry"))?;
        if let Some(old) = retained.generations.iter().find(|old| {
            old.config.state_home == generation.config.state_home
                && old.negotiated.generation == generation.negotiated.generation
        }) {
            if old.config.helper_executable != generation.config.helper_executable
                || old.config.api != generation.config.api
                || old.config.kind != generation.config.kind
                || old.config.features != generation.config.features
                || old.config.limits != generation.config.limits
                || old.config.linux_delegation != generation.config.linux_delegation
            {
                return Err(refused(
                    "prepared generation",
                    "the original configuration; close it before changing configuration",
                ));
            }
            return Ok(Arc::clone(old));
        }
        if retained.generations.len() >= 32 {
            return Err(refused(
                "retained generation capacity",
                "controlled application restart after closing owned generations",
            ));
        }
        retained.generations.push(Arc::clone(&generation));
        Ok(generation)
    }
    pub(super) async fn restart_generation(
        &self,
        reason: api::RestartReason,
        key: api::IdempotencyKey,
        options: api::CallOptions,
    ) -> api::Result<api::Read<api::OpenedHost>> {
        let (deadline, _cancel) =
            support::call_deadline(&self.runtime, &options).map_err(|e| api_error(&e))?;
        let _serial = super::super::pool::within(&deadline, self.restart_gate.lock())
            .await
            .map_err(|e| api_error(&e))?;
        if key.0.is_empty() || key.0.len() > 128 {
            return Err(refused(
                "restart key",
                "1..128 UTF-8 bytes retained for this exact source generation",
            ));
        }
        let source = {
            let mut retained = self
                .retained
                .lock()
                .map_err(|_| unavailable("factory generation registry"))?;
            if let Some(old) = retained.restarts.iter().find(|old| old.key == key) {
                if old.from != options.generation || old.reason != reason {
                    return Err(refused(
                        "restart key conflict",
                        "the original generation and reason for this key",
                    ));
                }
                if let Some(opened) = &old.opened {
                    return Ok(copy_opened(opened));
                }
            }
            let replayed = retained.restarts.iter().any(|old| old.key == key);
            if retained
                .restarts
                .iter()
                .any(|old| old.from == options.generation && old.key != key)
            {
                return Err(refused(
                    "restart source key",
                    "retry the original restart key; this source already has an admitted restart",
                ));
            }
            if retained.restarts.len() >= 32 {
                return Err(refused(
                    "restart key capacity",
                    "controlled application restart; retained keys are never evicted into duplicate restarts",
                ));
            }
            let mut selected = retained
                .generations
                .iter()
                .filter(|g| g.negotiated.generation == options.generation);
            let source = selected.next().cloned().ok_or_else(|| {
                refused(
                    "restart generation",
                    "an exact generation retained by this factory",
                )
            })?;
            if selected.next().is_some() {
                return Err(refused(
                    "restart generation",
                    "one unambiguous state home per generation in this factory",
                ));
            }
            if !replayed {
                match &reason {
                    api::RestartReason::Drained { receipt }
                        if receipt.generation == options.generation
                            && matches!(
                                source.health(),
                                api::GenerationHealth::Drained | api::GenerationHealth::Closed
                            ) => {}
                    api::RestartReason::Poisoned { incident }
                        if !incident.is_empty()
                            && incident.len() <= 1024
                            && source.health() == api::GenerationHealth::Poisoned => {}
                    _ => {
                        return Err(refused(
                            "restart source",
                            "this generation's actual drain receipt or recorded poison incident",
                        ));
                    }
                }
                retained.restarts.push(Restart {
                    from: options.generation,
                    key: key.clone(),
                    reason: reason.clone(),
                    opened: None,
                });
            }
            source
        };
        let mut remaining = options.clone();
        remaining.timeout = deadline.remaining().map_err(|e| api_error(&e))?;
        let receipt = source.drain_generation(remaining.clone()).await?;
        if let api::RestartReason::Drained { receipt: expected } = &reason
            && *expected != receipt
        {
            return Err(refused(
                "restart drain receipt",
                "the exact receipt retained by this generation",
            ));
        }
        remaining.timeout = deadline.remaining().map_err(|e| api_error(&e))?;
        source.close_generation(receipt, remaining).await?;
        let next = options
            .generation
            .0
            .checked_add(1)
            .ok_or_else(|| refused("host generation", "a nonexhausted generation counter"))?;
        let opened = api::HostFactory::open(
            self,
            source.config.clone(),
            api::OpenOptions {
                expected_generation: Some(api::Generation(next)),
                timeout: deadline.remaining().map_err(|e| api_error(&e))?,
                cancellation: options.cancellation,
            },
        )
        .await?;
        let mut retained = self
            .retained
            .lock()
            .map_err(|_| unavailable("factory restart registry"))?;
        let admitted = retained
            .restarts
            .iter_mut()
            .find(|old| old.key == key)
            .ok_or_else(|| unavailable("retained restart intent"))?;
        admitted.opened = Some(copy_opened(&opened));
        Ok(opened)
    }
}

fn copy_opened(read: &api::Read<api::OpenedHost>) -> api::Read<api::OpenedHost> {
    match read {
        api::Read::Present { value } => api::Read::Present {
            value: api::OpenedHost {
                host: Arc::clone(&value.host),
                negotiated: value.negotiated.clone(),
                store: value.store.clone(),
                readiness: value.readiness.clone(),
            },
        },
        api::Read::Absent { checked } => api::Read::Absent {
            checked: checked.clone(),
        },
        api::Read::Unreadable {
            source,
            reason,
            error,
        } => api::Read::Unreadable {
            source: source.clone(),
            reason: reason.clone(),
            error: error.clone(),
        },
        api::Read::Unknown { what } => api::Read::Unknown { what: what.clone() },
    }
}

impl EmbeddedFactory {
    pub(super) fn protected<'a, T: Send + 'a>(
        &'a self,
        generation: Option<api::Generation>,
        future: impl std::future::Future<Output = api::Result<T>> + Send + 'a,
    ) -> api::HostFuture<'a, T> {
        Box::pin(async move {
            match super::super::tasks::caught(future, generation.is_some()).await {
                Ok(result) => result,
                Err(()) => {
                    if let Ok(retained) = self.retained.lock() {
                        for source in &retained.generations {
                            if Some(source.negotiated.generation) == generation {
                                source.poison_now(true);
                            }
                        }
                    }
                    Err(api::ApiError {kind:api::ApiFailure::EnginePanicked,code:"factory-panicked".into(),message:"StateEngine factory operation panicked; its exact generation remains retained".into(),remedy:api::ApiRemedy{text:"Preserve the data home and use controlled application restart if lifecycle resources remain unjoined.".into(),command:None},retry:api::ApiRetry::AfterRefresh})
                }
            }
        })
    }
}
