//! Retained generation coordination, independent of any public Host object.
use super::*;
use crate::runtime::pool;
use std::sync::atomic::Ordering;
pub(super) enum OwnerJoin {
    NotStarted,
    Thread(std::thread::JoinHandle<()>),
    Joining(tokio::task::JoinHandle<std::thread::Result<()>>),
    Joined,
}
impl Generation {
    pub(super) async fn ready(
        &self,
        options: &api::CallOptions,
    ) -> core::Result<(
        HostedRouter,
        crate::client::lease::Deadline,
        support::CallCancellation,
    )> {
        if options.generation != self.negotiated.generation {
            return Err(core::SeError::invalid(
                "linked call",
                "the negotiated generation and an uncancelled request",
            ));
        }
        let (deadline, cancellation) = support::call_deadline(&self.runtime, options)?;
        let lifecycle = pool::within(&deadline, self.lifecycle.lock()).await?;
        match &*lifecycle {
            Lifecycle::Ready(serving) if self.health() == api::GenerationHealth::Ready => {
                Ok((serving.router.clone(), deadline, cancellation))
            }
            _ => Err(core::SeError::invalid(
                "linked call",
                "a ready embedded host before drain",
            )),
        }
    }
    pub(super) fn set_health(&self, health: api::GenerationHealth) {
        if matches!(
            health,
            api::GenerationHealth::Draining
                | api::GenerationHealth::Drained
                | api::GenerationHealth::Poisoned
                | api::GenerationHealth::Closed
        ) {
            self.native_fence.store(true, Ordering::Release);
        }
        if let Ok(mut current) = self.health.lock() {
            *current = health;
        }
        self.changed.notify_waiters();
    }
    /// Wait for an activating owner's readiness. Timeout keeps it Activating
    /// (call again); a reported failure or a lost owner becomes Failed.
    pub(super) async fn await_ready(
        &self,
        lifecycle: &mut Lifecycle,
        timeout: Duration,
    ) -> Result<(), api::ApiError> {
        let Lifecycle::Activating(activating) = lifecycle else {
            return Ok(());
        };
        let started = match tokio::time::timeout(timeout, &mut activating.ready).await {
            Ok(Ok(started)) => started,
            Ok(Err(_)) => Err(core::SeError::invalid(
                "embedded host",
                "an owner thread that reports readiness",
            )),
            Err(_) => {
                return Err(refused(
                    "host activation",
                    "readiness within the call timeout; call activate again to keep waiting",
                ));
            }
        };
        let Lifecycle::Activating(activating) = std::mem::replace(lifecycle, Lifecycle::Prepared)
        else {
            return Ok(());
        };
        match started {
            Ok((router, stop)) => {
                *lifecycle = Lifecycle::Ready(Box::new(Serving {
                    router,
                    stop,
                    exited: activating.exited,
                }));
                if self.poisoned.load(Ordering::Acquire) {
                    if let Lifecycle::Ready(serving) = lifecycle {
                        serving.router.fenced.store(true, Ordering::Release);
                    }
                    self.set_health(api::GenerationHealth::Poisoned);
                } else {
                    self.set_health(api::GenerationHealth::Ready);
                }
                Ok(())
            }
            Err(error) => {
                let failure = api_error(&error);
                *lifecycle = Lifecycle::Failed(failure.clone());
                self.set_health(api::GenerationHealth::Poisoned);
                Err(failure)
            }
        }
    }
    pub(super) fn owner_inputs(&self, epoch: api::HostEpoch, timeout: Duration) -> OwnerInputs {
        OwnerInputs {
            owner: self.self_ref.clone(),
            runtime: self.runtime.clone(),
            home: self.config.state_home.clone(),
            helper_executable: self.config.helper_executable.clone(),
            linux_delegation: self.config.linux_delegation.clone(),
            limits: self.config.limits.clone(),
            generation: self.negotiated.generation,
            epoch,
            timeout,
            poisoned: Arc::clone(&self.poisoned),
            router_fence: Arc::clone(&self.router_fence),
            quarantined: Arc::clone(&self.quarantined),
            changed: Arc::clone(&self.changed),
            resources: Arc::clone(&self.resources),
        }
    }
    pub(super) fn health(&self) -> api::GenerationHealth {
        if self.quarantined.load(Ordering::Acquire) {
            return api::GenerationHealth::Poisoned;
        }
        let health = self
            .health
            .lock()
            .map(|value| *value)
            .unwrap_or(api::GenerationHealth::Poisoned);
        if self.poisoned.load(Ordering::Acquire)
            && !matches!(
                health,
                api::GenerationHealth::Closed | api::GenerationHealth::Drained
            )
        {
            api::GenerationHealth::Poisoned
        } else {
            health
        }
    }
}

impl Generation {
    pub(super) async fn drain_generation(
        &self,
        options: api::CallOptions,
    ) -> api::Result<api::DrainReceipt> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(refused(
                "quarantined lifecycle",
                "controlled application restart; a panicked lifecycle retains unjoined resources",
            ));
        }
        if options.generation != self.negotiated.generation {
            return Err(refused(
                "drain generation",
                "the exact negotiated generation",
            ));
        }
        let (deadline, _cancel) =
            support::call_deadline(&self.runtime, &options).map_err(|e| api_error(&e))?;
        let mut lifecycle = pool::within(&deadline, self.lifecycle.lock())
            .await
            .map_err(|e| api_error(&e))?;
        pool::within(
            &deadline,
            self.await_ready(
                &mut lifecycle,
                deadline.remaining().map_err(|e| api_error(&e))?,
            ),
        )
        .await
        .map_err(|e| api_error(&e))??;
        let receipt = match &mut *lifecycle {
            Lifecycle::Ready(serving) => {
                self.set_health(api::GenerationHealth::Draining);
                serving.router.fenced.store(true, Ordering::Release);
                serving.stop.request();
                match pool::within(&deadline, &mut serving.exited)
                    .await
                    .map_err(|e| api_error(&e))?
                {
                    Ok(Ok(receipt)) => receipt,
                    Ok(Err(error)) => {
                        self.set_health(api::GenerationHealth::Poisoned);
                        let failure = api_error(&error);
                        *lifecycle = Lifecycle::Failed(failure.clone());
                        return Err(failure);
                    }
                    Err(_) => {
                        self.set_health(api::GenerationHealth::Poisoned);
                        return Err(refused(
                            "embedded drain",
                            "the retained owner's actual shutdown report; preserve quarantine and use controlled application restart",
                        ));
                    }
                }
            }
            Lifecycle::Drained(receipt) if self.health() == api::GenerationHealth::Closed => {
                return Ok(receipt.clone());
            }
            Lifecycle::Drained(receipt) => receipt.clone(),
            Lifecycle::Prepared => api::DrainReceipt {
                generation: self.negotiated.generation,
                pending_notices: 0,
                unresolved_effects: 0,
                writer_flushed: false,
            },
            Lifecycle::Failed(error) => return Err(error.clone()),
            Lifecycle::Activating(_) => {
                return Err(refused(
                    "embedded drain",
                    "completed activation within the original call deadline; retry drain",
                ));
            }
        };
        *lifecycle = Lifecycle::Drained(receipt.clone());
        drop(lifecycle);
        if !self.complete(&receipt) {
            self.set_health(api::GenerationHealth::Poisoned);
            return Ok(receipt);
        }
        let mut remaining = options;
        remaining.timeout = deadline.remaining().map_err(|e| api_error(&e))?;
        self.join_owner(&remaining).await?;
        self.set_health(api::GenerationHealth::Drained);
        Ok(receipt)
    }
    fn complete(&self, receipt: &api::DrainReceipt) -> bool {
        (receipt.writer_flushed || !self.activated.load(Ordering::Acquire))
            && receipt.unresolved_effects == 0
            && receipt.pending_notices == 0
    }
    pub(super) async fn close_generation(
        &self,
        drained: api::DrainReceipt,
        options: api::CallOptions,
    ) -> api::Result<api::DrainReceipt> {
        if self.quarantined.load(Ordering::Acquire) {
            return Err(refused(
                "quarantined lifecycle",
                "controlled application restart; exact unjoined resources remain retained",
            ));
        }
        if options.generation != self.negotiated.generation {
            return Err(refused(
                "close generation",
                "the exact negotiated generation",
            ));
        }
        let (deadline, _cancel) =
            support::call_deadline(&self.runtime, &options).map_err(|e| api_error(&e))?;
        {
            let lifecycle = pool::within(&deadline, self.lifecycle.lock())
                .await
                .map_err(|e| api_error(&e))?;
            if !matches!(&*lifecycle,Lifecycle::Drained(receipt) if *receipt==drained)
                || !self.complete(&drained)
            {
                return Err(refused(
                    "embedded close",
                    "this generation's complete drain receipt; unresolved resources require controlled application restart",
                ));
            }
        }
        let mut remaining = options;
        remaining.timeout = deadline.remaining().map_err(|e| api_error(&e))?;
        self.join_owner(&remaining).await?;
        self.set_health(api::GenerationHealth::Closed);
        Ok(drained)
    }
    async fn join_owner(&self, options: &api::CallOptions) -> api::Result<()> {
        let (deadline, _cancel) =
            support::call_deadline(&self.runtime, options).map_err(|e| api_error(&e))?;
        self.join_owner_before(&deadline).await
    }
    pub(super) async fn join_completed_owner(&self) {
        if self.quarantined.load(Ordering::Acquire) {
            return;
        }
        let result = match support::deadline(owner::SHUTDOWN_BUDGET) {
            Ok(deadline) => self.join_owner_before(&deadline).await,
            Err(error) => Err(api_error(&error)),
        };
        if result.is_err() {
            self.poison_now(true);
        }
    }
    async fn join_owner_before(
        &self,
        deadline: &crate::client::lease::Deadline,
    ) -> api::Result<()> {
        let mut state = pool::within(deadline, self.owner_join.lock())
            .await
            .map_err(|e| api_error(&e))?;
        if matches!(*state, OwnerJoin::Thread(_)) {
            let OwnerJoin::Thread(join) = std::mem::replace(&mut *state, OwnerJoin::NotStarted)
            else {
                return Err(unavailable("retained owner join"));
            };
            *state = OwnerJoin::Joining(self.runtime.spawn_blocking(move || join.join()));
        }
        if let OwnerJoin::Joining(join) = &mut *state {
            let result = pool::within(deadline, join)
                .await
                .map_err(|e| api_error(&e))?;
            if !matches!(result, Ok(Ok(()))) {
                self.set_health(api::GenerationHealth::Poisoned);
                return Err(refused(
                    "embedded owner join",
                    "a successful actual thread join; retain quarantine and use controlled application restart",
                ));
            }
            *state = OwnerJoin::Joined;
            if self.quarantined.load(Ordering::Acquire) {
                return Err(refused(
                    "embedded owner join",
                    "controlled application restart; quarantined resources remain retained",
                ));
            }
            self.resources
                .lock()
                .map_err(|_| unavailable("retained owner resources"))?
                .take();
        }
        Ok(())
    }
}

impl Generation {
    pub(super) async fn poison_generation(
        &self,
        report: &api::FaultReport,
        options: &api::CallOptions,
    ) -> api::Result<api::GenerationHealth> {
        if options.generation != self.negotiated.generation {
            return Err(refused(
                "poison generation",
                "the exact negotiated generation",
            ));
        }
        let (deadline, _cancel) =
            support::call_deadline(&self.runtime, options).map_err(|e| api_error(&e))?;
        deadline.remaining().map_err(|e| api_error(&e))?;
        if report.incident.is_empty() || report.incident.len() > 1024 {
            return Err(refused(
                "poison incident",
                "1..1024 UTF-8 bytes naming this generation's fault",
            ));
        }
        {
            let mut incident = self
                .incident
                .lock()
                .map_err(|_| unavailable("poison incident registry"))?;
            if incident
                .as_ref()
                .is_some_and(|original| original != &report.incident)
            {
                return Err(refused("poison incident", "the original recorded incident"));
            }
            *incident = Some(report.incident.clone());
        }
        self.poison_now(false);
        let lifecycle = pool::within(&deadline, self.lifecycle.lock())
            .await
            .map_err(|e| api_error(&e))?;
        if let Lifecycle::Ready(serving) = &*lifecycle {
            serving.router.fenced.store(true, Ordering::Release);
            serving
                .router
                .execution
                .mail_waits
                .close()
                .map_err(|e| api_error(&e))?;
        }
        Ok(api::GenerationHealth::Poisoned)
    }
}

impl Generation {
    pub(super) fn poison_now(&self, quarantined: bool) {
        self.poisoned.store(true, Ordering::Release);
        if quarantined
            && !self.quarantined.swap(true, Ordering::AcqRel)
            && let Some(owner) = self.self_ref.upgrade()
        {
            // One bounded strong quarantine reference survives dropped public
            // handles/factories. Only process exit can release unjoined work.
            std::mem::forget(owner);
        }
        if let Some(fenced) = self.router_fence.get() {
            fenced.store(true, Ordering::Release);
        }
        self.set_health(api::GenerationHealth::Poisoned);
    }
    pub(super) fn protected<'a, T: Send + 'a>(
        &'a self,
        route: &'static str,
        lifecycle: bool,
        future: impl std::future::Future<Output = api::Result<T>> + Send + 'a,
    ) -> api::HostFuture<'a, T> {
        Box::pin(async move {
            {
                let mut faults = self
                    .faults
                    .lock()
                    .map_err(|_| unavailable("route fault registry"))?;
                if !faults
                    .entry(route)
                    .or_default()
                    .available(std::time::Instant::now())
                {
                    return Err(refused(
                        route,
                        "this route exhausted three restarts in 60 seconds; preserve original request keys and retry after the fault window",
                    ));
                }
            }
            match super::super::tasks::caught(future, lifecycle).await {
                Ok(result) => result,
                Err(()) => {
                    if lifecycle {
                        self.poison_now(true);
                    }
                    if let Ok(mut faults) = self.faults.lock() {
                        faults
                            .entry(route)
                            .or_default()
                            .failed(std::time::Instant::now());
                    }
                    Err(api::ApiError {
                        kind: api::ApiFailure::EnginePanicked,
                        code: "engine-panicked".into(),
                        message: format!(
                            "StateEngine {route} panicked; its original operation may remain unresolved"
                        ),
                        remedy: api::ApiRemedy {
                            text: if lifecycle {
                                "Preserve this data home and use controlled application restart; exact lifecycle resources remain quarantined.".into()
                            } else {
                                "Reconcile the original operation key before retrying this route; unrelated sessions remain available.".into()
                            },
                            command: None,
                        },
                        retry: api::ApiRetry::AfterRefresh,
                    })
                }
            }
        })
    }
}
