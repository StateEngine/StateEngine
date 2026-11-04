//! Embedded SE Code host: the linked `HostFactory`/`Host` over the same
//! HostedRuntime the standalone process runs (sections 10 and 40 §2, W3).
//!
//! `open` is preparation only: a read-only store and schema readback, with no
//! lock, writer, listener or callback. `activate` takes ownership exactly as
//! the standalone child does (prepare, transcript restore, configuration,
//! listener, serve), inside SE Code's process and on SE Code's runtime.
//! `drain` stops serving through the in-process stop and joins every
//! obligation; `close` returns that same result. Methods outside the W3 slice
//! refuse by name instead of inventing an outcome.
mod binding;
mod capture;
mod context;
mod owner;
mod revoke;
mod selector;
mod store;
mod support;
use super::{HostedRouter, LocalStop};
use owner::{OwnerInputs, Started, Stopped, owner_thread};
use se_types as core;
use secode_stateengine_api as api;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use support::{api_error, observe_store, refused, unavailable};
use tokio::{runtime::Handle, sync::oneshot};

/// se-store verifies this exact `PRAGMA application_id` before `info()`
/// returns (se-store connection.rs `APP`), so a successful read implies it.
const STORE_APPLICATION_ID: u32 = 0x5345_4e47;

/// Configured with SE Code's runtime; creates no runtime of its own.
pub struct EmbeddedFactory {
    runtime: Handle,
}
impl EmbeddedFactory {
    pub fn new(runtime: Handle) -> Self {
        Self { runtime }
    }
}
/// The commercial composition's constructor, with exactly the
/// `EmbeddedFactoryBuilder` type in docs/design/commercial-factory.rs.
pub fn embedded_factory(runtime: Handle) -> Arc<dyn api::HostFactory> {
    Arc::new(EmbeddedFactory::new(runtime))
}

/// One activated generation: its router, stop and shutdown report.
struct Serving {
    router: HostedRouter,
    stop: LocalStop,
    exited: oneshot::Receiver<Stopped>,
}
/// An owner thread that has not yet reported readiness. Its receivers live
/// here, so a cancelled or timed-out activate leaves it reachable and a retry
/// resumes the same generation instead of spawning a second owner.
struct Activating {
    ready: oneshot::Receiver<Started>,
    exited: oneshot::Receiver<Stopped>,
}
enum Lifecycle {
    Prepared,
    Activating(Box<Activating>),
    Ready(Box<Serving>),
    Drained(api::DrainReceipt),
    Failed(api::ApiError),
}
struct EmbeddedHost {
    runtime: Handle,
    config: api::HostConfig,
    negotiated: api::Negotiated,
    lifecycle: tokio::sync::Mutex<Lifecycle>,
    health: Mutex<api::GenerationHealth>,
    changed: tokio::sync::Notify,
    native: Mutex<Option<(api::HostEpoch, Arc<dyn api::HostServices>)>>,
    bindings: binding::Bindings,
    binding_gate: tokio::sync::Mutex<()>,
}

impl api::HostFactory for EmbeddedFactory {
    fn open<'a>(
        &'a self,
        config: api::HostConfig,
        options: api::OpenOptions,
    ) -> api::HostFuture<'a, api::Read<api::OpenedHost>> {
        Box::pin(async move {
            if config.kind != api::HostKind::EmbeddedSecode
                || config.api.major != api::API_VERSION.major
            {
                return Err(refused(
                    "embedded host",
                    "an EmbeddedSecode configuration speaking API major 2",
                ));
            }
            let home = config.state_home.clone();
            let observed = tokio::task::spawn_blocking(move || observe_store(home))
                .await
                .map_err(|e| refused("store readback", &e.to_string()))?
                .map_err(|e| api_error(&e))?;
            let Some((info, generation)) = observed else {
                return Ok(api::Read::Absent {
                    checked: "setup-required: no StateEngine store at this state home; run se init for the workspace".into(),
                });
            };
            if options
                .expected_generation
                .is_some_and(|expected| expected.0 != generation)
            {
                return Err(refused(
                    "host generation",
                    "the store's next owner generation",
                ));
            }
            let version = api::StoreVersion {
                application_id: STORE_APPLICATION_ID,
                schema: info.schema_version,
            };
            let negotiated = api::Negotiated {
                api: api::API_VERSION,
                store: version,
                generation: api::Generation(generation),
                // Native mail is not offered by this slice; the local listener is.
                features: config
                    .features
                    .iter()
                    .copied()
                    .filter(|feature| *feature == api::Feature::LocalListener)
                    .collect(),
                limits: config.limits.clone(),
            };
            let host = Arc::new(EmbeddedHost {
                runtime: self.runtime.clone(),
                config,
                negotiated: negotiated.clone(),
                lifecycle: tokio::sync::Mutex::new(Lifecycle::Prepared),
                health: Mutex::new(api::GenerationHealth::Prepared),
                changed: tokio::sync::Notify::new(),
                native: Mutex::new(None),
                bindings: binding::Bindings::new().map_err(|e| api_error(&e))?,
                binding_gate: tokio::sync::Mutex::new(()),
            });
            Ok(api::Read::Present {
                value: api::OpenedHost {
                    host,
                    negotiated,
                    store: api::StoreInfo {
                        id: api::StoreId(info.id.as_str().to_owned()),
                        version,
                        // se-store exposes no public cursor form of its head yet.
                        head: None,
                    },
                    readiness: api::Readiness::Prepared,
                },
            })
        })
    }
    fn restart<'a>(
        &'a self,
        _reason: api::RestartReason,
        _key: api::IdempotencyKey,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Read<api::OpenedHost>> {
        Box::pin(async { Err(unavailable("embedded restart")) })
    }
    fn handover<'a>(
        &'a self,
        _request: api::HandoverRequest,
        _native: Arc<dyn api::HandoverServices>,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Receipt<api::HandoverReport>> {
        Box::pin(async { Err(unavailable("live handover")) })
    }
}

impl EmbeddedHost {
    async fn ready(
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
        let lifecycle = super::pool::within(&deadline, self.lifecycle.lock()).await?;
        match &*lifecycle {
            Lifecycle::Ready(serving)
                if api::Host::health(self) == api::GenerationHealth::Ready =>
            {
                Ok((serving.router.clone(), deadline, cancellation))
            }
            _ => Err(core::SeError::invalid(
                "linked call",
                "a ready embedded host before drain",
            )),
        }
    }
    fn set_health(&self, health: api::GenerationHealth) {
        if let Ok(mut current) = self.health.lock() {
            *current = health;
        }
        self.changed.notify_waiters();
    }
    /// Wait for an activating owner's readiness. Timeout keeps it Activating
    /// (call again); a reported failure or a lost owner becomes Failed.
    async fn await_ready(
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
                self.set_health(api::GenerationHealth::Ready);
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
    fn owner_inputs(&self, epoch: api::HostEpoch, timeout: Duration) -> OwnerInputs {
        OwnerInputs {
            runtime: self.runtime.clone(),
            home: self.config.state_home.clone(),
            helper_executable: self.config.helper_executable.clone(),
            linux_delegation: self.config.linux_delegation.clone(),
            limits: self.config.limits.clone(),
            generation: self.negotiated.generation,
            epoch,
            timeout,
        }
    }
}

impl api::Host for EmbeddedHost {
    fn list_projects<'a>(
        &'a self,
        _authority: &'a api::OwnerAuthority,
        page: api::PageRequest,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::ProjectInfo>>> {
        Box::pin(async move { self.selector_projects(page, options).await.map_err(|e| *e) })
    }
    fn list_agents<'a>(
        &'a self,
        _authority: &'a api::OwnerAuthority,
        project: api::ProjectId,
        page: api::PageRequest,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::AgentInfo>>> {
        Box::pin(async move {
            self.selector_agents(project, page, options)
                .await
                .map_err(|e| *e)
        })
    }
    fn project_active_sessions<'a>(
        &'a self,
        _authority: &'a api::OwnerAuthority,
        project: api::ProjectId,
        page: api::PageRequest,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::ActiveSession>>> {
        Box::pin(async move {
            self.selector_sessions(project, page, options)
                .await
                .map_err(|e| *e)
        })
    }
    fn poison<'a>(
        &'a self,
        _report: api::FaultReport,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::GenerationHealth> {
        Box::pin(async move {
            self.set_health(api::GenerationHealth::Poisoned);
            Ok(api::GenerationHealth::Poisoned)
        })
    }
    fn negotiated(&self) -> api::Negotiated {
        self.negotiated.clone()
    }
    fn health(&self) -> api::GenerationHealth {
        self.health
            .lock()
            .map(|health| *health)
            .unwrap_or(api::GenerationHealth::Poisoned)
    }
    fn wait_health<'a>(
        &'a self,
        after: api::GenerationHealth,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::GenerationHealth> {
        Box::pin(async move {
            // Register before reading, so a change between the read and the
            // wait cannot be missed.
            let mut changed = std::pin::pin!(self.changed.notified());
            changed.as_mut().enable();
            if self.health() != after {
                return Ok(self.health());
            }
            tokio::time::timeout(options.timeout, changed)
                .await
                .map_err(|_| refused("host health", "a change within the call timeout"))?;
            Ok(self.health())
        })
    }
    fn activate<'a>(
        &'a self,
        integration: api::HostIntegration,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Readiness> {
        Box::pin(async move {
            let api::HostIntegration::Secode { epoch, services } = integration;
            if options.generation != self.negotiated.generation {
                return Err(refused(
                    "host activation",
                    "the generation this open negotiated",
                ));
            }
            let mut lifecycle = self.lifecycle.lock().await;
            match &*lifecycle {
                Lifecycle::Prepared => {
                    *self
                        .native
                        .lock()
                        .map_err(|_| unavailable("native host registry"))? =
                        Some((epoch.clone(), services));
                    self.set_health(api::GenerationHealth::Activating);
                    let (ready, exited) = owner_thread(self.owner_inputs(epoch, options.timeout));
                    *lifecycle = Lifecycle::Activating(Box::new(Activating { ready, exited }));
                }
                // A retry resumes the same owner; it never spawns another.
                Lifecycle::Activating(_) => {}
                Lifecycle::Ready(_) => return Ok(api::Readiness::Ready),
                Lifecycle::Drained(_) | Lifecycle::Failed(_) => {
                    return Err(refused("host activation", "one prepared generation"));
                }
            }
            self.await_ready(&mut lifecycle, options.timeout).await?;
            Ok(api::Readiness::Ready)
        })
    }
    fn verify_capability<'a>(
        &'a self,
        _capability: &'a api::SessionCapability,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::BoundSession> {
        Box::pin(async {
            Err(unavailable(
                "process-bound session capabilities in an embedded host",
            ))
        })
    }
    fn open_project<'a>(
        &'a self,
        _authority: &'a api::OwnerAuthority,
        _project: api::ProjectId,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Read<api::ProjectInfo>> {
        Box::pin(async { Err(unavailable("embedded project open")) })
    }
    fn bind_session<'a>(
        &'a self,
        authority: &'a api::BindingAuthority,
        request: api::BindingRequest,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::IssuedSession> {
        Box::pin(async move {
            self.bind(authority, request, options)
                .await
                .map_err(|e| api_error(&e))
        })
    }
    fn revoke_session<'a>(
        &'a self,
        authority: &'a api::Authority,
        request: api::RevokeRequest,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Receipt<api::SessionIdentity>> {
        Box::pin(async move {
            self.revoke(authority, request, options)
                .await
                .map_err(|e| api_error(&e))
        })
    }
    fn tools<'a>(
        &'a self,
        _session: &'a api::BoundSession,
        _page: api::PageRequest,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Page<api::ToolDefinition>> {
        Box::pin(async { Err(unavailable("embedded tool listing")) })
    }
    fn call_tool<'a>(
        &'a self,
        _session: &'a api::BoundSession,
        _call: api::ToolCall,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::ToolOutput> {
        Box::pin(async { Err(unavailable("embedded tool calls")) })
    }
    fn continuity<'a>(
        &'a self,
        session: &'a api::BoundSession,
        request: api::ContinuityRequest,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::SessionContext> {
        Box::pin(async move {
            self.context(session, request, options)
                .await
                .map_err(|e| api_error(&e))
        })
    }
    fn capture_turn<'a>(
        &'a self,
        session: &'a api::BoundSession,
        turn: api::CapturedTurn,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Receipt<api::EventRef>> {
        Box::pin(async move {
            self.capture(session, turn, options)
                .await
                .map_err(|e| api_error(&e))
        })
    }
    fn native_state_changed<'a>(
        &'a self,
        _target: &'a api::HostSessionTarget,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, ()> {
        Box::pin(async { Err(unavailable("native mail targets")) })
    }
    fn adoption_status<'a>(
        &'a self,
        _authority: &'a api::OwnerAuthority,
        _page: api::PageRequest,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Page<api::Adoption>> {
        Box::pin(async { Err(unavailable("adoption status")) })
    }
    fn drain<'a>(&'a self, options: api::CallOptions) -> api::HostFuture<'a, api::DrainReceipt> {
        Box::pin(async move {
            let mut lifecycle = self.lifecycle.lock().await;
            // A generation still starting finishes starting before it stops.
            self.await_ready(&mut lifecycle, options.timeout).await?;
            let receipt = match &mut *lifecycle {
                Lifecycle::Ready(serving) => {
                    self.set_health(api::GenerationHealth::Draining);
                    serving.stop.request();
                    // Await by reference: a cancelled or timed-out drain keeps the
                    // generation serving, so a later drain waits for the real report.
                    match tokio::time::timeout(options.timeout, &mut serving.exited).await {
                        Ok(Ok(Ok(receipt))) => receipt,
                        Ok(Ok(Err(error))) => {
                            let failure = api_error(&error);
                            *lifecycle = Lifecycle::Failed(failure.clone());
                            self.set_health(api::GenerationHealth::Poisoned);
                            return Err(failure);
                        }
                        Ok(Err(_)) => {
                            let failure = refused(
                                "embedded host",
                                "an owner thread that reports its shutdown",
                            );
                            *lifecycle = Lifecycle::Failed(failure.clone());
                            return Err(failure);
                        }
                        Err(_) => {
                            return Err(refused(
                                "embedded drain",
                                "shutdown within the call timeout; drain again",
                            ));
                        }
                    }
                }
                // await_ready left it Ready or Failed, or already returned.
                Lifecycle::Activating(_) => {
                    return Err(refused(
                        "embedded drain",
                        "a generation that finished activating",
                    ));
                }
                Lifecycle::Drained(receipt) => return Ok(receipt.clone()),
                // Never activated: no writer, listener or effect ever existed.
                Lifecycle::Prepared => api::DrainReceipt {
                    generation: self.negotiated.generation,
                    pending_notices: 0,
                    unresolved_effects: 0,
                    writer_flushed: true,
                },
                Lifecycle::Failed(error) => return Err(error.clone()),
            };
            *lifecycle = Lifecycle::Drained(receipt.clone());
            self.set_health(
                if receipt.writer_flushed
                    && receipt.unresolved_effects == 0
                    && receipt.pending_notices == 0
                {
                    api::GenerationHealth::Drained
                } else {
                    api::GenerationHealth::Poisoned
                },
            );
            Ok(receipt)
        })
    }
    fn close<'a>(
        &'a self,
        drained: api::DrainReceipt,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::DrainReceipt> {
        Box::pin(async move {
            let lifecycle = self.lifecycle.lock().await;
            match &*lifecycle {
                Lifecycle::Drained(receipt) if *receipt == drained => {
                    if !receipt.writer_flushed
                        || receipt.unresolved_effects != 0
                        || receipt.pending_notices != 0
                    {
                        return Err(refused(
                            "embedded host close",
                            "a completely flushed drain with no unresolved effects or notices; this runtime retains custody and requires controlled application restart",
                        ));
                    }
                    self.set_health(api::GenerationHealth::Closed);
                    Ok(receipt.clone())
                }
                _ => Err(refused(
                    "host close",
                    "the receipt this generation's drain returned",
                )),
            }
        })
    }
}
