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
mod owner;
mod support;
use super::{HostedRouter, LocalStop};
use owner::{OwnerInputs, owner_thread};
use se_types as core;
use secode_stateengine_api as api;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use support::{api_error, refused, unavailable};
use tokio::{runtime::Handle, sync::oneshot};

/// se-store verifies this exact `PRAGMA application_id` before `info()`
/// returns (se-store connection.rs `APP`), so a successful read implies it.
const STORE_APPLICATION_ID: u32 = 0x5345_4e47;
const STORE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Configured with SE Code's runtime; creates no runtime of its own.
pub struct EmbeddedFactory {
    runtime: Handle,
}
impl EmbeddedFactory {
    pub fn new(runtime: Handle) -> Self {
        Self { runtime }
    }
}

/// One activated generation: its router, stop and shutdown report.
struct Serving {
    router: HostedRouter,
    stop: LocalStop,
    exited: oneshot::Receiver<api::DrainReceipt>,
}
enum Lifecycle {
    Prepared,
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

/// Read-only: the store's identity/schema and the next owner generation.
fn observe_store(home: PathBuf) -> core::Result<Option<(se_store::StoreInfo, u64)>> {
    use se_store::ReadStore;
    let options = se_store::StoreOptions {
        state_directory: home,
        busy_timeout: STORE_BUSY_TIMEOUT,
    };
    let capacity = std::num::NonZeroU32::MIN.saturating_add(1);
    let store = |e: Box<se_store::StoreError>| se_core::store_error::store_error(&e);
    let reader = match se_store::SqliteFactory::open_reader_with_capacity(&options, capacity)
        .map_err(store)?
    {
        core::Read::Present { value } => value,
        core::Read::Absent { .. } => return Ok(None),
        core::Read::Unreadable { reason, .. } => {
            return Err(se_core::scope::unreadable("state store", &reason));
        }
        core::Read::Unknown { what } => {
            return Err(se_core::scope::unreadable("state store", &what));
        }
    };
    let info = reader.info().map_err(store)?;
    let next = match reader.runtime_owner().map_err(store)? {
        core::Read::Present { value } => value.generation.get().saturating_add(1),
        core::Read::Absent { .. } => 1,
        core::Read::Unreadable { reason, .. } => {
            return Err(se_core::scope::unreadable("runtime owner", &reason));
        }
        core::Read::Unknown { what } => {
            return Err(se_core::scope::unreadable("runtime owner", &what));
        }
    };
    Ok(Some((info, next)))
}

impl EmbeddedHost {
    fn set_health(&self, health: api::GenerationHealth) {
        if let Ok(mut current) = self.health.lock() {
            *current = health;
        }
        self.changed.notify_waiters();
    }
    fn owner_inputs(&self, epoch: api::HostEpoch, timeout: Duration) -> OwnerInputs {
        OwnerInputs {
            runtime: self.runtime.clone(),
            home: self.config.state_home.clone(),
            limits: self.config.limits.clone(),
            generation: self.negotiated.generation,
            epoch,
            timeout,
        }
    }
}

impl api::Host for EmbeddedHost {
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
            let changed = self.changed.notified();
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
            let api::HostIntegration::Secode { epoch, services: _ } = integration;
            let mut lifecycle = self.lifecycle.lock().await;
            if !matches!(*lifecycle, Lifecycle::Prepared) {
                return Err(refused("host activation", "one prepared generation"));
            }
            self.set_health(api::GenerationHealth::Activating);
            let (ready, exited) = owner_thread(self.owner_inputs(epoch, options.timeout));
            let started = match tokio::time::timeout(options.timeout, ready).await {
                Ok(Ok(started)) => started,
                Ok(Err(_)) => Err(core::SeError::invalid(
                    "embedded host",
                    "an owner thread that reports readiness",
                )),
                Err(_) => Err(core::SeError::invalid(
                    "host activation",
                    "readiness within the call timeout",
                )),
            };
            match started {
                Ok((router, stop)) => {
                    *lifecycle = Lifecycle::Ready(Box::new(Serving {
                        router,
                        stop,
                        exited,
                    }));
                    self.set_health(api::GenerationHealth::Ready);
                    Ok(api::Readiness::Ready)
                }
                Err(error) => {
                    let failure = api_error(&error);
                    *lifecycle = Lifecycle::Failed(failure.clone());
                    self.set_health(api::GenerationHealth::Poisoned);
                    Err(failure)
                }
            }
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
        _authority: &'a api::BindingAuthority,
        _request: api::BindingRequest,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::IssuedSession> {
        Box::pin(async { Err(unavailable("embedded session binding")) })
    }
    fn revoke_session<'a>(
        &'a self,
        _authority: &'a api::Authority,
        _request: api::RevokeRequest,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Receipt<api::SessionIdentity>> {
        Box::pin(async { Err(unavailable("embedded session revocation")) })
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
        _session: &'a api::BoundSession,
        _request: api::ContinuityRequest,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::SessionContext> {
        Box::pin(async { Err(unavailable("session continuity")) })
    }
    fn capture_turn<'a>(
        &'a self,
        _session: &'a api::BoundSession,
        _turn: api::CapturedTurn,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Receipt<api::EventRef>> {
        Box::pin(async { Err(unavailable("embedded turn capture")) })
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
            let receipt = match std::mem::replace(&mut *lifecycle, Lifecycle::Prepared) {
                Lifecycle::Ready(serving) => {
                    let Serving {
                        stop,
                        exited,
                        router,
                    } = *serving;
                    drop(router);
                    self.set_health(api::GenerationHealth::Draining);
                    stop.request();
                    match tokio::time::timeout(options.timeout, exited).await {
                        Ok(Ok(receipt)) => receipt,
                        Ok(Err(_)) => {
                            let failure = refused(
                                "embedded host",
                                "an owner thread that reports its shutdown",
                            );
                            *lifecycle = Lifecycle::Failed(failure.clone());
                            return Err(failure);
                        }
                        // Still joining: keep nothing that would claim it closed.
                        Err(_) => {
                            let failure = refused(
                                "embedded drain",
                                "shutdown within the call timeout; drain again",
                            );
                            *lifecycle = Lifecycle::Failed(failure.clone());
                            return Err(failure);
                        }
                    }
                }
                Lifecycle::Drained(receipt) => receipt,
                // Never activated: no writer, listener or effect ever existed.
                Lifecycle::Prepared => api::DrainReceipt {
                    generation: self.negotiated.generation,
                    pending_notices: 0,
                    unresolved_effects: 0,
                    writer_flushed: true,
                },
                Lifecycle::Failed(error) => {
                    *lifecycle = Lifecycle::Failed(error.clone());
                    return Err(error);
                }
            };
            *lifecycle = Lifecycle::Drained(receipt.clone());
            self.set_health(api::GenerationHealth::Drained);
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
