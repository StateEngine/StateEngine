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
mod factory;
mod generation;
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
    retained: Mutex<factory::Retained>,
    restart_gate: tokio::sync::Mutex<()>,
}
impl EmbeddedFactory {
    pub fn new(runtime: Handle) -> Self {
        Self {
            runtime,
            retained: Mutex::new(factory::Retained::default()),
            restart_gate: tokio::sync::Mutex::new(()),
        }
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
struct Generation {
    runtime: Handle,
    config: api::HostConfig,
    negotiated: api::Negotiated,
    lifecycle: tokio::sync::Mutex<Lifecycle>,
    health: Mutex<api::GenerationHealth>,
    changed: Arc<tokio::sync::Notify>,
    native: Mutex<Option<(api::HostEpoch, Arc<dyn api::HostServices>)>>,
    bindings: binding::Bindings,
    binding_gate: tokio::sync::Mutex<()>,
    owner_join: tokio::sync::Mutex<generation::OwnerJoin>,
    resources: Arc<Mutex<Option<owner::RetainedResources>>>,
    activated: std::sync::atomic::AtomicBool,
    poisoned: Arc<std::sync::atomic::AtomicBool>,
    quarantined: Arc<std::sync::atomic::AtomicBool>,
    router_fence: Arc<std::sync::OnceLock<Arc<std::sync::atomic::AtomicBool>>>,
    faults: Mutex<std::collections::BTreeMap<&'static str, super::tasks::FaultBudget>>,
}

struct EmbeddedHost {
    generation: Arc<Generation>,
}
impl std::ops::Deref for EmbeddedHost {
    type Target = Generation;
    fn deref(&self) -> &Generation {
        &self.generation
    }
}

impl api::HostFactory for EmbeddedFactory {
    fn open<'a>(
        &'a self,
        config: api::HostConfig,
        options: api::OpenOptions,
    ) -> api::HostFuture<'a, api::Read<api::OpenedHost>> {
        self.protected(None,async move {
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
            let generation = Arc::new(Generation {
                runtime: self.runtime.clone(),
                config,
                negotiated: negotiated.clone(),
                lifecycle: tokio::sync::Mutex::new(Lifecycle::Prepared),
                health: Mutex::new(api::GenerationHealth::Prepared),
                changed: Arc::new(tokio::sync::Notify::new()),
                native: Mutex::new(None),
                bindings: binding::Bindings::new().map_err(|e| api_error(&e))?,
                binding_gate: tokio::sync::Mutex::new(()),
                owner_join: tokio::sync::Mutex::new(generation::OwnerJoin::NotStarted),
                resources: Arc::new(Mutex::new(None)),
                activated: std::sync::atomic::AtomicBool::new(false),
                poisoned: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                quarantined: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                router_fence: Arc::new(std::sync::OnceLock::new()),
                faults: Mutex::new(std::collections::BTreeMap::new()),
            });
            let generation = self.remember(generation)?;
            let host = Arc::new(EmbeddedHost { generation });
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
        reason: api::RestartReason,
        key: api::IdempotencyKey,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Read<api::OpenedHost>> {
        self.protected(Some(options.generation), async move {
            self.restart_generation(reason, key, options).await
        })
    }
    fn handover<'a>(
        &'a self,
        _request: api::HandoverRequest,
        _native: Arc<dyn api::HandoverServices>,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Receipt<api::HandoverReport>> {
        self.protected(None, async { Err(unavailable("live handover")) })
    }
}

impl api::Host for EmbeddedHost {
    fn list_projects<'a>(
        &'a self,
        _authority: &'a api::OwnerAuthority,
        page: api::PageRequest,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::ProjectInfo>>> {
        self.protected("list_projects", false, async move {
            self.selector_projects(page, options).await.map_err(|e| *e)
        })
    }
    fn list_agents<'a>(
        &'a self,
        _authority: &'a api::OwnerAuthority,
        project: api::ProjectId,
        page: api::PageRequest,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Read<api::Page<api::AgentInfo>>> {
        self.protected("list_agents", false, async move {
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
        self.protected("project_active_sessions", false, async move {
            self.selector_sessions(project, page, options)
                .await
                .map_err(|e| *e)
        })
    }
    fn poison<'a>(
        &'a self,
        _report: api::FaultReport,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::GenerationHealth> {
        self.protected("poison", true, async move {
            self.poison_generation(&options).await
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
        self.protected("wait_health", false, async move {
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
        self.protected("activate", true, async move {
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
                    self.activated
                        .store(true, std::sync::atomic::Ordering::Release);
                    let (ready, exited, join) =
                        owner_thread(self.owner_inputs(epoch, options.timeout));
                    *self.owner_join.lock().await = join.map_or(
                        generation::OwnerJoin::NotStarted,
                        generation::OwnerJoin::Thread,
                    );
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
            if self.health() != api::GenerationHealth::Ready {
                return Err(refused(
                    "host activation",
                    "a healthy unfenced generation; use independent factory recovery",
                ));
            }
            Ok(api::Readiness::Ready)
        })
    }
    fn verify_capability<'a>(
        &'a self,
        _capability: &'a api::SessionCapability,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::BoundSession> {
        self.protected("verify_capability", false, async {
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
        self.protected("open_project", false, async {
            Err(unavailable("embedded project open"))
        })
    }
    fn bind_session<'a>(
        &'a self,
        authority: &'a api::BindingAuthority,
        request: api::BindingRequest,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::IssuedSession> {
        self.protected("bind_session", false, async move {
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
        self.protected("revoke_session", false, async move {
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
        self.protected("tools", false, async {
            Err(unavailable("embedded tool listing"))
        })
    }
    fn call_tool<'a>(
        &'a self,
        _session: &'a api::BoundSession,
        _call: api::ToolCall,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::ToolOutput> {
        self.protected("call_tool", false, async {
            Err(unavailable("embedded tool calls"))
        })
    }
    fn continuity<'a>(
        &'a self,
        session: &'a api::BoundSession,
        request: api::ContinuityRequest,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::SessionContext> {
        self.protected("continuity", false, async move {
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
        self.protected("capture_turn", false, async move {
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
        self.protected("native_state_changed", false, async {
            Err(unavailable("native mail targets"))
        })
    }
    fn adoption_status<'a>(
        &'a self,
        _authority: &'a api::OwnerAuthority,
        _page: api::PageRequest,
        _options: api::CallOptions,
    ) -> api::HostFuture<'a, api::Page<api::Adoption>> {
        self.protected("adoption_status", false, async {
            Err(unavailable("adoption status"))
        })
    }
    fn drain<'a>(&'a self, options: api::CallOptions) -> api::HostFuture<'a, api::DrainReceipt> {
        self.protected("drain", true, async move {
            self.drain_generation(options).await
        })
    }
    fn close<'a>(
        &'a self,
        drained: api::DrainReceipt,
        options: api::CallOptions,
    ) -> api::HostFuture<'a, api::DrainReceipt> {
        self.protected("close", true, async move {
            self.close_generation(drained, options).await
        })
    }
}
