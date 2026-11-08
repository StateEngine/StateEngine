//! Source-host broker for typed list, watch and send operations.
//! It holds protected credentials, never exposes them through IPC, and
//! starts no listener or provider process. Installation is explicit and optional.
mod bindings;
mod call;
use bindings::{BindingResolver, Connections};
mod watch;
use super::*;
use se_core::{
    admission::HumanTerminal,
    ops::{AnyOp, AnyOutput, remote::*},
};
use se_store::{Actor, Admission, RecordIdentity, Scope};
use se_types::{ProjectId, Result, SeError, SessionId};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::OnceCell;

const MAX_SOURCES: usize = 64;

/// Trusted local configuration read under security's native owner-only guard.
/// Not deserializable: aliases/arguments cannot provide a key or grant.
pub struct BrokerBinding {
    pub alias: String,
    pub route: RemoteRoute,
    pub device: MachineSession,
    pub signer: Arc<dyn CredentialSource>,
}
struct Binding {
    config: BrokerBinding,
    client: Arc<OnceCell<Arc<dyn RemoteClient>>>,
}
/// Verified by protected native IPC or the session-only loopback MCP route on
/// this call. No caller-provided actor/session field is used to construct it.
pub struct VerifiedSourceSession {
    source: RemoteSourceSession,
    fence: Arc<AtomicBool>,
    credential: se_store::RecordId,
}
impl VerifiedSourceSession {
    pub fn source(&self) -> &RemoteSourceSession {
        &self.source
    }
    fn context(&self) -> RemoteCallContext {
        RemoteCallContext::from_verified_source(self.source.clone(), Arc::clone(&self.fence))
    }
}
struct Source {
    credential: se_store::RecordId,
    fence: Weak<AtomicBool>,
}
type SourceKey = (ProjectId, SessionId, [u8; 16]);
#[derive(Default)]
struct Sources {
    entries: BTreeMap<SourceKey, Source>,
    stopping_sessions: BTreeSet<(ProjectId, SessionId)>,
    stopping_credentials: BTreeSet<(ProjectId, [u8; 16])>,
}
pub struct RemoteBroker {
    source_host: RemoteHostId,
    connector: Arc<dyn RemoteConnector>,
    resolver: Arc<dyn BindingResolver>,
    connections: Mutex<Connections>,
    sources: Mutex<Sources>,
    watches: watch::Watches,
    closed: AtomicBool,
}
impl RemoteBroker {
    #[cfg(feature = "remote")]
    pub(crate) fn source_host(&self) -> RemoteHostId {
        self.source_host
    }
    /// Call only with the security lane's verified saved binding/key values.
    /// An absent broker remains None in the existing host: no remote tasks,
    /// timers, maximum-sized buffers or async initialization in local CLI reads.
    #[cfg(feature = "remote")]
    fn with_resolver(
        source_host: RemoteHostId,
        connector: Arc<dyn RemoteConnector>,
        resolver: Arc<dyn BindingResolver>,
    ) -> Self {
        Self {
            source_host,
            connector,
            resolver,
            connections: Mutex::new(Connections::default()),
            sources: Mutex::new(Sources::default()),
            watches: watch::Watches::default(),
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) fn check_open(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            Err(refused("the owning source host is closing"))
        } else {
            Ok(())
        }
    }
    pub(crate) async fn disconnect(&self, host: RemoteHostId) -> Result<()> {
        let clients = self
            .connections
            .lock()
            .map_err(|_| poisoned())?
            .remove_host(host);
        for client in clients {
            client.close().await?;
        }
        Ok(())
    }
    pub(crate) async fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        let mut first = None;
        match self.sources.lock() {
            Ok(sources) => {
                for source in sources.entries.values() {
                    if let Some(fence) = source.fence.upgrade() {
                        fence.store(true, Ordering::Release);
                    }
                }
            }
            Err(_) => first = Some(poisoned()),
        }
        if let Err(error) = self.watches.close() {
            first = Some(error);
        }
        let clients = self.connections.lock().map_err(|_| poisoned())?.clients();
        for client in clients {
            if let Err(error) = client.close().await
                && first.is_none()
            {
                first = Some(error);
            }
        }
        first.map_or(Ok(()), Err)
    }
    pub(crate) fn verified_source(
        &self,
        admission: &Admission,
        credential: se_store::RecordId,
    ) -> Result<VerifiedSourceSession> {
        self.check_open()?;
        let (Scope::Project(project), Actor::Agent(agent), Some(session)) =
            (&admission.scope, &admission.actor, &admission.session)
        else {
            return Err(refused(
                "source admission is not a current bound agent session",
            ));
        };
        let source = RemoteSourceSession {
            host: self.source_host,
            project: project.clone(),
            agent: agent.clone(),
            session: session.clone(),
            generation: se_types::Generation::new(admission.generation)?,
        };
        let mut sources = self.sources.lock().map_err(|_| poisoned())?;
        sources.entries.retain(|_, s| s.fence.strong_count() > 0);
        if sources
            .stopping_sessions
            .contains(&(project.clone(), session.clone()))
            || sources
                .stopping_credentials
                .contains(&(project.clone(), *credential.as_bytes()))
        {
            return Err(refused(
                "this source session/credential has a pending or unresolved stop; reconnect after its owner resolves it",
            ));
        }
        let key = (project.clone(), session.clone(), *credential.as_bytes());
        let fence = if let Some(old) = sources.entries.get(&key) {
            if old.credential != credential {
                return Err(refused(
                    "source credential changed during this retained session",
                ));
            }
            old.fence.upgrade().ok_or_else(poisoned)?
        } else {
            if sources.entries.len() >= MAX_SOURCES {
                return Err(refused(
                    "source session capacity reached; close an older watch",
                ));
            }
            let fence = Arc::new(AtomicBool::new(false));
            sources.entries.insert(
                key,
                Source {
                    credential,
                    fence: Arc::downgrade(&fence),
                },
            );
            fence
        };
        let verified = VerifiedSourceSession {
            source,
            fence,
            credential,
        };
        verified.context().check_current()?;
        Ok(verified)
    }
    /// Fence before accepting a local revocation/stop transition. Unknown or
    /// failed stop cannot reopen a queued old request. No await/auth lock here.
    pub(crate) fn fence(&self, revoked: &crate::runtime::mail::Revocations) -> Result<()> {
        let mut sources = self.sources.lock().map_err(|_| poisoned())?;
        // Retain stop intents through their durable completion. Otherwise an
        // old session could register a new fence after the pre-submit sweep.
        if sources.stopping_sessions.len()
            + sources.stopping_credentials.len()
            + revoked.sessions.len()
            + revoked.credentials.len()
            > 4096
        {
            return Err(refused(
                "unresolved source stop capacity reached; the Owner must resolve earlier stops",
            ));
        }
        sources
            .stopping_sessions
            .extend(revoked.sessions.iter().cloned());
        sources.stopping_credentials.extend(
            revoked
                .credentials
                .iter()
                .map(|(p, c)| (p.clone(), *c.as_bytes())),
        );
        for (key, source) in &sources.entries {
            if (sources
                .stopping_sessions
                .contains(&(key.0.clone(), key.1.clone()))
                || sources
                    .stopping_credentials
                    .contains(&(key.0.clone(), key.2)))
                && let Some(fence) = source.fence.upgrade()
            {
                fence.store(true, Ordering::Release);
            }
        }
        self.watches.remove_fenced()?;
        Ok(())
    }
    pub(crate) fn fence_committed(
        &self,
        revoked: &crate::runtime::mail::Revocations,
    ) -> Result<()> {
        // Re-sweep before retiring pending intent. Later calls recheck the real
        // credential after registration and see this committed revoke/epoch.
        self.fence(revoked)?;
        let mut sources = self.sources.lock().map_err(|_| poisoned())?;
        for key in &revoked.sessions {
            sources.stopping_sessions.remove(key);
        }
        for (project, credential) in &revoked.credentials {
            sources
                .stopping_credentials
                .remove(&(project.clone(), *credential.as_bytes()));
        }
        Ok(())
    }
    async fn connection(
        &self,
        b: &Binding,
        call: &RemoteCallContext,
    ) -> Result<Arc<dyn RemoteClient>> {
        self.check_open()?;
        call.check_current()?;
        let connected = b
            .client
            .get_or_try_init(|| {
                self.connector.connect(
                    b.config.route.clone(),
                    b.config.device.clone(),
                    Arc::clone(&b.config.signer),
                )
            })
            .await?;
        call.check_current()?;
        Ok(Arc::clone(connected))
    }
}
fn scope(allowed: &RemoteScope, verb: RemoteVerb, targets: &mut Vec<RemoteTarget>) -> Result<()> {
    if targets.is_empty() {
        *targets = allowed.targets.clone();
    }
    if targets.iter().any(|t| !allowed.allows(verb, t)) {
        return Err(refused("selected target or verb is outside this grant"));
    }
    Ok(())
}
fn check_size(value: &impl serde::Serialize, budget: u32) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| refused("remote result encoding failed"))?;
    if bytes.len() > budget as usize {
        return Err(SeError::too_large(
            "remote whole result",
            budget as usize,
            bytes.len(),
        ));
    }
    Ok(())
}
fn refused(reason: &str) -> SeError {
    SeError::new(se_types::Detail::CapabilityInvalid(se_types::details::CapabilityInvalid {subject:"remote source broker".into(),reason:reason.into(),next_step:"Use the Owner-configured binding and current launched source session; never fall back to a human key or a broader target.".into()}))
}
fn poisoned() -> SeError {
    refused("source broker state is unreadable")
}
