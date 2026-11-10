//! Native owner control is separate from machine session authorization.
use super::{
    ClientConnectionId, CredentialSource,
    session::{SecurityStore, entropy, now},
};
use se_core::admission::{HumanTerminal, require_human_terminal};
use se_store::remote::GrantRecord;
use se_types::Result;
use se_types::remote::*;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
mod authorize;
mod fence;
mod handshake;
pub(crate) use fence::GrantFence;
pub use fence::{OutputFence, OutputInvalidation};

pub struct AuthenticatedDevice {
    connection: ClientConnectionId,
    grant: GrantRecord,
    fence: Arc<fence::GrantFence>,
}
impl AuthenticatedDevice {
    pub fn grant(&self) -> &GrantRecord {
        &self.grant
    }
    pub fn connection(&self) -> ClientConnectionId {
        self.connection
    }
}

pub struct AuthorizedRemoteRequest {
    pub(crate) admission: se_core::remote::RemoteAdmission,
    pub(crate) request: RemoteRequest,
    pub(crate) attribution: RemoteAttribution,
    pub(crate) fence: Arc<fence::GrantFence>,
}
impl AuthorizedRemoteRequest {
    pub fn request(&self) -> &RemoteRequest {
        &self.request
    }
    pub fn attribution(&self) -> &RemoteAttribution {
        &self.attribution
    }
    pub fn admission(&self) -> &se_core::remote::RemoteAdmission {
        &self.admission
    }
    pub fn into_parts(
        self,
    ) -> (
        se_core::remote::RemoteAdmission,
        RemoteRequest,
        RemoteAttribution,
        AdmissionPermit,
    ) {
        let principal = self.admission.grant().principal.clone();
        (
            self.admission,
            self.request,
            self.attribution,
            AdmissionPermit {
                principal,
                fence: self.fence,
            },
        )
    }
}
/// Consumed once by the nonblocking writer enqueue. Planning has already closed its read pin.
pub struct AdmissionPermit {
    principal: RemotePrincipalId,
    fence: Arc<fence::GrantFence>,
}
impl AdmissionPermit {
    pub fn submit(
        self,
        writer: &se_store::SqliteClient,
        batch: se_store::AtomicBatch,
    ) -> Result<<se_store::SqliteClient as se_store::WriterClient>::Completion> {
        self.submit_with(writer, batch, se_core::store_error::store_error)
    }
    pub(crate) fn submit_with(
        self,
        writer: &se_store::SqliteClient,
        batch: se_store::AtomicBatch,
        map_error: impl FnOnce(&se_store::StoreError) -> se_types::SeError,
    ) -> Result<<se_store::SqliteClient as se_store::WriterClient>::Completion> {
        use se_store::WriterClient;
        if batch.admission.actor != se_store::Actor::Remote(self.principal) {
            return Err(refused("remote admission principal differs"));
        }
        let _guard = self.fence.output()?;
        writer.submit(batch).map_err(|error| map_error(&error))
    }
}

struct PendingChannel {
    connection: ClientConnectionId,
    until: Instant,
    reply: tokio::sync::oneshot::Sender<Arc<AuthenticatedDevice>>,
}
struct CachedFence {
    fence: std::sync::Weak<fence::GrantFence>,
}
#[derive(Default)]
pub(crate) struct State {
    pub(crate) all_fenced: bool,
    pending: HashMap<[u8; 32], PendingChannel>,
    fences: HashMap<RemoteGrantId, CachedFence>,
    renewing: std::collections::HashSet<RemoteGrantId>,
}
pub struct Security {
    pub(crate) store: Arc<SecurityStore>,
    pub(crate) host: RemoteHostId,
    pub(crate) instance: RemoteInstanceId,
    pub(crate) generation: se_types::Generation,
    pub(crate) state: Mutex<State>,
    pub(crate) blocking: crate::runtime::BlockingPool,
}
impl Security {
    pub fn new(
        store: Arc<SecurityStore>,
        identity: &dyn CredentialSource,
        generation: se_types::Generation,
        blocking: crate::runtime::BlockingPool,
    ) -> Result<Self> {
        if generation.get() != store.generation {
            return Err(refused("remote host generation differs from writer"));
        }
        let host = RemoteHostId(se_types::Sha256::from_bytes(identity.credential_sha256()));
        Ok(Self {
            store,
            host,
            instance: RemoteInstanceId(entropy()?),
            generation,
            state: Mutex::new(State::default()),
            blocking,
        })
    }
    pub fn pending_channel(
        &self,
        connection: ClientConnectionId,
    ) -> Result<(
        [u8; 32],
        tokio::sync::oneshot::Receiver<Arc<AuthenticatedDevice>>,
    )> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("remote security state poisoned"))?;
        if state.all_fenced {
            return Err(refused("remote access is fenced"));
        }
        state
            .pending
            .retain(|_, pending| pending.until > Instant::now() && !pending.reply.is_closed());
        if state.pending.len() >= 8 {
            return Err(refused(
                "remote channel authorization is busy; retry after pending connections finish",
            ));
        }
        let channel = entropy()?;
        let (reply, receiver) = tokio::sync::oneshot::channel();
        if state.pending.contains_key(&channel) {
            return Err(refused("channel identity collision; retry connection"));
        }
        state.pending.insert(
            channel,
            PendingChannel {
                connection,
                until: Instant::now() + Duration::from_secs(10),
                reply,
            },
        );
        Ok((channel, receiver))
    }
    pub fn cancel_channel(&self, channel: [u8; 32]) -> Result<()> {
        self.state
            .lock()
            .map_err(|_| refused("remote security state poisoned"))?
            .pending
            .remove(&channel);
        Ok(())
    }
    pub async fn authorize_channel(
        &self,
        authorization: super::ssh::Authorization,
    ) -> Result<RemoteReady> {
        let pending = self
            .state
            .lock()
            .map_err(|_| refused("remote security state poisoned"))?
            .pending
            .remove(&authorization.channel)
            .ok_or_else(|| {
                refused("forwarded connection is absent; no credential was sent to its listener")
            })?;
        if pending.until <= Instant::now() || pending.reply.is_closed() {
            return Err(refused(
                "forwarded connection expired before SSH authorization",
            ));
        }
        let device = Arc::new(
            self.authenticate_session(
                pending.connection,
                authorization.hello,
                authorization.credential,
            )
            .await?,
        );
        let store = self.store.clone();
        let checked = device.clone();
        let instance = self.instance;
        let generation = self.generation;
        let ready = self
            .blocking
            .run_owned(&super::session::control::deadline()?, move || {
                let grant = store.grant(&checked.grant.grant)?;
                if grant.state != se_store::remote::GrantState::Active
                    || grant.expires_at_us <= now()?
                    || grant.authority_revision != checked.grant.authority_revision
                {
                    return Err(refused(
                        "machine authority changed during SSH authorization",
                    ));
                }
                Ok(RemoteReady {
                    protocol: se_types::ApiVersion {
                        major: CLIENT_PROTOCOL_MAJOR,
                        minor: CLIENT_PROTOCOL_MINOR,
                    },
                    host: grant.host,
                    instance,
                    generation,
                    grant: grant.grant,
                    authority_revision: grant.authority_revision.value.get(),
                    scope: grant.scope,
                    expires_at: se_types::UnixMicros::new(
                        u64::try_from(grant.expires_at_us)
                            .map_err(|_| refused("machine session expiry is invalid"))?,
                    )?,
                })
            })
            .await?;
        pending
            .reply
            .send(device)
            .map_err(|_| refused("forwarded connection closed during SSH authorization"))?;
        Ok(ready)
    }
    pub async fn authenticate_session(
        &self,
        connection: ClientConnectionId,
        hello: RemoteHello,
        credential: LinkSecret,
    ) -> Result<AuthenticatedDevice> {
        if hello.host != self.host
            || hello.protocol.major != CLIENT_PROTOCOL_MAJOR
            || hello.protocol.minor != CLIENT_PROTOCOL_MINOR
        {
            return Err(refused("machine session host or protocol differs"));
        }
        let store = self.store.clone();
        let host = self.host;
        let checked = self
            .blocking
            .run_owned(&super::session::control::deadline()?, move || {
                let grant = store.grant(&hello.grant)?;
                let expected: [u8; 32] = Sha256::digest(credential.expose()).into();
                use subtle::ConstantTimeEq;
                if !bool::from(expected.ct_eq(&grant.credential_sha256.0))
                    || grant.host != host
                    || grant.device != hello.device
                    || grant.authority_revision.value.get() != hello.authority_revision
                    || grant.state != se_store::remote::GrantState::Active
                    || grant.expires_at_us <= now()?
                    || !matches!(grant.subject, RemoteSubject::Machine { .. })
                {
                    return Err(refused("machine session refused"));
                }
                Ok(grant)
            })
            .await?;
        let fence = self.fence(&checked)?;
        drop(fence.output()?);
        Ok(AuthenticatedDevice {
            connection,
            grant: checked,
            fence,
        })
    }
    pub fn host(&self) -> RemoteHostId {
        self.host
    }
    pub fn instance(&self) -> RemoteInstanceId {
        self.instance
    }
    /// Transport calls after accepting its loopback connection. This ID
    /// is native host state; there is no wire constructor or deserializer.
    pub fn accepted_connection(&self) -> Result<ClientConnectionId> {
        Ok(ClientConnectionId::new(
            std::num::NonZeroU64::new(u64::from_le_bytes(entropy()?))
                .ok_or_else(|| refused("connection entropy absent"))?,
        ))
    }
    pub(crate) fn fence_all(&self) -> Result<Vec<Arc<fence::GrantFence>>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("remote security state poisoned"))?;
        state.all_fenced = true;
        state.pending.clear();
        Ok(state
            .fences
            .values()
            .filter_map(|entry| entry.fence.upgrade())
            .collect())
    }
    pub(crate) fn retire_fence(
        &self,
        grant: &RemoteGrantId,
        fence: &Arc<fence::GrantFence>,
    ) -> Result<()> {
        // Only a confirmed durable revoke with outside socket closure reaches here.
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("remote security state poisoned"))?;
        if state.fences.get(grant).is_some_and(|entry| {
            entry
                .fence
                .upgrade()
                .is_some_and(|current| Arc::ptr_eq(&current, fence))
        }) {
            state.fences.remove(grant);
        }
        Ok(())
    }
    pub(crate) fn fence(&self, g: &GrantRecord) -> Result<Arc<fence::GrantFence>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| refused("remote security state poisoned"))?;
        if state.all_fenced {
            return Err(refused(
                "all remote authority is fenced; restart the host after security rotation resolves",
            ));
        }
        state
            .fences
            .retain(|_, entry| entry.fence.strong_count() > 0);
        if let Some(fence) = state
            .fences
            .get(&g.grant)
            .and_then(|entry| entry.fence.upgrade())
        {
            return Ok(fence);
        }
        let fence = Arc::new(fence::GrantFence::new());
        state.fences.insert(
            g.grant.clone(),
            CachedFence {
                fence: Arc::downgrade(&fence),
            },
        );
        Ok(fence)
    }
}
pub(crate) fn refused(reason: &str) -> se_types::SeError {
    se_types::SeError::new(se_types::Detail::CapabilityInvalid(se_types::details::CapabilityInvalid {
        subject:"remote client authority".into(),reason:reason.into(),next_step:"Use the saved machine connection and current authorized source session. Revoked access requires explicit authorization through the machine owner.".into(),
    }))
}

/// Constructed by existing IPC/native presence admission, never decoded from wire.
#[derive(Clone)]
pub struct VerifiedLocalOwner {
    pub(crate) owner: se_types::HumanId,
    pub(crate) generation: u64,
    pub(crate) deadline: Instant,
}
impl VerifiedLocalOwner {
    pub fn from_native(admission: &se_store::Admission, terminal: &HumanTerminal) -> Result<Self> {
        require_human_terminal("remote authority control", admission, terminal)?;
        Self::from_machine(admission)
    }
    /// Only after native IPC has verified machine proof, owner and ancestry.
    pub fn from_machine(admission: &se_store::Admission) -> Result<Self> {
        if admission.session.is_some()
            || admission.scope != se_store::Scope::Registry
            || admission.generation == 0
        {
            return Err(se_core::scope::unreadable(
                "remote Owner admission",
                "a local session cannot issue remote authority",
            ));
        }
        let se_store::Actor::Human(owner) = &admission.actor else {
            return Err(refused("native human authority required"));
        };
        Ok(Self {
            owner: owner.clone(),
            generation: admission.generation,
            deadline: Instant::now() + Duration::from_secs(30),
        })
    }
}
