//! Native Owner capability over this exact host generation. No operation here
//! is registered in the agent tool catalogue or the ordinary HTTP dispatcher.
use super::coverage::ReceiverObservation;
use super::*;
use crate::host::{AsChannelDeadline, ChannelDeadline as Deadline, ChannelHost};
use se_core::{commit::Cx, store_error::store_error};
use se_store::{
    Actor, Admission, AtomicBatch, CommitReceipt, Door, EventBody, EventHeader, IntentDigest,
    NewEvent, RequestIdentity, Scope, Snapshot, SqliteSnapshot,
};
use se_types::{HumanId, IdempotencyKey, ProjectId, Read, Result, Secret};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// The channel receiver's periodic cycles: how often the loop rescans for
/// committed connections, and how often a worker polls its transport. The
/// production defaults live here; the in-process test hook shortens them
/// without adding a user-visible configuration surface.
#[derive(Clone, Copy)]
pub struct ReceiverIntervals {
    pub rescan: std::time::Duration,
    pub poll: std::time::Duration,
}
impl Default for ReceiverIntervals {
    fn default() -> Self {
        Self {
            rescan: std::time::Duration::from_secs(5),
            poll: std::time::Duration::from_secs(1),
        }
    }
}
pub struct Channels {
    pub(super) host: Arc<dyn ChannelHost>,
    pub(super) configuration: Option<se_config::config_policy::ConfigFile>,
    pub(super) owner: HumanId,
    pub(super) store_id: se_types::StoreId,
    pub(super) credentials: Arc<NativeChannelCredentials>,
    pub(super) pairing_key: Arc<Secret>,
    pub(crate) transports: Vec<Arc<dyn ChannelTransport>>,
    pub(super) fenced: Arc<AtomicBool>,
    pub(super) changed: tokio::sync::Notify,
    pub(super) output_gates: std::sync::Mutex<
        std::collections::HashMap<ChannelId, std::sync::Weak<tokio::sync::Mutex<()>>>,
    >,
    pub(super) health_version: std::sync::atomic::AtomicU64,
    pub(super) receiver_running: AtomicBool,
    pub(super) health: std::sync::Mutex<std::collections::HashMap<ChannelId, ReceiverObservation>>,
}
impl Channels {
    pub fn new(
        host: Arc<dyn ChannelHost>,
        transports: Vec<Arc<dyn ChannelTransport>>,
        configuration: Option<se_config::config_policy::ConfigFile>,
        owner: HumanId,
        credentials: Arc<NativeChannelCredentials>,
        pairing_key: Secret,
        fenced: Arc<AtomicBool>,
    ) -> Result<Self> {
        let store_id = host.store_id();
        Ok(Self {
            host,
            configuration,
            owner,
            store_id,
            credentials,
            pairing_key: Arc::new(pairing_key),
            transports,
            fenced,
            changed: tokio::sync::Notify::new(),
            output_gates: std::sync::Mutex::default(),
            health: std::sync::Mutex::default(),
            health_version: std::sync::atomic::AtomicU64::new(0),
            receiver_running: AtomicBool::new(false),
        })
    }
    pub fn changed(&self) -> &tokio::sync::Notify {
        &self.changed
    }
    pub(super) fn transport(&self, connector: Connector) -> Result<Arc<dyn ChannelTransport>> {
        self.transports
            .iter()
            .find(|transport| transport.descriptor().connector == connector)
            .cloned()
            .ok_or_else(|| channel_error(ChannelError::Unsupported))
    }
    pub(super) async fn blocking<T: Send + 'static>(
        &self,
        owned: bool,
        deadline: &Deadline,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let value = self
            .host
            .run_blocking(
                owned,
                deadline,
                Box::new(move || Ok(Box::new(work()?) as Box<dyn std::any::Any + Send>)),
            )
            .await?;
        value
            .downcast::<T>()
            .map(|boxed| *boxed)
            .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))
    }
    pub(super) async fn token(
        &self,
        reference: CredentialRef,
        deadline: &Deadline,
    ) -> Result<Secret> {
        let credentials = self.credentials.clone();
        self.blocking(false, deadline, move || {
            credentials.resolve(&reference).map_err(channel_error)
        })
        .await
    }
    pub fn supports_resume(&self) -> bool {
        self.configuration.is_some() && self.host.has_custody()
    }
    pub async fn credential_catalog(
        &self,
        deadline: &impl AsChannelDeadline,
    ) -> Result<CredentialCatalog> {
        let deadline = &deadline.as_channel_deadline();
        self.admission(None)?;
        let credentials = self.credentials.clone();
        self.blocking(false, deadline, move || {
            credentials.catalog().map_err(channel_error)
        })
        .await
    }
    pub(super) fn output_gate(&self, id: &ChannelId) -> Result<Arc<tokio::sync::Mutex<()>>> {
        let mut gates = self
            .output_gates
            .lock()
            .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))?;
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(id).and_then(std::sync::Weak::upgrade) {
            return Ok(gate);
        }
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        gates.insert(id.clone(), Arc::downgrade(&gate));
        Ok(gate)
    }
    pub(super) fn unavailable(&self, id: ChannelId, code: &str) -> Result<()> {
        self.set_health(id, ConnectionHealth::Unavailable { code: code.into() })
    }
    pub(super) fn set_health(&self, id: ChannelId, health: ConnectionHealth) -> Result<()> {
        let at = now()?;
        let mut observations = self
            .health
            .lock()
            .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))?;
        observations
            .entry(id)
            .or_insert_with(|| ReceiverObservation {
                health: ConnectionHealth::Unavailable {
                    code: "receiver_starting".into(),
                },
                coverage: ReceiveCoverage::unobserved(at),
            })
            .observe(health, at);
        self.health_version.fetch_add(1, Ordering::AcqRel);
        drop(observations);
        self.changed.notify_waiters();
        Ok(())
    }
    pub(super) fn admission(&self, project: Option<ProjectId>) -> Result<Admission> {
        if self.fenced.load(Ordering::Acquire) {
            return Err(channel_error(ChannelError::ReceiverNotRunning));
        }
        Ok(Admission {
            scope: project.map(Scope::Project).unwrap_or(Scope::Registry),
            actor: Actor::Human(self.owner.clone()),
            session: None,
            generation: self.host.generation().get(),
        })
    }
    pub(super) async fn read<T: Send + 'static>(
        &self,
        project: Option<ProjectId>,
        deadline: &Deadline,
        work: impl FnOnce(&mut Cx<'_, SqliteSnapshot>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let value = self
            .host
            .read_snapshot(
                self.admission(project)?,
                deadline,
                Box::new(move |cx| Ok(Box::new(work(cx)?) as Box<dyn std::any::Any + Send>)),
            )
            .await?;
        value
            .downcast::<T>()
            .map(|boxed| *boxed)
            .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))
    }
    pub(super) async fn connection(
        &self,
        id: ChannelId,
        deadline: &Deadline,
    ) -> Result<se_store::channel::Connection> {
        self.read(None, deadline, move |cx| {
            se_core::scope::require_present(
                cx.read
                    .channel_connection(&id)
                    .map_err(|e| store_error(&e))?,
                "channel",
                "Inspect the Owner's saved channel list.",
            )
        })
        .await
    }
    pub(super) async fn replay(
        &self,
        project: ProjectId,
        request: RequestIdentity,
        deadline: &Deadline,
    ) -> Result<Option<CommitReceipt>> {
        self.read(Some(project), deadline, move |cx| {
            match cx
                .read
                .resolve_request(&request)
                .map_err(|e| store_error(&e))?
            {
                Read::Present { value } => Ok(Some(value)),
                Read::Absent { .. } => Ok(None),
                other => se_core::scope::require_present(
                    other,
                    "channel request",
                    "Resolve the original key after restoring store access.",
                )
                .map(Some),
            }
        })
        .await
    }
    pub(super) async fn change(
        &self,
        project: ProjectId,
        request: RequestIdentity,
        change: se_store::channel::Change,
        deadline: &Deadline,
    ) -> Result<CommitReceipt> {
        self.commit(project, request, deadline, move |cx| {
            Ok(vec![event(cx, EventBody::ChannelRecorded { change })?])
        })
        .await
    }
    pub(super) async fn commit(
        &self,
        project: ProjectId,
        request: RequestIdentity,
        deadline: &Deadline,
        plan: impl FnOnce(&mut Cx<'_, SqliteSnapshot>) -> Result<Vec<NewEvent>> + Send + 'static,
    ) -> Result<CommitReceipt> {
        let operation = request.intent.operation;
        let key = request.key.clone();
        let batch = self
            .read(Some(project), deadline, move |cx| {
                Ok(AtomicBatch {
                    expected_incarnation: cx.read.info().incarnation,
                    admission: cx.admission.clone(),
                    request: Some(request),
                    events: plan(cx)?,
                    import_checkpoint: None,
                })
            })
            .await?;
        let receipt = self
            .host
            .submit_batch(batch, operation, key, deadline)
            .await?;
        self.changed.notify_waiters();
        Ok(receipt)
    }
    pub(super) async fn committed_change(
        &self,
        project: ProjectId,
        receipt: &CommitReceipt,
        deadline: &Deadline,
    ) -> Result<se_store::channel::Change> {
        let events = receipt.events.clone();
        self.read(Some(project), deadline, move |cx| {
            for id in events {
                let row = se_core::scope::require_present(
                    cx.read.event(id).map_err(|e| store_error(&e))?,
                    "channel commit",
                    "Resolve the original committed event.",
                )?;
                if let EventBody::ChannelRecorded { change } = row.body {
                    return Ok(change);
                }
            }
            Err(channel_error(ChannelError::IdempotencyConflict))
        })
        .await
    }
}
pub(super) fn intent(
    operation: &'static str,
    key: impl Into<Option<IdempotencyKey>>,
    value: &impl serde::Serialize,
) -> Result<RequestIdentity> {
    let bytes = serde_json::to_vec(value).map_err(|_| channel_error(ChannelError::InvalidInput))?;
    let sha256: [u8; 32] = Sha256::digest(bytes).into();
    let key = match key.into() {
        Some(key) => key,
        None => IdempotencyKey::new(se_types::hex_lower(&sha256))
            .map_err(|_| channel_error(ChannelError::InvalidInput))?,
    };
    Ok(RequestIdentity {
        key,
        intent: IntentDigest {
            operation,
            codec_version: 1,
            sha256,
        },
    })
}
pub(super) fn allocate_facts() -> Result<se_core::dispatch::CallFacts> {
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| se_core::scope::unreadable("system clock", &e.to_string()))?;
    let mut random = [0; 60];
    se_proc::fill_entropy(&mut random)
        .map_err(|e| se_core::scope::unreadable("host identity entropy", &e.to_string()))?;
    let mut event = [0; 10];
    event.copy_from_slice(&random[..10]);
    let mut message = [0; 10];
    message.copy_from_slice(&random[10..20]);
    let mut agent = [0; 10];
    agent.copy_from_slice(&random[20..30]);
    let mut profile_event = [0; 10];
    profile_event.copy_from_slice(&random[30..40]);
    let mut notification_event = [0; 10];
    notification_event.copy_from_slice(&random[40..50]);
    let mut notification_message = [0; 10];
    notification_message.copy_from_slice(&random[50..60]);
    Ok(se_core::dispatch::CallFacts {
        event: se_types::EventId::from_parts(time.as_millis() as u64, event)?,
        message: se_types::MessageId::from_parts(time.as_millis() as u64, message)?,
        agent: se_types::AgentId::from_parts(time.as_millis() as u64, agent)?,
        profile_event: se_types::EventId::from_parts(time.as_millis() as u64, profile_event)?,
        notification_event: se_types::EventId::from_parts(
            time.as_millis() as u64,
            notification_event,
        )?,
        notification_message: se_types::MessageId::from_parts(
            time.as_millis() as u64,
            notification_message,
        )?,
        occurred_at_us: i64::try_from(time.as_micros())
            .map_err(|_| se_core::scope::unreadable("system clock", "timestamp exceeds i64"))?,
        door: se_store::Door::Host,
    })
}
pub(super) fn event(
    cx: &Cx<'_, SqliteSnapshot>,
    body: EventBody<se_store::InputText>,
) -> Result<NewEvent> {
    let facts = allocate_facts()?;
    Ok(NewEvent {
        header: EventHeader {
            event: facts.event,
            scope: cx.admission.scope.clone(),
            actor: cx.admission.actor.clone(),
            session: None,
            origin: cx.read.info().id,
            door: Door::Host,
            occurred_at_us: facts.occurred_at_us,
            cause: None,
            supersedes: None,
        },
        body,
    })
}
pub(super) fn channel_error(error: ChannelError) -> se_types::SeError {
    error.refusal()
}
/// Same cause-preserving custody failure, as a host refusal.
pub(super) fn store_unavailable(cause: impl std::fmt::Display) -> se_types::SeError {
    channel_error(super::error::credential_store_unavailable(cause))
}
pub(super) fn now() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_micros()).ok())
        .ok_or_else(|| channel_error(ChannelError::InvalidInput))
}

pub(super) fn deadline(timeout: std::time::Duration) -> Result<Deadline> {
    Deadline::from_timeout(timeout)
}
