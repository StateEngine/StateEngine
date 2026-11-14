//! Native Owner capability over this exact host generation. No operation here
//! is registered in the agent tool catalogue or the ordinary HTTP dispatcher.
use super::coverage::ReceiverObservation;
use super::*;
use crate::{ExecutionContext, client::lease::Deadline};
use se_core::{commit::Cx, store_error::store_error};
use se_store::{
    Actor, Admission, AtomicBatch, CommitReceipt, Door, EventBody, EventHeader, IntentDigest,
    NewEvent, ReadStore, RequestIdentity, Scope, Snapshot, SqliteSnapshot,
};
use se_types::{HumanId, IdempotencyKey, ProjectId, Read, Result, Secret};
use sha2::{Digest, Sha256};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub struct Channels {
    pub(super) context: ExecutionContext,
    pub(super) configuration: Option<se_config::config_policy::ConfigFile>,
    pub(super) store: crate::runtime::store::Store,
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
    pub(crate) fn new(
        context: ExecutionContext,
        transports: Vec<Arc<dyn ChannelTransport>>,
        configuration: Option<se_config::config_policy::ConfigFile>,
        owner: HumanId,
        credentials: Arc<NativeChannelCredentials>,
        pairing_key: Secret,
        fenced: Arc<AtomicBool>,
    ) -> Result<Self> {
        let store_id = context
            .reader
            .info()
            .map_err(|error| store_error(&error))?
            .id;
        let store = crate::runtime::store::Store {
            record_feed: context.atlas.records.clone(),
            reader: context.reader.clone(),
            reads: context.reads.clone(),
            writer: context.writer.clone(),
            pool: context.blocking.clone(),
            generation: context.generation,
            pending: context.pending_writes.clone(),
            mail_waits: context.mail_waits.clone(),
            fault: context.ownership_fault.clone(),
        };
        Ok(Self {
            context,
            configuration,
            store,
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
    pub(super) fn transport(&self, connector: Connector) -> Result<Arc<dyn ChannelTransport>> {
        self.transports
            .iter()
            .find(|transport| transport.descriptor().connector == connector)
            .cloned()
            .ok_or_else(|| channel_error(ChannelError::Unsupported))
    }
    pub(super) async fn token(
        &self,
        reference: CredentialRef,
        deadline: &Deadline,
    ) -> Result<Secret> {
        let credentials = self.credentials.clone();
        self.context
            .blocking
            .run(crate::BlockingClass::Foreground, deadline, move || {
                credentials.resolve(&reference).map_err(channel_error)
            })
            .await
    }
    pub fn supports_resume(&self) -> bool {
        self.configuration.is_some() && self.context.custody.get().is_some()
    }
    pub async fn credential_catalog(&self, deadline: &Deadline) -> Result<CredentialCatalog> {
        self.admission(None)?;
        let credentials = self.credentials.clone();
        self.context
            .blocking
            .run(crate::BlockingClass::Foreground, deadline, move || {
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
            generation: self.context.generation.get(),
        })
    }
    pub(super) async fn read<T: Send + 'static>(
        &self,
        project: Option<ProjectId>,
        deadline: &Deadline,
        work: impl FnOnce(&mut Cx<'_, SqliteSnapshot>) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.store
            .read(self.admission(project)?, deadline, work)
            .await
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
        let identity = crate::runtime::WriteIdentity {
            operation: request.intent.operation,
            natural_key: None,
            key: Some(request.key.clone()),
            natural_events: vec![],
        };
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
        let receipt =
            crate::runtime::submit::submit(&self.context, batch, &identity, deadline).await?;
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
pub(super) fn event(
    cx: &Cx<'_, SqliteSnapshot>,
    body: EventBody<se_store::InputText>,
) -> Result<NewEvent> {
    let facts = crate::runtime::start::allocate_facts()?;
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
pub(super) fn now() -> Result<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|v| i64::try_from(v.as_micros()).ok())
        .ok_or_else(|| channel_error(ChannelError::InvalidInput))
}

pub(super) fn deadline(timeout: std::time::Duration) -> Result<Deadline> {
    Deadline::from_options(&crate::client::ClientOptions {
        expected_generation: None,
        timeout,
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}
