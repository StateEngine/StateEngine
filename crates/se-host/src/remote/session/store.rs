//! Adapter to the existing host writer, with fresh finite pins and await-only commits.
use se_core::{scope, store_error::store_error};
use se_remote::entropy;
use se_store::{
    Actor, Admission, AtomicBatch, EventBody, EventHeader, IntentDigest, NewEvent, ReadStore,
    RequestIdentity, Scope, SqliteClient, SqliteReader, StoreInfo, WriterClient, remote::*,
};
use se_types::{EventId, HumanId, IdempotencyKey, Read, Result, remote::*};
use sha2::{Digest, Sha256};

pub struct SecurityStore {
    pub(crate) reader: SqliteReader,
    reads: Option<se_store::ReadPhasePool>,
    pub(crate) writer: SqliteClient,
    pub(crate) info: StoreInfo,
    pub(crate) generation: u64,
    pub(crate) owner: HumanId,
    owner_fault: Option<std::sync::Arc<crate::runtime::tasks::OwnershipFault>>,
}
impl SecurityStore {
    pub fn new(
        reader: SqliteReader,
        writer: SqliteClient,
        generation: u64,
        owner: HumanId,
    ) -> Result<Self> {
        let info = reader.info().map_err(|e| store_error(&e))?;
        if generation == 0 || info.schema_version < 7 || info.state != se_store::StoreState::Ready {
            return Err(scope::unreadable(
                "remote security store",
                "a ready migrated host writer is required",
            ));
        }
        Ok(Self {
            reader,
            reads: None,
            writer,
            info,
            generation,
            owner,
            owner_fault: None,
        })
    }
    pub(crate) fn with_reads(mut self, reads: se_store::ReadPhasePool) -> Self {
        self.reads = Some(reads);
        self
    }
    pub(crate) fn with_owner_fault(
        mut self,
        fault: std::sync::Arc<crate::runtime::tasks::OwnershipFault>,
    ) -> Self {
        self.owner_fault = Some(fault);
        self
    }
    pub(crate) fn read<T>(
        &self,
        call: impl FnOnce(&mut se_store::ReadPhase) -> se_store::StoreResult<T>,
    ) -> Result<T> {
        let mut phase = match &self.reads {
            Some(reads) => reads.read_phase(),
            None => self.reader.read_phase(),
        }
        .map_err(|e| store_error(&e))?;
        let result = phase
            .remote_store_binding(&self.info, self.generation)
            .and_then(|()| call(&mut phase))
            .map_err(|e| store_error(&e));
        match (result, phase.close()) {
            (result, Ok(())) => result,
            (Ok(_), Err(error)) => Err(store_error(&error)),
            (Err(original), Err(error)) => Err(original.with_cause(error)),
        }
    }
    pub(crate) fn grant(&self, id: &RemoteGrantId) -> Result<GrantRecord> {
        match self.read(|phase| phase.remote_grant(id))? {
            Read::Present { value } if value.store == self.info.id => Ok(value),
            _ => Err(scope::unreadable(
                "remote grant",
                "machine authority refused; reconnect through SSH or restore the original host binding",
            )),
        }
    }
    pub(crate) fn grants(
        &self,
        after: Option<&RemoteGrantId>,
        limit: usize,
    ) -> Result<(Vec<GrantRecord>, bool)> {
        self.read(|phase| phase.remote_grants(after, limit))
    }
    pub(crate) async fn commit(
        &self,
        actor: Actor,
        key: IdempotencyKey,
        transition: SecurityTransition,
        intent: serde_json::Value,
    ) -> Result<se_store::CommitReceipt> {
        let now = now()?;
        let event = event_id(now)?;
        let bytes = serde_json::to_vec(&intent)
            .map_err(|e| scope::unreadable("remote security intent", &e.to_string()))?;
        let operation = match &transition {
            SecurityTransition::Connect { .. } => "remote.machine.connect",
            SecurityTransition::Renew { .. } => "remote.lease.renew",
            SecurityTransition::Revoke { .. } => "remote.grant.revoke",
            SecurityTransition::RevokeAll => "remote.grants.revoke-all",
            SecurityTransition::LaunchPermission { .. } => "remote.launch.permission",
        };
        let original_key = key.clone();
        let batch = AtomicBatch {
            expected_incarnation: self.info.incarnation,
            admission: Admission {
                scope: Scope::Registry,
                actor: actor.clone(),
                session: None,
                generation: self.generation,
            },
            request: Some(RequestIdentity {
                key,
                intent: IntentDigest {
                    operation,
                    codec_version: 1,
                    sha256: Sha256::digest(bytes).into(),
                },
            }),
            events: vec![NewEvent {
                header: EventHeader {
                    event,
                    scope: Scope::Registry,
                    actor,
                    session: None,
                    origin: self.info.id.clone(),
                    door: se_store::Door::Host,
                    occurred_at_us: now,
                    cause: None,
                    supersedes: None,
                },
                body: EventBody::RemoteSecurity { transition },
            }],
            import_checkpoint: None,
        };
        let fault = self.owner_fault.clone();
        let completion = self.writer.submit(batch).map_err(|error| {
            if let Some(fault) = &fault {
                fault.observe_writer(&error);
            }
            se_core::store_error::write_error(&error, operation, Some(&original_key), &[])
        })?;
        // The accepted writer transaction outlives an interrupted socket/Owner
        // waiter. Observe ownership loss even when nobody remains to await it.
        let completion = tokio::spawn(async move {
            let result = completion.await;
            if let Err(error) = &result
                && let Some(fault) = fault
            {
                fault.observe_writer(error);
            }
            result
        });
        let identity = crate::runtime::WriteIdentity {
            operation,
            key: Some(original_key.clone()),
            natural_key: None,
            natural_events: vec![],
        };
        completion
            .await
            .map_err(|error| {
                identity.wait_error(scope::unreadable(
                    "remote security completion",
                    &error.to_string(),
                ))
            })?
            .map_err(|error| identity.store_error(&error))
    }
}
pub(crate) fn now() -> Result<i64> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| scope::unreadable("remote host clock", &e.to_string()))?
        .as_micros();
    i64::try_from(micros).map_err(|e| scope::unreadable("remote host clock", &e.to_string()))
}
pub(crate) fn event_id(now: i64) -> Result<EventId> {
    EventId::from_parts(
        u64::try_from(now / 1000)
            .map_err(|_| scope::unreadable("remote clock", "negative timestamp"))?,
        entropy()?,
    )
}
