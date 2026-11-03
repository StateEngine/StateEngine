//! Linked operations use the same bounded readers, writer and completion observer.
use super::super::{BlockingClass, HostedRouter, executor, failure::WriteIdentity, submit};
use crate::client::lease::Deadline;
use se_core::{scope, store_error::store_error};
use se_store::{
    Admission, AtomicBatch, CommitReceipt, EventBody, EventHeader, InputText, NewEvent,
    PositionPurpose, ReadScope, Snapshot,
};
use se_types::{EventId, Result, SeError};
use secode_stateengine_api as api;
use sha2::{Digest, Sha256};

pub(super) async fn read<T: Send + 'static>(
    router: &HostedRouter,
    scope: ReadScope,
    deadline: &Deadline,
    work: impl FnOnce(&mut se_store::SqliteSnapshot) -> Result<T> + Send + 'static,
) -> Result<T> {
    router.check_open()?;
    let reader = router.execution.reader.clone();
    let generation = router.execution.generation;
    let fenced = router.fenced.clone();
    let bound = deadline.clone();
    router
        .execution
        .blocking
        .run(BlockingClass::Foreground, deadline, move || {
            bound.remaining()?;
            if fenced.load(std::sync::atomic::Ordering::Acquire) {
                return Err(SeError::invalid(
                    "linked read admission",
                    "a ready host before its drain fence",
                ));
            }
            let phase = executor::checked_phase(&reader, generation)?;
            let mut snapshot = phase.into_snapshot(scope).map_err(|e| store_error(&e))?;
            let result = work(&mut snapshot);
            executor::close_read(result, snapshot.close())
        })
        .await
}

pub(super) async fn write(
    router: &HostedRouter,
    batch: AtomicBatch,
    operation: &'static str,
    deadline: &Deadline,
) -> Result<CommitReceipt> {
    router.check_open()?;
    let identity = WriteIdentity {
        operation,
        natural_key: if batch.request.is_none() {
            Some(operation.into())
        } else {
            None
        },
        key: batch.request.as_ref().map(|r| r.key.clone()),
        natural_events: if batch.request.is_none() {
            batch
                .events
                .iter()
                .map(|e| e.header.event.clone())
                .collect()
        } else {
            Vec::new()
        },
    };
    submit::submit(&router.execution, batch, &identity, deadline).await
}

pub(super) fn event(
    read: &impl Snapshot,
    admission: &Admission,
    id: EventId,
    occurred_at_us: i64,
    body: EventBody<InputText>,
) -> NewEvent {
    NewEvent {
        header: EventHeader {
            event: id,
            scope: admission.scope.clone(),
            actor: admission.actor.clone(),
            session: admission.session.clone(),
            origin: read.info().id,
            door: se_store::Door::Host,
            occurred_at_us,
            cause: None,
            supersedes: None,
        },
        body,
    }
}

pub(super) fn request(
    operation: &'static str,
    key: api::IdempotencyKey,
    intent: serde_json::Value,
) -> Result<se_store::RequestIdentity> {
    use crate::linked::FromLinked;
    let bytes = serde_json::to_vec(&serde_json::json!({
        "operation": operation, "codec_version": 1, "arguments": intent
    }))
    .map_err(|e| scope::unreadable("linked intent", &e.to_string()))?;
    Ok(se_store::RequestIdentity {
        key: se_types::IdempotencyKey::from_linked(key)?,
        intent: se_store::IntentDigest {
            operation,
            codec_version: 1,
            sha256: Sha256::digest(bytes).into(),
        },
    })
}

pub(super) fn receipt<T>(
    read: &impl Snapshot,
    receipt: CommitReceipt,
    key: api::IdempotencyKey,
    value: T,
) -> Result<api::Receipt<T>> {
    use crate::linked::ToLinked;
    let event = api::EventRef {
        id: receipt.primary_event.to_linked(),
        position: read
            .position_cursor(&receipt.first, PositionPurpose::Receipt)
            .map_err(|e| store_error(&e))?
            .to_linked(),
    };
    if !receipt.events.contains(&receipt.primary_event) {
        return Err(SeError::invalid(
            "linked receipt",
            "its committed primary event",
        ));
    }
    let commit = api::Commit {
        event,
        idempotency_key: key,
        value,
        effects: api::EffectStatus::NotRequired,
    };
    Ok(match receipt.state {
        se_store::CommitState::Committed => api::Receipt::Committed { commit },
        se_store::CommitState::Replayed | se_store::CommitState::NaturalKeyReplay => {
            api::Receipt::Replayed { original: commit }
        }
    })
}

pub(super) fn known(operation: &str, receipt: &CommitReceipt) -> super::super::CommittedWrite {
    super::super::CommittedWrite {
        operation: operation.into(),
        key: receipt.request_key.clone(),
        natural_events: if receipt.request_key.is_none() {
            receipt.events.clone()
        } else {
            Vec::new()
        },
        committed_events: receipt.events.clone(),
    }
}
