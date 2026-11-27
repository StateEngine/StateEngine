//! Preserve pending state and read back the accepted native reservation.
use super::*;
use se_core::store_error::store_error;
use se_store::{CommitReceipt, remote::LaunchAttribution};
/// A started agent's receipt: the launched target and the caller's original key.
pub(in crate::remote::service) struct Completion {
    pub(in crate::remote::service) target: RemoteTarget,
    pub(in crate::remote::service) key: se_types::IdempotencyKey,
    pub(in crate::remote::service) operation: &'static str,
    pub(in crate::remote::service) attribution: RemoteAttribution,
    pub(in crate::remote::service) admission: Admission,
    pub(in crate::remote::service) native_key: se_types::IdempotencyKey,
    pub(in crate::remote::service) replayed: bool,
}
pub(in crate::remote::service) async fn finish(
    service: &Service,
    store: &crate::runtime::store::Store,
    completion: Completion,
    reply: LaunchReply,
    deadline: &crate::client::lease::Deadline,
) -> Result<RemoteLaunchResult> {
    let (outcome, attribution) = match reply {
        LaunchReply::Pending(value) => {
            let outcome = RemoteLaunchOutcome::Pending {
                launch: RemoteLaunchStarted {
                    target: completion.target,
                    session: value.session_id,
                    lifecycle: value.lifecycle_id,
                    details: None,
                },
                idempotency_key: completion.key,
                setup_needed: matches!(value.state, se_core::ops::LaunchPendingState::SetupNeeded),
            };
            (outcome, completion.attribution)
        }
        LaunchReply::Running(value) => {
            let target = completion.target.clone();
            return started(
                service,
                store,
                completion,
                RemoteLaunchStarted {
                    target,
                    session: value.session_id,
                    lifecycle: value.lifecycle_id,
                    details: None,
                },
                value.event_id,
                deadline,
            )
            .await;
        }
    };
    Ok(RemoteLaunchResult {
        schema: RemoteLaunchResult::SCHEMA.into(),
        body: RemoteLaunchBody {
            outcome,
            attribution,
        },
    })
}

pub(in crate::remote::service) async fn started(
    service: &Service,
    store: &crate::runtime::store::Store,
    completion: Completion,
    launch: RemoteLaunchStarted,
    event: se_types::EventId,
    deadline: &crate::client::lease::Deadline,
) -> Result<RemoteLaunchResult> {
    let Completion {
        key,
        operation,
        attribution,
        admission,
        native_key,
        replayed,
        ..
    } = completion;
    let known = crate::runtime::CommittedWrite {
        operation: operation.into(),
        key: Some(key.clone()),
        natural_events: vec![],
        committed_events: vec![event],
    };
    let expected = attribution.clone();
    let (receipt, origin) = store
        .read(admission, deadline, move |cx| {
            se_core::remote::read_launch_receipt(cx, native_key, launch, &expected)
        })
        .await
        .map_err(|error| known.response_error(error))?;
    let position = seal(service, &receipt, &origin).map_err(|error| known.response_error(error))?;
    let replayed = replayed || origin.attribution.source != attribution.source;
    let commit = se_types::Commit {
        event_id: receipt.primary_event,
        position,
        idempotency_key: key,
        value: RemoteLaunchStarted {
            target: origin.target,
            session: origin.session,
            lifecycle: origin.lifecycle,
            details: origin.details,
        },
        effects: se_types::EffectStatus::NotRequired,
    };
    let receipt = if replayed {
        se_types::Receipt::Replayed { original: commit }
    } else {
        se_types::Receipt::Committed { commit }
    };
    Ok(RemoteLaunchResult {
        schema: RemoteLaunchResult::SCHEMA.into(),
        body: RemoteLaunchBody {
            outcome: RemoteLaunchOutcome::Started { receipt },
            attribution: origin.attribution,
        },
    })
}

fn seal(
    service: &Service,
    receipt: &CommitReceipt,
    origin: &LaunchAttribution,
) -> Result<se_types::Cursor> {
    let associated = serde_json::to_vec(&serde_json::json!({
        "schema":"stateengine.remote-launch-receipt/v1",
        "store":origin.attribution.store,
        "grant":origin.attribution.grant,
        "source":origin.attribution.source.as_ref().map(|s|s.address()),
        "target":origin.target,
        "session":origin.session,
        "lifecycle":origin.lifecycle,
    }))
    .map_err(|_| SeError::invalid("remote launch receipt", "encodable exact origin"))?;
    let position =
        se_store::remote::position_payload(&receipt.first).map_err(|e| store_error(&e))?;
    service.cursors.sealed_receipt(&position, &associated)
}
