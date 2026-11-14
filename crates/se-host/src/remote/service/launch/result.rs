//! Preserve pending state and read back the accepted native reservation.
use super::*;
use se_core::store_error::store_error;
use se_store::{CommitReceipt, remote::LaunchAttribution};
pub(super) struct Completion {
    pub(super) input: RemoteLaunch,
    pub(super) attribution: RemoteAttribution,
    pub(super) admission: Admission,
    pub(super) native_key: se_types::IdempotencyKey,
    pub(super) replayed: bool,
}
pub(super) async fn finish(
    service: &Service,
    store: &crate::runtime::store::Store,
    completion: Completion,
    reply: LaunchReply,
    deadline: &crate::client::lease::Deadline,
) -> Result<RemoteLaunchResult> {
    let Completion {
        input,
        attribution,
        admission,
        native_key,
        replayed,
    } = completion;
    let launched_target = input.target.clone();
    let (outcome, attribution) = match reply {
        LaunchReply::Pending(value) => {
            let outcome = RemoteLaunchOutcome::Pending {
                launch: RemoteLaunchStarted {
                    target: input.target,
                    session: value.session_id,
                    lifecycle: value.lifecycle_id,
                },
                idempotency_key: input.idempotency_key,
                setup_needed: matches!(value.state, se_core::ops::LaunchPendingState::SetupNeeded),
            };
            (outcome, attribution)
        }
        LaunchReply::Running(value) => {
            return started(
                service,
                store,
                Completion {
                    input,
                    attribution,
                    admission,
                    native_key,
                    replayed,
                },
                RemoteLaunchStarted {
                    target: launched_target,
                    session: value.session_id,
                    lifecycle: value.lifecycle_id,
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

pub(super) async fn started(
    service: &Service,
    store: &crate::runtime::store::Store,
    completion: Completion,
    launch: RemoteLaunchStarted,
    event: se_types::EventId,
    deadline: &crate::client::lease::Deadline,
) -> Result<RemoteLaunchResult> {
    let Completion {
        input,
        attribution,
        admission,
        native_key,
        replayed,
    } = completion;
    let known = crate::runtime::CommittedWrite {
        operation: "remote.launch".into(),
        key: Some(input.idempotency_key.clone()),
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
        idempotency_key: input.idempotency_key,
        value: RemoteLaunchStarted {
            target: origin.target,
            session: origin.session,
            lifecycle: origin.lifecycle,
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
