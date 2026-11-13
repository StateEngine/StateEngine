//! Preserve pending state and read back the accepted native reservation.
use super::*;
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
            let known = crate::runtime::CommittedWrite {
                operation: "remote.launch".into(),
                key: Some(input.idempotency_key.clone()),
                natural_events: vec![],
                committed_events: vec![value.event_id.clone()],
            };
            let launched = RemoteLaunchStarted {
                target: input.target,
                session: value.session_id,
                lifecycle: value.lifecycle_id,
            };
            let (receipt, origin) = receipt::read_back(
                store,
                admission,
                native_key,
                launched,
                &attribution,
                deadline,
            )
            .await
            .map_err(|error| known.response_error(error))?;
            let position = receipt::seal(service, &receipt, &origin)
                .map_err(|error| known.response_error(error))?;
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
            (RemoteLaunchOutcome::Started { receipt }, origin.attribution)
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
