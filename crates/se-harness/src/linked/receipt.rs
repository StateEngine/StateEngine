use super::{ToLinked, error_body};
use se_types as core;
use secode_stateengine_api as api;

pub fn event_ref(value: core::EventRef) -> api::EventRef {
    api::EventRef {
        id: value.id.to_linked(),
        position: value.position.to_linked(),
    }
}
fn commit<T, U>(
    value: core::Commit<T>,
    context: &core::RenderCx<'_>,
    map: impl FnOnce(T) -> core::Result<U>,
) -> core::Result<api::Commit<U>> {
    let effects = match value.effects {
        core::EffectStatus::NotRequired => api::EffectStatus::NotRequired,
        core::EffectStatus::Pending => api::EffectStatus::Pending,
        core::EffectStatus::Witnessed { witness } => api::EffectStatus::Witnessed {
            witness: event_ref(witness),
        },
        core::EffectStatus::Failed { error } => api::EffectStatus::Failed {
            error: error_body(&error, context)?,
        },
    };
    Ok(api::Commit {
        event: api::EventRef {
            id: value.event_id.to_linked(),
            position: value.position.to_linked(),
        },
        idempotency_key: value.idempotency_key.to_linked(),
        value: map(value.value)?,
        effects,
    })
}
pub fn receipt<T, U>(
    value: core::Receipt<T>,
    context: &core::RenderCx<'_>,
    map: impl FnOnce(T) -> core::Result<U>,
) -> core::Result<api::Receipt<U>> {
    Ok(match value {
        core::Receipt::Committed { commit: value } => api::Receipt::Committed {
            commit: commit(value, context, map)?,
        },
        core::Receipt::Replayed { original } => api::Receipt::Replayed {
            original: commit(original, context, map)?,
        },
        core::Receipt::Refused { error } => api::Receipt::Refused {
            error: error_body(&error, context)?,
        },
        core::Receipt::Pending {
            cause,
            event_id,
            idempotency_key,
        } => api::Receipt::Pending {
            cause: match cause {
                core::PendingReason::Queued => api::PendingReason::Queued,
                core::PendingReason::AwaitingWitness => api::PendingReason::AwaitingWitness,
                core::PendingReason::Recovering => api::PendingReason::Recovering,
            },
            event_id: event_id.as_ref().map(ToLinked::to_linked),
            idempotency_key: idempotency_key.to_linked(),
        },
    })
}
