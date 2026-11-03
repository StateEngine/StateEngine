//! A targeted governing read supplies the exact ratified proposal; no generic
//! decision/history read or widened visibility is used to recover private rows.
use super::types::GoverningDecision;
use crate::{ops::receipt, scope};
use se_store::{EventBody, ProjectionRecord, Scope, StoredText};
use se_types::Result;

pub(super) fn decode(record: ProjectionRecord, admitted: &Scope) -> Result<GoverningDecision> {
    let first = record.original.as_deref().ok_or_else(|| {
        scope::unreadable(
            "governing decision",
            "the targeted current-ratified read did not retain its exact proposal",
        )
    })?;
    let (
        EventBody::DecisionProposed {
            decision,
            key,
            statement,
            ..
        },
        EventBody::DecisionRatified {
            decision: active, ..
        },
    ) = (&first.body, &record.current.body)
    else {
        return Err(scope::unreadable(
            "governing decision",
            "proposal or current ratification has another kind",
        ));
    };
    if decision != active
        || &first.header.scope != admitted
        || &record.current.header.scope != admitted
    {
        return Err(scope::unreadable(
            "governing decision",
            "proposal/head identity or project differs",
        ));
    }
    let StoredText::Present(text) = statement else {
        return Err(scope::unreadable(
            "governing decision",
            "a governing statement was erased; it was not replaced by empty text",
        ));
    };
    Ok(GoverningDecision {
        id: decision.clone(),
        key: key.clone(),
        statement: text.clone(),
        ratified_at: receipt::timestamp(record.current.recorded_at_us)?,
    })
}
