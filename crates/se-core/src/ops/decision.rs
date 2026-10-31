//! Synchronous decision batches; approval authority is a native admission fact,
//! never a typed decision ID or a field in the operation input.
use super::{administration::*, inputs::Validate};
use crate::{
    admission::{HumanTerminal, require_human_terminal},
    commit::Cx,
    dispatch::{Kernel, admitted},
    scope,
    store_error::store_error,
};
use se_store::{AtomicBatch, DecisionKind, EventBody, Expected, InputText, Revision, Snapshot};
use se_types::{DecisionId, IdempotencyKey, Result, SeError};
use std::num::NonZeroU64;

/// Owned continuation facts only; receipt construction must read the actual
/// immutable event and its proposal in a fresh admitted Snapshot.
pub struct DecisionThen {
    pub(crate) request: IdempotencyKey,
    pub(crate) action: &'static str,
}
impl DecisionThen {
    pub fn request(&self) -> &IdempotencyKey {
        &self.request
    }
    pub fn action(&self) -> &'static str {
        self.action
    }
}
fn intent<T: serde::Serialize>(input: &T) -> Result<serde_json::Value> {
    serde_json::to_value(input)
        .map_err(|error| scope::unreadable("decision intent", &error.to_string()))
}
fn expected<R: Snapshot>(
    id: &DecisionId,
    want: Option<u64>,
    cx: &mut Cx<'_, R>,
) -> Result<Revision> {
    let record = scope::require_present(
        cx.read.decision(id.clone()).map_err(|e| store_error(&e))?,
        &id.to_string(),
    )?;
    if record.current.header.scope != cx.admission.scope {
        return Err(scope::unreadable(
            "decision",
            "snapshot returned another scope",
        ));
    }
    let value = NonZeroU64::new(want.unwrap_or(record.revision.value.get()))
        .ok_or_else(|| SeError::invalid("expect", "positive entity revision"))?;
    Ok(Revision { value })
}
fn batch<R: Snapshot>(
    kernel: &Kernel,
    name: &'static str,
    action: &'static str,
    key: IdempotencyKey,
    normalized: serde_json::Value,
    body: EventBody<InputText>,
    cx: &Cx<'_, R>,
) -> Result<(AtomicBatch, DecisionThen)> {
    let event = kernel.event(body, cx)?;
    Ok((
        kernel.batch(name, key.clone(), normalized, event, cx)?,
        DecisionThen {
            request: key,
            action,
        },
    ))
}
pub fn propose<R: Snapshot>(
    kernel: &Kernel,
    input: DecisionPropose,
    cx: &mut Cx<'_, R>,
) -> Result<(AtomicBatch, DecisionThen)> {
    input.validate()?;
    admitted(cx)?;
    let normalized = intent(&input)?;
    // CallFacts.message is the adapter's unused second fresh UUID allocation on
    // this operation. Re-kind those bytes instead of introducing RNG in core.
    let bytes = kernel.facts()?.message.canonical_bytes()?.ok_or_else(|| {
        SeError::invalid("decision allocation", "fresh canonical UUIDv7 call facts")
    })?;
    let body = EventBody::DecisionProposed {
        decision: DecisionId::from_bytes(bytes)?,
        key: input.key,
        statement: InputText::Inline(input.statement),
        rationale: input.rationale.map(InputText::Inline),
        prior: input.supersedes,
        kind: DecisionKind::Decision,
    };
    batch(
        kernel,
        "decision.propose",
        "propose",
        input.idempotency_key,
        normalized,
        body,
        cx,
    )
}
pub fn ratify<R: Snapshot>(
    kernel: &Kernel,
    input: DecisionRatify,
    cx: &mut Cx<'_, R>,
    terminal: &HumanTerminal,
) -> Result<(AtomicBatch, DecisionThen)> {
    input.validate()?;
    admitted(cx)?;
    require_human_terminal("decision.ratify", cx.admission, terminal)?;
    let normalized = intent(&input)?;
    let expected = Expected::Revision(expected(&input.decision_id, input.expect, cx)?);
    let body = EventBody::DecisionRatified {
        decision: input.decision_id,
        expected,
        // The ratification event itself records this admitted human action.
        approval: kernel.facts()?.event.clone(),
    };
    batch(
        kernel,
        "decision.ratify",
        "ratify",
        input.idempotency_key,
        normalized,
        body,
        cx,
    )
}
pub fn reject<R: Snapshot>(
    kernel: &Kernel,
    input: DecisionReject,
    cx: &mut Cx<'_, R>,
    terminal: &HumanTerminal,
) -> Result<(AtomicBatch, DecisionThen)> {
    input.validate()?;
    admitted(cx)?;
    require_human_terminal("decision.reject", cx.admission, terminal)?;
    let normalized = intent(&input)?;
    let expected = Expected::Revision(expected(&input.decision_id, input.expect, cx)?);
    let body = EventBody::DecisionRejected {
        decision: input.decision_id,
        expected,
        reason: InputText::Inline(input.reason),
    };
    batch(
        kernel,
        "decision.reject",
        "reject",
        input.idempotency_key,
        normalized,
        body,
        cx,
    )
}
pub fn retract<R: Snapshot>(
    kernel: &Kernel,
    input: DecisionRetract,
    cx: &mut Cx<'_, R>,
    terminal: &HumanTerminal,
) -> Result<(AtomicBatch, DecisionThen)> {
    input.validate()?;
    admitted(cx)?;
    require_human_terminal("decision.retract", cx.admission, terminal)?;
    let normalized = intent(&input)?;
    let expected = Expected::Revision(expected(&input.decision_id, input.expect, cx)?);
    let body = EventBody::DecisionRetracted {
        decision: input.decision_id,
        expected,
        reason: InputText::Inline(input.reason),
    };
    batch(
        kernel,
        "decision.retract",
        "retract",
        input.idempotency_key,
        normalized,
        body,
        cx,
    )
}
pub fn supersede<R: Snapshot>(
    kernel: &Kernel,
    input: DecisionSupersede,
    cx: &mut Cx<'_, R>,
    terminal: &HumanTerminal,
) -> Result<(AtomicBatch, DecisionThen)> {
    input.validate()?;
    admitted(cx)?;
    require_human_terminal("decision.supersede", cx.admission, terminal)?;
    let normalized = intent(&input)?;
    let prior_expected = expected(&input.decision_id, input.expect, cx)?;
    let replacement_expected = expected(&input.replacement_id, input.replacement_expect, cx)?;
    let body = EventBody::DecisionSuperseded {
        prior: input.decision_id,
        replacement: input.replacement_id,
        prior_expected,
        replacement_expected,
        approval: kernel.facts()?.event.clone(),
    };
    batch(
        kernel,
        "decision.supersede",
        "supersede",
        input.idempotency_key,
        normalized,
        body,
        cx,
    )
}
