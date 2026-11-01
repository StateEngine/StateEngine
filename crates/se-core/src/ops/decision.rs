//! Synchronous decision batches; approval authority is a native admission fact,
//! never a typed decision ID or a field in the operation input.
use super::{administration::*, inputs::Validate};
use crate::{
    commit::Cx,
    dispatch::{Kernel, admitted},
    scope,
    store_error::store_error,
};
use se_store::{AtomicBatch, DecisionKind, EventBody, Expected, InputText, Revision, Snapshot};
use se_types::{DecisionId, EventId, IdempotencyKey, Result, SeError};
use std::num::NonZeroU64;

mod supersede;

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
) -> Result<(Revision, EventId)> {
    let record = scope::require_present(
        cx.read.decision(id.clone()).map_err(|e| store_error(&e))?,
        &id.to_string(),
        "Verify the decision's exact ID and recorded revision in this project before retrying the original request unchanged.",
    )?;
    if record.current.header.scope != cx.admission.scope {
        return Err(scope::unreadable(
            "decision",
            "snapshot returned another scope",
        ));
    }
    let value = NonZeroU64::new(want.unwrap_or(record.revision.value.get()))
        .ok_or_else(|| SeError::invalid("expect", "positive entity revision"))?;
    Ok((Revision { value }, record.current.header.event))
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
) -> Result<(AtomicBatch, DecisionThen)> {
    input.validate()?;
    admitted(cx)?;
    let normalized = intent(&input)?;
    let expected = Expected::Revision(expected(&input.decision_id, input.expect, cx)?.0);
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
) -> Result<(AtomicBatch, DecisionThen)> {
    input.validate()?;
    admitted(cx)?;
    let normalized = intent(&input)?;
    let expected = Expected::Revision(expected(&input.decision_id, input.expect, cx)?.0);
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
) -> Result<(AtomicBatch, DecisionThen)> {
    input.validate()?;
    admitted(cx)?;
    let normalized = intent(&input)?;
    let expected = Expected::Revision(expected(&input.decision_id, input.expect, cx)?.0);
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
) -> Result<(AtomicBatch, DecisionThen)> {
    supersede::plan(kernel, input, cx)
}

fn text(value: &se_store::StoredText, subject: &str) -> Result<String> {
    match value {
        se_store::StoredText::Present(value) => Ok(value.clone()),
        _ => Err(scope::unreadable(
            subject,
            "original content is unavailable; no complete receipt can be reconstructed",
        )),
    }
}
pub(super) fn row<R: Snapshot>(
    id: &DecisionId,
    latest: &se_store::StoredEvent,
    cx: &mut Cx<'_, R>,
) -> Result<super::DecisionRow> {
    use super::{DecisionRow, DecisionState, DecisionStatement};
    let record = scope::require_present(
        cx.read
            .decision(id.clone())
            .map_err(|error| store_error(&error))?,
        "receipt proposal",
        "Read the original proposal event in this project; when recovering a write response, preserve its original --key and committed event IDs.",
    )?;
    let proposal = record.original.as_deref().unwrap_or(&record.current);
    if proposal.header.scope != cx.admission.scope || latest.header.scope != cx.admission.scope {
        return Err(scope::unreadable(
            "decision receipt",
            "proposal/transition scope differs",
        ));
    }
    let EventBody::DecisionProposed {
        decision,
        key,
        statement,
        rationale,
        prior,
        ..
    } = &proposal.body
    else {
        return Err(scope::unreadable(
            "decision proposal",
            "original event is not a proposal",
        ));
    };
    if decision != id || latest.revision.value < proposal.revision.value {
        return Err(scope::unreadable(
            "decision receipt",
            "proposal identity or transition revision differs",
        ));
    }
    let (state, reason, replacement) = match &latest.body {
        EventBody::DecisionProposed { decision, .. } if decision == id => {
            (DecisionState::Pending, None, None)
        }
        EventBody::DecisionRatified { decision, .. } if decision == id => {
            (DecisionState::Ratified, None, None)
        }
        EventBody::DecisionRejected {
            decision, reason, ..
        } if decision == id => (
            DecisionState::Rejected,
            Some(text(reason, "rejection reason")?),
            None,
        ),
        EventBody::DecisionRetracted {
            decision, reason, ..
        } if decision == id => (
            DecisionState::Retracted,
            Some(text(reason, "retraction reason")?),
            None,
        ),
        EventBody::DecisionSuperseded {
            prior, replacement, ..
        } if prior == id => (DecisionState::Superseded, None, Some(replacement.clone())),
        _ => {
            return Err(scope::unreadable(
                "decision receipt",
                "transition does not belong to the proposal",
            ));
        }
    };
    let statement = text(statement, "decision statement")?;
    let decided = state != DecisionState::Pending;
    Ok(DecisionRow {
        id: id.clone(),
        key: key.clone(),
        state,
        governing: state == DecisionState::Ratified,
        revision: latest.revision.value.get(),
        statement: DecisionStatement {
            bytes: statement.len() as u64,
            text: statement,
            complete: true,
            command: None,
            argv: None,
        },
        rationale: rationale
            .as_ref()
            .map(|value| text(value, "decision rationale"))
            .transpose()?,
        proposed_by: super::receipt::actor_ref(cx.read, &proposal.header.actor)?,
        proposed_at: super::receipt::timestamp(proposal.recorded_at_us)?,
        decided_by: if decided {
            Some(super::receipt::actor_ref(cx.read, &latest.header.actor)?)
        } else {
            None
        },
        decided_at: if decided {
            Some(super::receipt::timestamp(latest.recorded_at_us)?)
        } else {
            None
        },
        reason,
        supersedes: prior.clone(),
        superseded_by: replacement,
        event_id: latest.header.event.clone(),
    })
}
pub fn committed<R: Snapshot>(
    then: DecisionThen,
    receipt: se_store::CommitReceipt,
    cx: &mut Cx<'_, R>,
) -> Result<super::DecisionReceipt> {
    use super::{DecisionAction, ReceiptAuthority, ReceiptGuard};
    crate::dispatch::receipt_key(&receipt, &then.request)?;
    let event = super::receipt::committed_event(cx.read, &receipt)?;
    if event.header.scope != cx.admission.scope || event.header.actor != cx.admission.actor {
        return Err(scope::unreadable(
            "decision receipt",
            "original scope/actor differs",
        ));
    }
    if then.action == "supersede" && matches!(event.body, EventBody::DecisionRatified { .. }) {
        return supersede::committed(&receipt, &event, cx);
    }
    let (action, id) = match &event.body {
        EventBody::DecisionProposed { decision, .. } => (DecisionAction::Propose, decision),
        EventBody::DecisionRatified { decision, .. } => (DecisionAction::Ratify, decision),
        EventBody::DecisionRejected { decision, .. } => (DecisionAction::Reject, decision),
        EventBody::DecisionRetracted { decision, .. } => (DecisionAction::Retract, decision),
        EventBody::DecisionSuperseded { prior, .. } => (DecisionAction::Supersede, prior),
        _ => {
            return Err(scope::unreadable(
                "decision receipt",
                "primary event is not a decision operation",
            ));
        }
    };
    let actual_action = match action {
        DecisionAction::Propose => "propose",
        DecisionAction::Ratify => "ratify",
        DecisionAction::Reject => "reject",
        DecisionAction::Retract => "retract",
        DecisionAction::Supersede => "supersede",
    };
    if actual_action != then.action {
        return Err(scope::unreadable(
            "decision receipt",
            "operation action differs from its original event",
        ));
    }
    let guarded = action != DecisionAction::Propose;
    if guarded && !matches!(event.header.actor, se_store::Actor::Human(_)) {
        return Err(scope::unreadable(
            "decision approval receipt",
            "transition was not committed by its owner",
        ));
    }
    let original = row(id, &event, cx)?;
    let (decision, replaced) = if let EventBody::DecisionSuperseded {
        replacement,
        replacement_expected,
        ..
    } = &event.body
    {
        let cause = event.header.cause.clone().ok_or_else(|| {
            scope::unreadable(
                "supersede receipt",
                "immutable replacement revision reference is absent",
            )
        })?;
        let replacement_event = scope::require_present(
            cx.read.event(cause).map_err(|error| store_error(&error))?,
            "superseding replacement revision",
            scope::COMMITTED_READ_RECOVERY,
        )?;
        if replacement_event.revision.value != replacement_expected.value
            || !matches!(&replacement_event.body, EventBody::DecisionRatified { decision, .. } if decision == replacement)
        {
            return Err(scope::unreadable(
                "supersede receipt",
                "referenced replacement revision was not ratified",
            ));
        }
        let mut replacement_row = row(replacement, &replacement_event, cx)?;
        replacement_row.supersedes = Some(id.clone());
        (replacement_row, Some(original))
    } else {
        (original, None)
    };
    Ok(super::DecisionReceipt {
        commit: super::receipt::write_fields(&receipt, &event)?,
        authority: ReceiptAuthority {
            guard: guarded.then_some(ReceiptGuard::OwnerTerminalOutsideAgentTree),
            limit: "mistake/drift guard; not proof against a determined agent using the same OS account".into(),
        },
        action, project: super::receipt::named_project(cx)?, decision, replaced,
    })
}
