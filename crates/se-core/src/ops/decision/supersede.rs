//! One owner action approves a pending replacement and retires the predecessor
//! in one FULL batch. The store's existing transition/CAS rules remain intact.
use super::*;
use se_store::{CommitReceipt, StoredEvent, WriterModeValue};

pub(super) fn plan<R: Snapshot>(
    kernel: &Kernel,
    input: DecisionSupersede,
    cx: &mut Cx<'_, R>,
    terminal: &HumanTerminal,
) -> Result<(AtomicBatch, DecisionThen)> {
    input.validate()?;
    admitted(cx)?;
    require_human_terminal("decision.supersede", cx.admission, terminal)?;
    let normalized = intent(&input)?;
    let prior_expected = expected(&input.decision_id, input.expect, cx)?.0;
    let (mut replacement_expected, mut cause) =
        expected(&input.replacement_id, input.replacement_expect, cx)?;
    let replacement = scope::require_present(
        cx.read
            .decision(input.replacement_id.clone())
            .map_err(|e| store_error(&e))?,
        "superseding replacement",
    )?;
    let pending = matches!(replacement.current.body, EventBody::DecisionProposed { .. });
    let ratification = if pending {
        let event = kernel.event(
            EventBody::DecisionRatified {
                decision: input.replacement_id.clone(),
                expected: Expected::Revision(replacement_expected),
                approval: kernel.facts()?.event.clone(),
            },
            cx,
        )?;
        replacement_expected.value =
            replacement_expected.value.checked_add(1).ok_or_else(|| {
                SeError::invalid("replacement revision", "room for its approval transition")
            })?;
        cause = event.header.event.clone();
        Some(event)
    } else {
        None
    };
    let body = EventBody::DecisionSuperseded {
        prior: input.decision_id,
        replacement: input.replacement_id,
        prior_expected,
        replacement_expected,
        approval: kernel.facts()?.event.clone(),
    };
    let (mut batch, then) = batch(
        kernel,
        "decision.supersede",
        "supersede",
        input.idempotency_key,
        normalized,
        body,
        cx,
    )?;
    batch.events[0].header.cause = Some(cause);
    if let Some(ratification) = ratification {
        // Re-kind the adapter's unused second fresh UUID; do not add RNG to core.
        let bytes = kernel.facts()?.message.canonical_bytes()?.ok_or_else(|| {
            SeError::invalid("supersede allocation", "fresh canonical UUIDv7 call facts")
        })?;
        let retirement = &mut batch.events[0];
        retirement.header.event = EventId::from_bytes(bytes)?;
        if retirement.header.event == ratification.header.event {
            return Err(SeError::invalid(
                "supersede allocation",
                "two distinct fresh event IDs",
            ));
        }
        // Primary receipt is the replacement's actual governing transition;
        // the predecessor retirement follows under the same atomic commit.
        batch.events.insert(0, ratification);
    }
    Ok((batch, then))
}

pub(super) fn committed<R: Snapshot>(
    receipt: &CommitReceipt,
    primary: &StoredEvent,
    cx: &mut Cx<'_, R>,
) -> Result<super::super::DecisionReceipt> {
    use super::super::{DecisionAction, ReceiptAuthority, ReceiptGuard};
    if receipt.events.len() != 2 || receipt.events[0] != primary.header.event {
        return Err(scope::unreadable(
            "supersede receipt",
            "atomic approval/retirement membership differs",
        ));
    }
    let retired = scope::require_present(
        cx.read
            .event(receipt.events[1].clone())
            .map_err(|e| store_error(&e))?,
        "atomic predecessor retirement",
    )?;
    let EventBody::DecisionRatified {
        decision,
        expected: Expected::Revision(expected),
        approval,
    } = &primary.body
    else {
        return Err(scope::unreadable(
            "supersede receipt",
            "primary event is not its replacement approval",
        ));
    };
    let EventBody::DecisionSuperseded {
        prior,
        replacement,
        prior_expected,
        replacement_expected,
        approval: retirement_approval,
    } = &retired.body
    else {
        return Err(scope::unreadable(
            "supersede receipt",
            "second event is not predecessor retirement",
        ));
    };
    if decision != replacement
        || primary.header.actor != retired.header.actor
        || primary.header.scope != retired.header.scope
        || !matches!(primary.header.actor, se_store::Actor::Human(_))
        || retired.writer.kind() != receipt.writer.kind()
        || retired.durability != receipt.durability
        || retired.header.cause.as_ref() != Some(&primary.header.event)
        || approval != &primary.header.event
        || retirement_approval != &primary.header.event
        || expected.value.get().checked_add(1) != Some(primary.revision.value.get())
        || primary.revision.value != replacement_expected.value
        || prior_expected.value.get().checked_add(1) != Some(retired.revision.value.get())
    {
        return Err(scope::unreadable(
            "supersede receipt",
            "immutable atomic transition facts differ",
        ));
    }
    let mut replacement = row(decision, primary, cx)?;
    replacement.supersedes = Some(prior.clone());
    Ok(super::super::DecisionReceipt {
        commit: super::super::receipt::write_fields(receipt, primary)?,
        action: DecisionAction::Supersede,
        authority: ReceiptAuthority {
            guard: Some(ReceiptGuard::OwnerTerminalOutsideAgentTree),
            limit: "mistake/drift guard; not proof against a determined agent using the same OS account".into(),
        },
        project: super::super::receipt::named_project(cx)?,
        decision: replacement,
        replaced: Some(row(prior, &retired, cx)?),
    })
}
