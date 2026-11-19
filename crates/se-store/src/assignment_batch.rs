//! Assignment transitions must be committed with their floor message.
use crate::{error::*, *};
pub(crate) fn validate_batch(batch: &AtomicBatch) -> StoreResult<()> {
    validate_routes(batch)?;
    let has_assignment = batch.events.iter().any(|e| {
        matches!(
            e.body,
            EventBody::AssignmentOpened { .. } | EventBody::AssignmentTransitioned { .. }
        )
    });
    if !has_assignment {
        return Ok(());
    }
    if batch
        .events
        .iter()
        .any(|e| matches!(e.body, EventBody::ProjectCaptainChanged { .. }))
    {
        return Err(invalid(
            "change the captain and assignments in separate operations",
        ));
    }
    for (index, event) in batch.events.iter().enumerate() {
        validate_assignment(batch, index, event)?;
    }
    Ok(())
}

fn validate_routes(batch: &AtomicBatch) -> StoreResult<()> {
    for (index, event) in batch.events.iter().enumerate() {
        if let EventBody::CaptainMessageRouted {
            message_event,
            captain,
        } = &event.body
        {
            let matching = batch.events[..index]
                .iter()
                .find(|candidate| &candidate.header.event == message_event);
            if !matches!(matching.map(|value| &value.body), Some(EventBody::MessageSent { recipient, kind, reply_to: None, .. }) if recipient == captain && matches!(kind.as_str(), "question" | "blocker" | "done"))
            {
                return Err(invalid(
                    "captain route requires a preceding matching direct report",
                ));
            }
        }
    }
    Ok(())
}

fn validate_assignment(batch: &AtomicBatch, index: usize, event: &NewEvent) -> StoreResult<()> {
    let (floor_event, expected_action, expected_kind, assignee) = match &event.body {
        EventBody::AssignmentOpened {
            assignment,
            assignee,
            floor_event,
            ..
        } => {
            if assignment != floor_event {
                return Err(invalid(
                    "assignment ID must identify its opening floor event",
                ));
            }
            (
                floor_event,
                se_types::WorkAction::Assign,
                "task",
                Some(assignee),
            )
        }
        EventBody::AssignmentTransitioned {
            floor_event,
            action,
            ..
        } => {
            use se_store_contract::assignment::AssignmentTransition;
            let (work, kind) = match action {
                AssignmentTransition::Accept => (se_types::WorkAction::Notify, "note"),
                AssignmentTransition::Done => (se_types::WorkAction::Notify, "done"),
                AssignmentTransition::Block => (se_types::WorkAction::Notify, "blocker"),
                AssignmentTransition::HandBack => (se_types::WorkAction::Return, "handoff"),
            };
            (floor_event, work, kind, None)
        }
        _ => return Ok(()),
    };
    let Some(floor) = batch.events[..index]
        .iter()
        .find(|candidate| &candidate.header.event == floor_event)
    else {
        return Err(invalid(
            "assignment requires a preceding floor event in the same operation",
        ));
    };
    let EventBody::WorkMessageSent {
        work,
        kind,
        body,
        refs,
        quiet: false,
        reply_to: None,
        ..
    } = &floor.body
    else {
        return Err(invalid("assignment event must reference a floor message"));
    };
    if work.action != expected_action
        || kind != expected_kind
        || assignee.is_some_and(|agent| !work.addressees.contains(agent))
        || body.as_materialized()?.trim().is_empty()
        || matches!(&event.body, EventBody::AssignmentTransitioned { assignment, .. } if !refs.contains(assignment))
    {
        return Err(invalid(
            "assignment floor message does not match its transition",
        ));
    }
    // The assignment projection checks this claimed captain against the current
    // captain in the same transaction before any batch can commit.
    let captain = match &event.body {
        EventBody::AssignmentOpened { captain, .. }
        | EventBody::AssignmentTransitioned { captain, .. } => Some(captain),
        _ => None,
    };
    validate_human_report(batch, event, captain, kind, body)?;
    if batch
        .events
        .iter()
        .filter(|candidate| match &candidate.body {
            EventBody::AssignmentOpened {
                floor_event: referenced,
                ..
            }
            | EventBody::AssignmentTransitioned {
                floor_event: referenced,
                ..
            } => referenced == floor_event,
            _ => false,
        })
        .count()
        != 1
    {
        return Err(invalid(
            "each assignment transition requires its own floor event",
        ));
    }

    Ok(())
}

fn validate_human_report(
    batch: &AtomicBatch,
    event: &NewEvent,
    captain: Option<&Actor>,
    kind: &str,
    body: &InputText,
) -> StoreResult<()> {
    if let (
        EventBody::AssignmentTransitioned {
            assignment, action, ..
        },
        Some(Actor::Human(owner)),
    ) = (&event.body, captain)
    {
        use se_store_contract::assignment::AssignmentTransition;
        if matches!(
            action,
            AssignmentTransition::Done
                | AssignmentTransition::Block
                | AssignmentTransition::HandBack
        ) {
            let text = body.as_materialized()?;
            let found = batch.events.iter().any(|candidate| match &candidate.body {
                EventBody::MessageSent {
                    recipient: Actor::Human(recipient),
                    kind: direct_kind,
                    body: direct_body,
                    refs,
                    quiet: false,
                    ..
                } => {
                    recipient == owner
                        && direct_kind == kind
                        && refs.contains(assignment)
                        && direct_body
                            .as_materialized()
                            .is_ok_and(|direct| direct == text)
                }
                _ => false,
            });
            if !found {
                return Err(invalid(
                    "report to a human captain requires matching direct mail in the same operation",
                ));
            }
        }
    }
    Ok(())
}
