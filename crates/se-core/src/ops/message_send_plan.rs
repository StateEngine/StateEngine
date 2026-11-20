//! Planning and replay for local mail writes.
use crate::{
    commit::*,
    dispatch::{Kernel, admitted},
    ops::inputs::Validate,
    scope,
    store_error::store_error,
};
use se_store::{Actor, EventBody, InputText, RequestIdentity, Snapshot, StoreErrorCode};
use se_types::{EventId, MessageId, Read, Result, SeError};

/// Resolves a send destination: floor work mail names the registered agents,
/// direct mail resolves the selector, and an unauthenticated remote reply
/// contact is refused before any recipient is chosen.
fn resolve_recipient<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    input: &MessageSend,
) -> Result<Option<Actor>> {
    if let Some(work) = &input.work {
        for agent in &work.addressees {
            if scope::selected_actor(cx, agent.as_str())? != Actor::Agent(agent.clone()) {
                return Err(SeError::invalid(
                    "work.addressees",
                    "registered canonical agents in this project",
                ));
            }
        }
        return Ok(None);
    }
    let selector = input
        .to
        .as_deref()
        .ok_or_else(|| SeError::invalid("to", "an explicit recipient"))?;
    let remote = input
        .reply_to
        .as_ref()
        .map(|original| {
            cx.read
                .remote_reply_recipient(original.clone(), selector)
                .map_err(|error| store_error(&error))
        })
        .transpose()?
        .flatten();
    if remote.is_none()
        && selector.split_once('/').is_some_and(|(host, rest)| {
            host.len() == 64 && host.bytes().all(|b| b.is_ascii_hexdigit()) && rest.contains('/')
        })
    {
        return Err(SeError::new(se_types::Detail::CapabilityInvalid(se_types::details::CapabilityInvalid {
            subject: "remote reply contact".into(),
            reason: "this recipient has no authenticated message from that source address".into(),
            next_step: "Reply from the original recipient's current session using the sender address and original message ID as reply_to. The destination Owner can restore revoked source access with se remote permissions --local in a terminal on the destination.".into(),
        })));
    }
    match remote {
        Some(actor) => Ok(Some(actor)),
        None => Ok(Some(scope::selected_actor(cx, selector)?)),
    }
}
/// Checks a replacement target through the sender's own read port: it must be
/// a direct message the sender wrote to the same recipient, not yet replaced.
fn supersede_target<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    old: &MessageId,
    recipient: &Actor,
) -> Result<EventId> {
    let record = match cx.read.message(old.clone()) {
        Ok(Read::Present { value }) => value,
        Ok(Read::Absent { checked }) => {
            return Err(SeError::invalid(
                "supersedes",
                &format!(
                    "a message ID that exists in this project; the target was not found ({checked}); list your sent mail with se msg list --box sent"
                ),
            ));
        }
        Ok(Read::Unknown { what } | Read::Unreadable { reason: what, .. }) => {
            return Err(scope::unreadable("supersession target", &what));
        }
        Err(error) if error.code == StoreErrorCode::ScopeMismatch => {
            return Err(scope::unreadable_with(
                "supersession target",
                "it is not readable from this seat, and only its sender can supersede it",
                "ask the original sender to send the replacement, or send the recipient a new direct message that references the target ID and states the replacement",
            ));
        }
        Err(error) => return Err(store_error(&error)),
    };
    if record.work.is_some() {
        return Err(SeError::invalid(
            "supersedes",
            "a direct message; floor work mail keeps its own lifecycle",
        ));
    }
    if record.sender != cx.admission.actor {
        return Err(SeError::invalid(
            "supersedes",
            &format!(
                "a message you sent; the target was sent by {} — ask that sender to supersede it, or reply to it with your new instruction",
                record.sender.wire().to_owned()
            ),
        ));
    }
    if record.recipient != *recipient {
        return Err(SeError::invalid(
            "supersedes",
            &format!(
                "a message you sent to the same recipient; the target was sent to {}",
                record.recipient.wire().to_owned()
            ),
        ));
    }
    if let Some(replacement) = &record.superseded_by {
        return Err(SeError::invalid(
            "supersedes",
            &format!(
                "a message that has no replacement yet; the target is already replaced by {} — supersede that replacement instead",
                replacement.as_str()
            ),
        ));
    }
    Ok(record.event.clone())
}
fn message_identity<R: Snapshot>(
    kernel: &Kernel,
    input: &MessageSend,
    recipient: Option<&Actor>,
    implicit_captain: bool,
    cx: &mut Cx<'_, R>,
) -> Result<(Vec<EventId>, serde_json::Value, RequestIdentity)> {
    let registry = cx.read.legacy_registry().map_err(|e| store_error(&e))?;
    let refs = input
        .refs
        .iter()
        .map(|id| {
            EventId::from_legacy(id.clone())
                .or_else(|_| EventId::from_registered_legacy(id.clone(), &registry))
        })
        .collect::<Result<Vec<_>>>()?;
    drop(registry);
    let kind = serde_json::to_value(&input.kind)
        .map_err(|e| scope::unreadable("message kind", &e.to_string()))?;
    let mut intent =
        serde_json::json!({"kind":kind,"body":input.body,"refs":refs,"reply_to":input.reply_to});
    if let Some(old) = &input.supersedes {
        // An absent field stays out of the intent so ordinary sends digest
        // exactly as before it existed and same-key retries still replay.
        intent["supersedes"] = serde_json::json!(old);
    }
    if input.quiet {
        intent["quiet"] = serde_json::Value::Bool(true);
    }
    if implicit_captain {
        intent["recipient"] = serde_json::json!("captain-default");
    } else if let Some(recipient) = &recipient {
        intent["recipient"] = serde_json::json!(recipient.wire().to_owned());
    } else {
        intent["recipient"] = serde_json::json!("floor");
        intent["work"] = serde_json::json!(input.work);
    }
    let key = input.idempotency_key.clone();
    let identity = kernel.request_identity("message.send", key.clone(), &intent)?;
    Ok((refs, kind, identity))
}

fn replacement<R: Snapshot>(
    input: &MessageSend,
    identity: &RequestIdentity,
    recipient: Option<&Actor>,
    cx: &mut Cx<'_, R>,
) -> Result<Option<EventId>> {
    // Look the receipt up before validating, so an exact retry of a committed
    // send replays the original result instead of re-checking replacement.
    let supersede_event = match (
        cx.read
            .resolve_request(identity)
            .map_err(|e| store_error(&e))?,
        input.supersedes.as_ref(),
    ) {
        (Read::Present { .. }, _) => None,
        (Read::Absent { .. }, None) => None,
        (Read::Absent { .. }, Some(old)) => {
            let recipient = recipient
                .ok_or_else(|| SeError::invalid("supersedes", "a checked direct recipient"))?;
            Some(supersede_target(cx, old, recipient)?)
        }
        (other, _) => Err(
            match scope::require_present(
                other,
                "original request receipt",
                "Resolve the original request after restoring store access.",
            ) {
                Ok(_) => SeError::invalid(
                    "supersession request",
                    "a store that keeps request receipts consistent",
                ),
                Err(error) => error,
            },
        )?,
    };
    Ok(supersede_event)
}

fn add_route_check<R: Snapshot>(
    kernel: &Kernel,
    batch: &mut se_store::AtomicBatch,
    cx: &Cx<'_, R>,
) -> Result<()> {
    let recipient = match &batch.events[0].body {
        EventBody::MessageSent { recipient, .. } => recipient.clone(),
        _ => {
            return Err(scope::unreadable(
                "captain route",
                "expected a direct message",
            ));
        }
    };
    let mut route = kernel.event(
        EventBody::CaptainMessageRouted {
            message_event: kernel.facts()?.event.clone(),
            captain: recipient,
        },
        cx,
    )?;
    route.header.event = kernel.facts()?.profile_event.clone();
    batch.events.push(route);
    Ok(())
}

pub(crate) fn send<R: Snapshot>(
    kernel: &Kernel,
    input: MessageSend,
    cx: &mut Cx<'_, R>,
) -> Result<OpStep<MessageSendOutput, MessageSendThen>> {
    input.validate()?;
    admitted(cx)?;
    let implicit_captain = input.to.is_none();
    let mut recipient = if implicit_captain {
        None
    } else {
        resolve_recipient(cx, &input)?
    };
    let (refs, kind, identity) =
        message_identity(kernel, &input, recipient.as_ref(), implicit_captain, cx)?;
    let key = input.idempotency_key.clone();
    if implicit_captain {
        match cx
            .read
            .resolve_request(&identity)
            .map_err(|e| store_error(&e))?
        {
            Read::Present { value } => {
                return Ok(OpStep::Complete(kernel.message_committed(
                    MessageSendThen { request: key },
                    value,
                    cx,
                )?));
            }
            Read::Absent { .. } => {}
            other => {
                scope::require_present(
                    other,
                    "message receipt",
                    "Restore access to the store and retry the same key.",
                )?;
                return Err(scope::unreadable(
                    "message receipt",
                    "unexpected present value",
                ));
            }
        }
        let Actor::Agent(_) = &cx.admission.actor else {
            return Err(SeError::invalid(
                "to",
                "an explicit recipient for owner mail",
            ));
        };
        let captain = crate::ops::assignment::current_captain(cx)?;
        if captain == cx.admission.actor {
            return Err(SeError::invalid(
                "to",
                "an explicit recipient when you are captain",
            ));
        }
        recipient = Some(captain);
    }
    let supersede_event = replacement(&input, &identity, recipient.as_ref(), cx)?;
    let kind = kind
        .as_str()
        .ok_or_else(|| SeError::invalid("message kind", "registered string"))?
        .to_owned();
    let body = if let Some(work) = input.work {
        EventBody::WorkMessageSent {
            message: kernel.facts()?.message.clone(),
            work,
            kind,
            body: InputText::Inline(input.body),
            refs,
            reply_to: input.reply_to,
            quiet: input.quiet,
        }
    } else {
        EventBody::MessageSent {
            message: kernel.facts()?.message.clone(),
            recipient: recipient.ok_or_else(|| {
                SeError::invalid("message recipient", "a checked direct recipient")
            })?,
            kind,
            body: InputText::Inline(input.body),
            refs,
            reply_to: input.reply_to,
            quiet: input.quiet,
        }
    };
    let mut event = kernel.event(body, cx)?;
    if let Some(old) = supersede_event {
        event.header.supersedes = Some(old);
    }
    let mut batch = kernel.batch_with_identity(identity, event, cx)?;
    if implicit_captain {
        add_route_check(kernel, &mut batch, cx)?;
    }
    Ok(OpStep::Commit {
        batch,
        then: MessageSendThen { request: key },
    })
}
