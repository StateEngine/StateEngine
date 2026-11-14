//! Only native receipt-bound contacts can introduce ordinary return mail.
use super::*;

pub(crate) fn validate_returns(c: &Connection, batch: &AtomicBatch) -> StoreResult<bool> {
    if !batch.events.iter().any(|event| {
        matches!(
            &event.body,
            EventBody::RemoteMailboxRecorded {
                change: MailboxChange::Received { .. } | MailboxChange::Checkpoint { .. }
            }
        )
    }) {
        return Ok(false);
    }
    if !matches!(batch.admission.actor, Actor::Remote(_))
        || batch.admission.session.is_some()
        || batch.request.is_none()
    {
        return Err(denied());
    }
    let Some(EventBody::RemoteMailboxRecorded {
        change:
            MailboxChange::Checkpoint {
                source,
                peer,
                target,
                ..
            },
    }) = batch.events.last().map(|e| &e.body)
    else {
        return Err(denied());
    };
    let mut messages = 0;
    let mut received = 0;
    for event in &batch.events {
        if event.header.door != Door::Host {
            return Err(denied());
        }
        match &event.body {
            EventBody::MessageSent {
                message,
                recipient,
                body: InputText::Inline(body),
                refs,
                reply_to,
                ..
            } => {
                if *recipient != Actor::Agent(source.agent.clone())
                    || body.is_empty()
                    || body.len() > se_types::MESSAGE_BODY_MAX_BYTES
                    || !refs.is_empty()
                    || reply_to.is_some()
                {
                    return Err(denied());
                }
                if !batch.events.iter().any(|e| matches!(&e.body, EventBody::RemoteMailboxRecorded { change: MailboxChange::Received { record } } if record.message == *message)) { return Err(denied()); }
                messages += 1;
            }
            EventBody::RemoteMailboxRecorded {
                change: MailboxChange::Received { record },
            } => {
                if record.source != *source
                    || record.sender.host != *peer
                    || record.sender.project != target.project
                    || record.sender.agent != target.agent
                    || batch.admission.actor != Actor::Remote(record.principal.clone())
                {
                    return Err(denied());
                }
                let contact = mailbox::contact(c, source, *peer, target, &record.original)?
                    .ok_or_else(denied)?;
                super::admit_address(c, &record.sender)?;
                if contact.principal != record.principal {
                    return Err(denied());
                }
                received += 1;
            }
            EventBody::RemoteMailboxRecorded {
                change: MailboxChange::Checkpoint { .. },
            } if std::ptr::eq(event, batch.events.last().ok_or_else(denied)?) => (),
            _ => return Err(denied()),
        }
    }
    if messages != received || batch.admission.scope != Scope::Project(source.project.clone()) {
        return Err(denied());
    }
    Ok(true)
}
