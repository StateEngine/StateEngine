//! Check the original contact before atomically importing a whole return page.
use super::*;
use se_store::{EventBody, InputText, remote::ReturnAttribution};

pub(super) async fn page(
    context: &ExecutionContext,
    source: &VerifiedSourceSession,
    contact: &MailContact,
    device: &MachineSession,
    client: Arc<dyn RemoteClient>,
) -> Result<()> {
    let address = source.source().address();
    let selected = contact.clone();
    let grant = device.grant.clone();
    let lookup = address.clone();
    let after = background_read(context, move |phase| {
        phase.remote_return_cursor(&lookup, selected.peer, &selected.target, &grant)
    })
    .await?;
    let input = RemoteReplies {
        target: contact.target.clone(),
        after: after.clone(),
        limit: 20,
        budget: 65536,
    };
    let result = client.replies(source.context(), input).await?;
    source.context().check_current()?;
    let Some(cursor) = page_cursor(&result, &after)? else {
        return Ok(());
    };
    let selected = contact.clone();
    let lookup = address.clone();
    let messages = result.body.messages;
    let intent = serde_json::json!({"source":address,"peer":device.host,"grant":device.grant,"target":contact.target,"messages":messages,"cursor":cursor});
    let last = messages.last().ok_or_else(poisoned)?.message.clone();
    let bodies = background_read(context, move |phase| {
        let mut bodies = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for message in messages {
            if message.sender.host != selected.peer || message.sender.project != selected.target.project || message.sender.agent != selected.target.agent
                || !seen.insert(message.message.clone()) || message.body.is_empty() || message.occurred_at_us < 0 {
                return Err(invalid("return mail differs from its authenticated contact"));
            }
            if serde_json::from_value::<se_core::commit::MessageKind>(serde_json::Value::String(message.kind.clone())).is_err() {
                return Err(invalid("return mail has an unsupported ordinary mail kind; its page was not acknowledged"));
            }
            let original = phase.remote_mail_contact(&lookup,selected.peer,&selected.target,&message.original)?
                .ok_or_else(||invalid("return mail has no original committed source send; its page was not acknowledged"))?;
            if original.principal != selected.principal { return Err(invalid("return-mail principal differs from its original contact")); }
            if phase.remote_return_seen(&lookup,selected.peer,&message.message)? { continue; }
            let now = session::now().map_err(|_|invalid("return-mail clock unavailable"))?;
            let id = se_types::MessageId::from_parts(u64::try_from(now / 1000).map_err(|_|invalid("return-mail clock is negative"))?,
                session::entropy().map_err(|_|invalid("return-mail entropy unavailable"))?).map_err(|_|invalid("return-mail ID allocation failed"))?;
            bodies.push(EventBody::MessageSent {
                message:id.clone(),recipient:Actor::Agent(lookup.agent.clone()),body:InputText::Inline(message.body.into()),
                kind:message.kind,refs:Vec::new(),reply_to:None,quiet:message.quiet,
            });
            bodies.push(EventBody::RemoteMailboxRecorded { change:MailboxChange::Received { record:ReturnAttribution {
                message:id,peer_message:message.message,original:message.original,source:lookup.clone(),sender:message.sender,principal:original.principal,
            } } });
        }
        Ok(bodies)
    }).await?;
    let mut bodies = bodies;
    bodies.push(EventBody::RemoteMailboxRecorded {
        change: MailboxChange::Checkpoint {
            source: address,
            peer: device.host,
            target: contact.target.clone(),
            grant: device.grant.clone(),
            cursor,
        },
    });
    let admission = Admission {
        scope: Scope::Project(source.source().project.clone()),
        actor: Actor::Remote(contact.principal.clone()),
        session: None,
        generation: context.generation.get(),
    };
    let key = IdempotencyKey::new(format!("remote-return-{}-{last}", device.grant))?;
    write::commit(
        context,
        admission,
        key,
        "remote.return.receive",
        intent,
        bodies,
    )
    .await?;
    Ok(())
}

fn invalid(reason: &str) -> Box<se_store::StoreError> {
    Box::new(se_store::StoreError {
        code:se_store::StoreErrorCode::ScopeMismatch,cause:reason.into(),detail:se_store::StoreDetail::None,
        remedy:se_types::Remedy { text:"Restore the original send receipt and saved destination pairing before retrying this same return-mail page.".into(),command:None },
        retry:se_types::Retry::AfterReread,
    })
}

fn page_cursor(
    result: &RemoteRepliesResult,
    after: &Option<se_types::Cursor>,
) -> Result<Option<se_types::Cursor>> {
    check_size(result, 65536)?;
    if result.schema != RemoteRepliesResult::SCHEMA || result.messages.len() > 20 {
        return Err(refused(
            "return-mail response changed its schema or page limit",
        ));
    }
    if result.messages.is_empty() {
        if &result.next != after || result.more {
            return Err(refused(
                "empty return-mail page changed its cursor or omitted pending mail",
            ));
        }
        return Ok(None);
    }
    let cursor = result
        .next
        .clone()
        .ok_or_else(|| refused("return-mail page has no durable continuation"))?;
    if Some(&cursor) == after.as_ref() {
        return Err(refused(
            "return-mail page repeated its cursor without progress",
        ));
    }
    Ok(Some(cursor))
}
