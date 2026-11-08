//! Read-only mail views. The store enforces the admitted private scope and keyset.
use super::{
    inputs::{MessageBox, MessageList, MessageView, Validate},
    outputs::*,
    receipt,
};
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{Actor, MessageQuery, ReadBudget, Snapshot, StoredText};
use se_types::{Detail, Page, PageRequest, Result, SeError, details};
use std::{num::NonZeroU32, time::Duration};

pub fn list<R: Snapshot>(input: MessageList, cx: &mut Cx<'_, R>) -> Result<MessagePage> {
    input.validate()?;
    scope::project(cx.admission)?;
    let from = input
        .from
        .as_deref()
        .map(|name| scope::selected_actor(cx, name))
        .transpose()?;
    let selected_to = input
        .owner_to
        .as_deref()
        .map(|name| scope::selected_actor(cx, name))
        .transpose()?;
    let (to, from) = if input.cli_list {
        (selected_to, from)
    } else {
        match input.mailbox {
            MessageBox::Inbox => (Some(cx.admission.actor.clone()), from),
            MessageBox::Sent => {
                if let Some(from) = &from
                    && from != &cx.admission.actor
                {
                    return Err(scope_denied(
                        cx,
                        &format!("from {} in sent box", scope::actor_id(from)),
                    ));
                }
                (None, Some(cx.admission.actor.clone()))
            }
        }
    };
    if matches!(cx.admission.actor, Actor::Agent(_))
        && to.as_ref().is_some_and(|to| to != &cx.admission.actor)
        && from
            .as_ref()
            .is_some_and(|from| from != &cx.admission.actor)
    {
        return Err(scope_denied(
            cx,
            "both sender and recipient name other principals",
        ));
    }
    let kind = input
        .kind
        .as_ref()
        .map(|kind| {
            serde_json::to_value(kind)
                .map_err(|e| scope::unreadable("message kind", &e.to_string()))
                .and_then(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| SeError::invalid("kind", "registered string"))
                })
        })
        .transpose()?;
    let mut full_command = vec![
        "se".into(),
        "--project".into(),
        scope::project(cx.admission)?.to_string(),
        "msg".into(),
        "list".into(),
        "--full".into(),
        "--limit".into(),
        input.limit.to_string(),
    ];
    let to_selector = input.owner_to.as_deref().filter(|_| input.cli_list);
    for (flag, actor, original) in [
        ("--to", &to, to_selector),
        ("--from", &from, input.from.as_deref()),
    ] {
        if let Some(actor) = actor {
            let selector = match actor {
                Actor::Human(_) => original.unwrap_or("owner").to_owned(),
                Actor::Agent(_) | Actor::Remote(_) => scope::actor_id(actor),
            };
            full_command.extend([flag.into(), selector]);
        }
    }
    if let Some(kind) = &kind {
        full_command.extend(["--kind".into(), kind.clone()]);
    }
    if matches!(input.view, MessageView::All) {
        full_command.push("--all".into());
    }
    if let Some(cursor) = &input.cursor {
        full_command.extend(["--cursor".into(), cursor.to_string()]);
    }
    let query = MessageQuery {
        recipient: to.clone(),
        sender: from.clone(),
        kind,
        unread_only: matches!(input.view, MessageView::Unread),
        full_body: true,
    };
    let count_query = MessageQuery {
        unread_only: true,
        ..query.clone()
    };
    let unread_total = cx
        .read
        .message_count(count_query)
        .map_err(|e| store_error(&e))?;
    let page = cx
        .read
        .messages(
            query,
            ReadBudget {
                page: PageRequest {
                    after: input.cursor,
                    limit: NonZeroU32::new(u32::from(input.limit))
                        .ok_or_else(|| SeError::invalid("limit", "positive"))?,
                    max_bytes: NonZeroU32::new(256 * 1024)
                        .ok_or_else(|| SeError::invalid("body budget", "positive"))?,
                },
                deadline: Duration::from_secs(5),
            },
        )
        .map_err(|e| {
            let mut error = store_error(&e);
            if let Detail::CursorInvalid(detail) = error.body.detail() {
                let mut detail = detail.clone();
                detail.next_step =
                    "Remove or replace --cursor, then rerun the same message list (MCP: cursor)."
                        .into();
                error.body = se_types::ErrorBody::new(Detail::CursorInvalid(detail));
            }
            error
        })?;
    let window = page.window().clone();
    let next = page.next().cloned();
    let mut items = Vec::with_capacity(page.items().len());
    for record in page.into_items() {
        let from = receipt::mail_sender_ref(cx.read, &record)?;
        let event = scope::require_present(
            cx.read
                .event(record.event.clone())
                .map_err(|e| store_error(&e))?,
            "mail sent event",
            "Read the original message event in the same project, then retry this inbox/list cursor; do not send another message.",
        )?;
        let StoredText::Present(body) = record.body else {
            return Err(scope::unreadable(
                "message body",
                "content is erased; it cannot be represented as an empty preview",
            ));
        };
        if !record.body_complete {
            return Err(scope::unreadable(
                "message body",
                "the full-body store read returned a truncated body",
            ));
        }
        let bytes = body.len() as u64;
        let preview_end = if input.full {
            body.len()
        } else {
            body.char_indices()
                .nth(usize::from(input.preview_chars.unwrap_or(400)))
                .map(|(offset, _)| offset)
                .unwrap_or(body.len())
        };
        let complete = preview_end == body.len();
        let kind = serde_json::from_value(serde_json::Value::String(record.kind))
            .map_err(|e| scope::unreadable("stored message kind", &e.to_string()))?;
        let body_command = (!complete).then(|| command_text(&full_command));
        let body_argv = (!complete).then(|| full_command.clone());
        let delivery = Delivery {
            state: if matches!(record.recipient, Actor::Human(_)) {
                "not-applicable"
            } else if record.delivered.is_some() {
                "delivered"
            } else {
                "pending"
            }
            .into(),
            at: None,
        };
        let disposition = Delivery {
            state: if record.superseded_by.is_some() {
                "superseded"
            } else if record.dismissed.is_some() {
                "dismissed"
            } else if record.read.is_some() {
                "read"
            } else {
                "unread"
            }
            .into(),
            at: None,
        };
        items.push(MessageRow {
            channel_reply: channel_reply(cx.read, &record.message)?,
            id: record.message,
            event_id: record.event,
            from,
            to: if record.work.is_some() {
                receipt::floor_ref()
            } else {
                receipt::actor_ref(cx.read, &record.recipient)?
            },
            for_recipient: if record.work.is_some() {
                Some(receipt::actor_ref(cx.read, &record.recipient)?)
            } else {
                None
            },
            work: record.work,
            kind,
            sent_at: receipt::timestamp(if event.header.door == se_store::Door::Import {
                event.header.occurred_at_us
            } else {
                event.recorded_at_us
            })?,
            reply_to: record.reply_to,
            refs: record.refs,
            delivery,
            disposition,
            notification: receipt::notification(cx.read, record.quiet, record.notifications)?,
            body: MessageBody {
                text: body[..preview_end].into(),
                complete,
                bytes,
                command: body_command,
                argv: body_argv,
            },
            unreadable: None,
        });
    }
    let to_ref = to
        .as_ref()
        .map(|actor| receipt::actor_ref(cx.read, actor))
        .transpose()?;
    let from_ref = from
        .as_ref()
        .map(|actor| receipt::actor_ref(cx.read, actor))
        .transpose()?;
    let view = MessagePageView {
        op: "list".into(),
        recipient: to_ref.clone(),
        disposition: if matches!(input.view, MessageView::Unread) {
            "unread"
        } else {
            "all"
        }
        .into(),
        r#box: if input.cli_list {
            "any"
        } else {
            match input.mailbox {
                MessageBox::Inbox => "inbox",
                MessageBox::Sent => "sent",
            }
        }
        .into(),
        filter: MessageFilter {
            to: to_ref,
            from: from_ref,
            kind: input.kind,
        },
        inspection: matches!(cx.admission.actor, Actor::Human(_))
            && to.as_ref().is_some_and(|to| to != &cx.admission.actor),
        full: input.full,
        scope: if matches!(cx.admission.actor, Actor::Human(_)) {
            "project"
        } else {
            "own"
        }
        .into(),
    };
    Ok(MessagePage {
        view,
        consistency: "live-keyset".into(),
        page: Page::new(items, window, next)?,
        unread_total: Some(unread_total),
    })
}
fn scope_denied<R: Snapshot>(cx: &Cx<'_, R>, filter: &str) -> SeError {
    match &cx.admission.actor {
        Actor::Agent(agent) => {
            SeError::new(Detail::MessageScopeDenied(details::MessageScopeDenied {
                filter: filter.into(),
                agent: agent.clone(),
            }))
        }
        Actor::Human(_) | Actor::Remote(_) => SeError::invalid("mail filters", filter),
    }
}

fn command_text(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            if !arg.is_empty()
                && arg
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:/".contains(&byte))
            {
                arg.clone()
            } else if cfg!(windows) {
                format!("'{}'", arg.replace('\'', "''"))
            } else {
                format!("'{}'", arg.replace('\'', "'\"'\"'"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn channel_reply<R: se_store::Snapshot>(
    read: &mut R,
    id: &se_types::MessageId,
) -> se_types::Result<Option<super::outputs::ChannelReply>> {
    if read.info().schema_version < 5 {
        return Ok(None);
    }
    let route = read
        .channel_reply_route(id)
        .map_err(|e| se_core_store_error(&e))?;
    Ok(route.map(|r|super::outputs::ChannelReply{instruction:if r.active {format!("This message came from the Owner's paired phone. Send your answer with stateengine_msg_send to {} and set reply_to to {}. A final turn answer alone stays local and does not reach the phone. Keep each linked reply under 1500 characters; send several linked replies when a longer answer is needed.",r.owner,r.original)}else{"The phone channel is disconnected; a new mail reply remains saved but cannot reach that phone.".into()},to:r.owner,reply_to:r.original,active:r.active}))
}
fn se_core_store_error(error: &se_store::StoreError) -> se_types::SeError {
    crate::store_error::store_error(error)
}
pub fn channel_reply_instruction<R: se_store::Snapshot>(
    read: &mut R,
    id: &se_types::MessageId,
) -> se_types::Result<Option<String>> {
    Ok(channel_reply(read, id)?.map(|r| r.instruction))
}
