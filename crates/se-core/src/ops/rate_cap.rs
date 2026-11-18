//! Agent-door send rate cap, ported from the Node floor rule: one sender may
//! not bury one recipient in messages. The count is a bounded newest-first
//! read of the pair's own deliveries, so a capped pair counts exactly and a
//! long history is never read. The owner door, a note to yourself and floor
//! work mail are exempt; exact retries replay before this is reached.
use crate::{commit::Cx, scope, store_error::store_error};
use se_store::{Actor, MailDirection, MessageQuery, ReadBudget, Snapshot};
use se_types::{Detail, PageRequest, Result, SeError, details};
use std::{num::NonZeroU32, time::Duration};

/// Most messages one sender may put on one recipient inside the window.
pub(crate) const LIMIT: u64 = 10;
/// Rolling window the limit counts, in minutes.
pub(crate) const WINDOW_MINUTES: u64 = 10;
const PAGE_LIMIT: u32 = 32; // capped pair plus margin; never whole history
const PAGE_BYTES: u32 = 256 * 1024;

/// Refuse a capped agent pair by name, with the legal alternatives.
pub(crate) fn enforce<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    recipient: Option<&Actor>,
    now_us: i64,
) -> Result<()> {
    let sender = &cx.admission.actor;
    let Some(recipient) = recipient else {
        return Ok(()); // one floor work act fans out; it is not a pair
    };
    if matches!(sender, Actor::Human(_)) || sender == recipient {
        return Ok(()); // the owner door and a note to yourself are never refused
    }
    let since_us = now_us - WINDOW_MINUTES as i64 * 60 * 1_000_000;
    let count = sent_in_window(cx, sender, recipient, since_us)?;
    if count < LIMIT {
        return Ok(());
    }
    Err(SeError::new(Detail::MessageRateOverCap(
        details::MessageRateOverCap {
            from: sender.wire().to_owned(),
            to: recipient.wire().to_owned(),
            count,
            limit: LIMIT,
            window_minutes: WINDOW_MINUTES,
        },
    )))
}
fn sent_in_window<R: Snapshot>(
    cx: &mut Cx<'_, R>,
    sender: &Actor,
    recipient: &Actor,
    since_us: i64,
) -> Result<u64> {
    let page = cx
        .read
        .messages(
            MessageQuery {
                sender: Some(sender.clone()),
                recipient: Some(recipient.clone()),
                kind: None,
                unread_only: false,
                full_body: false,
                direction: MailDirection::NewestFirst,
            },
            ReadBudget {
                page: PageRequest {
                    after: None,
                    limit: NonZeroU32::new(PAGE_LIMIT)
                        .ok_or_else(|| SeError::invalid("mail page", "positive"))?,
                    max_bytes: NonZeroU32::new(PAGE_BYTES)
                        .ok_or_else(|| SeError::invalid("mail page", "positive"))?,
                },
                deadline: Duration::from_secs(1),
            },
        )
        .map_err(|error| store_error(&error))?;
    let mut count = 0;
    for record in page.into_items() {
        let event = cx
            .read
            .event(record.event)
            .map_err(|error| store_error(&error))?;
        let event =
            scope::require_present(event, "message event", "restore mail history and retry")?;
        if event.recorded_at_us < since_us {
            break; // the stream is newest-first; the rest is older than the window
        }
        count += 1;
    }
    Ok(count)
}
