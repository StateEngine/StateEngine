//! Per-recipient send rate cap, enforced inside the append transaction.
//! One sender may not bury one recipient in messages: the count is the
//! pair's own rows, read under the write lock after the event is stamped,
//! so two competing sends can never both read the same total. The owner
//! door, notes to yourself, host background mail and imported history are
//! exempt; floor work mail is its own pair (sender to floor) and counts
//! one per broadcast, never per fan-out delivery.
use super::*;

/// Most messages one sender may put on one recipient inside the window.
pub(super) const LIMIT: u64 = 10;
/// Rolling window the limit counts, in minutes.
pub(super) const WINDOW_MINUTES: u64 = 10;

/// The owner door, host background mail and imported history never bury a
/// recipient; a note to yourself is exempt per pair.
fn exempt(header: &EventHeader, recipient: Option<&Actor>) -> bool {
    matches!(header.door, Door::Host | Door::Import)
        || matches!(header.actor, Actor::Human(_))
        || recipient.is_some_and(|to| to == &header.actor)
}

fn refusal(from: &Actor, to: &str, count: u64) -> Box<StoreError> {
    let from = from.wire();
    let mut error = fail(
        StoreErrorCode::MessageRateOverCap,
        format!(
            "{from} has sent {count} messages to {to} in the last {WINDOW_MINUTES} minutes (limit {LIMIT})"
        ),
    );
    error.detail = StoreDetail::MessageRateOverCap {
        from: from.to_owned(),
        to: to.to_owned(),
        count,
        limit: LIMIT,
        window_minutes: WINDOW_MINUTES,
    };
    error
}

fn actor_ref_key(c: &Connection, actor: &Actor, scope: &[u8]) -> StoreResult<Vec<u8>> {
    key(
        c,
        actor.kind(),
        actor.wire(),
        if actor.kind() == "human" {
            &[0]
        } else {
            scope
        },
        false,
    )
}

/// Direct pair: count only the pair's direct rows. Floor fan-out toward
/// the recipient is delivery of the sender's floor broadcast, not a direct
/// message, so it never counts against the pair.
pub(super) fn direct(
    c: &Connection,
    header: &EventHeader,
    project: &[u8],
    scope: &[u8],
    sender: &Actor,
    recipient: &Actor,
) -> StoreResult<()> {
    if exempt(header, Some(recipient)) {
        return Ok(());
    }
    let since_us = header.occurred_at_us - WINDOW_MINUTES as i64 * 60 * 1_000_000;
    let from = actor_ref_key(c, sender, scope)?;
    let to = actor_ref_key(c, recipient, scope)?;
    let count: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM messages m JOIN events e ON e.seq = m.sent_seq
             WHERE m.project_id = ? AND m.sender_id = ? AND m.recipient_id = ?
               AND e.recorded_at_us >= ?",
            crate::sql_value::sql_params![project, from, to, since_us],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let count = u64::try_from(count).map_err(invalid)?;
    if count >= LIMIT {
        return Err(refusal(sender, recipient.wire(), count));
    }
    Ok(())
}

/// Floor pair: the sender's own broadcasts, one each; the fan-out row per
/// addressee is delivery, not another message.
pub(super) fn floor(
    c: &Connection,
    header: &EventHeader,
    project: &[u8],
    scope: &[u8],
    sender: &Actor,
) -> StoreResult<()> {
    if exempt(header, None) {
        return Ok(());
    }
    let since_us = header.occurred_at_us - WINDOW_MINUTES as i64 * 60 * 1_000_000;
    let from = actor_ref_key(c, sender, scope)?;
    let count: i64 = c
        .query_row(
            "SELECT COUNT(DISTINCT d.sent_seq) FROM message_deliveries d
             JOIN events e ON e.seq = d.sent_seq
             WHERE d.project_id = ? AND d.sender_id = ? AND d.is_floor = 1
               AND e.recorded_at_us >= ?",
            crate::sql_value::sql_params![project, from, since_us],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let count = u64::try_from(count).map_err(invalid)?;
    if count >= LIMIT {
        return Err(refusal(sender, "floor", count));
    }
    Ok(())
}
