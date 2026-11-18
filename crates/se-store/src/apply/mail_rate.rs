//! Per-recipient send rate cap, enforced inside the append transaction.
//! One sender may not bury one recipient in messages: the count is the
//! pair's own direct rows inside the window, read under the write lock
//! after the event is stamped, so two competing sends can never both read
//! the same total. Only direct messages count, per sender-to-recipient
//! pair, and floor fan-out never counts against a recipient. The owner
//! door, notes to yourself, host background mail and imported history are
//! exempt.
use super::*;

/// Most messages one sender may put on one recipient inside the window.
pub(super) const LIMIT: u64 = 10;
/// Rolling window the limit counts, in minutes.
pub(super) const WINDOW_MINUTES: u64 = 10;

/// The owner door, host background mail and imported history never bury a
/// recipient; a note to yourself is exempt per pair.
fn exempt(header: &EventHeader, recipient: &Actor) -> bool {
    matches!(header.door, Door::Host | Door::Import)
        || matches!(header.actor, Actor::Human(_))
        || recipient == &header.actor
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
        if actor.kind() == "human" { &[0] } else { scope },
        false,
    )
}

/// Direct pair: count exactly the pair's rows inside the window. The
/// window is a lower time bound on the append stamp, and the stamp can
/// move backwards when the system clock steps, so the lookup is bounded
/// by that time through the pair's time index, never by a fixed number of
/// newest rows. Floor fan-out toward the recipient is delivery of the
/// sender's floor broadcast, not a direct message, so it never counts
/// against the pair.
pub(super) fn direct(
    c: &Connection,
    header: &EventHeader,
    project: &[u8],
    scope: &[u8],
    sender: &Actor,
    recipient: &Actor,
) -> StoreResult<()> {
    if exempt(header, recipient) {
        return Ok(());
    }
    let since_us = header.occurred_at_us - WINDOW_MINUTES as i64 * 60 * 1_000_000;
    let from = actor_ref_key(c, sender, scope)?;
    let to = actor_ref_key(c, recipient, scope)?;
    // Homes older than schema 15 lack the stamp column, so their count joins
    // the event stamp; the cap bounds their newest rows, so the bound stays
    // small until a host open migrates the home.
    let count: i64 = if crate::connection::info(c)?.schema_version >= 15 {
        c.query_row(
            "SELECT COUNT(*) FROM messages
             WHERE project_id = ? AND sender_id = ? AND recipient_id = ?
               AND recorded_at_us >= ?",
            crate::sql_value::sql_params![project, from, to, since_us],
            |r| r.get(0),
        )
        .map_err(sql)?
    } else {
        c.query_row(
            "SELECT COUNT(*)
             FROM (SELECT m.sent_seq FROM messages m
                   WHERE m.project_id = ? AND m.sender_id = ? AND m.recipient_id = ?
                   ORDER BY m.sent_seq DESC LIMIT ?)
             JOIN events e ON e.seq = sent_seq
             WHERE e.recorded_at_us >= ?",
            crate::sql_value::sql_params![project, from, to, LIMIT + 1, since_us],
            |r| r.get(0),
        )
        .map_err(sql)?
    };
    let count = u64::try_from(count).map_err(invalid)?;
    if count >= LIMIT {
        return Err(refusal(sender, recipient.wire(), count));
    }
    Ok(())
}
