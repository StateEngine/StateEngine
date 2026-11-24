//! Imported message replacement is distinct from recipient read or dismissal.
use super::*;
pub(super) fn supersede(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    facts: Value,
) -> StoreResult<()> {
    let EventBody::MessageSuperseded {
        message,
        replacement,
        ..
    } = body
    else {
        return Err(invalid("message replacement dispatch"));
    };
    if h.door != Door::Import || message == replacement {
        return Err(invalid(
            "historical message replacement requires distinct original source IDs",
        ));
    }
    let p = project_id(c, &h.scope, false)?;
    let scope = scope_key(c, &h.scope, false)?;
    let key_for = |id: &se_types::MessageId| key(c, "message", id.as_str(), &scope, false);
    let keys = SupersedeKeys {
        project: &p,
        scope: &scope,
        old: &key_for(&message)?,
        new: &key_for(&replacement)?,
    };
    supersede_rows(c, &keys, h, seq, rev)?;
    codec::aux(c, seq, facts)
}
/// Header-carried replacement: the new message event itself supersedes the
/// recorded send event of an earlier direct message.
pub(super) fn supersede_from_header(
    c: &Connection,
    h: &EventHeader,
    old_event: &se_types::EventId,
    new_message: &se_types::MessageId,
    seq: i64,
    rev: u64,
) -> StoreResult<()> {
    let p = project_id(c, &h.scope, false)?;
    let scope = scope_key(c, &h.scope, false)?;
    let event = key(c, "event", old_event.as_str(), &scope, false)?;
    let old: Option<Vec<u8>> = c
        .query_row(
            "SELECT d.message_id FROM events e JOIN messages d ON d.sent_seq = e.seq WHERE e.project_id = ? AND e.event_id = ?",
            rusqlite::params![p, event],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    let old =
        old.ok_or_else(|| reference_missing("supersession target event has no recorded message"))?;
    let new = key(c, "message", new_message.as_str(), &scope, false)?;
    let keys = SupersedeKeys {
        project: &p,
        scope: &scope,
        old: &old,
        new: &new,
    };
    supersede_rows(c, &keys, h, seq, rev)
}
struct SupersedeKeys<'a> {
    project: &'a [u8],
    scope: &'a [u8],
    old: &'a [u8],
    new: &'a [u8],
}
fn supersede_rows(
    c: &Connection,
    k: &SupersedeKeys<'_>,
    h: &EventHeader,
    seq: i64,
    rev: u64,
) -> StoreResult<()> {
    let row: Option<(Vec<u8>, Vec<u8>, bool)> = c
        .query_row(
            "SELECT d.sender_id,d.recipient_id,m.read_seq IS NULL AND m.dismissed_seq IS NULL AND d.superseded_by IS NULL FROM messages d JOIN marks m ON m.message_seq=d.sent_seq WHERE d.project_id=? AND d.message_id=?",
            rusqlite::params![k.project, k.old],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(sql)?;
    let (sender, recipient, unread) =
        row.ok_or_else(|| reference_missing("replaced source message is absent"))?;
    let actor = key(
        c,
        h.actor.kind(),
        h.actor.wire(),
        if matches!(h.actor, Actor::Human(_)) {
            &[0]
        } else {
            k.scope
        },
        false,
    )?;
    let valid: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM messages WHERE project_id=? AND message_id=? AND sender_id=? AND recipient_id=?)",
            rusqlite::params![k.project, k.new, sender, recipient],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if sender != actor || !valid {
        return Err(scope_mismatch(
            "replacement must preserve the exact recorded sender and recipient",
        ));
    }
    let changed = c
        .execute(
            "UPDATE messages SET superseded_by=?,revision=? WHERE project_id=? AND message_id=? AND superseded_by IS NULL",
            crate::sql_value::sql_params![k.new, rev, k.project, k.old],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(invalid_transition(
            "source message already has a replacement",
        ));
    }
    if connection::mail_table(c)? == "message_deliveries" {
        c.execute(
            "UPDATE message_deliveries SET superseded_by=?,revision=? WHERE project_id=? AND message_id=?",
            crate::sql_value::sql_params![k.new, rev, k.project, k.old],
        )
        .map_err(sql)?;
    }
    if unread {
        count(c, k.project, &recipient, -1, seq)?;
    }
    Ok(())
}
