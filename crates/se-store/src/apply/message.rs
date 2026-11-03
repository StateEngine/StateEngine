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
    let old = key_for(&message)?;
    let new = key_for(&replacement)?;
    let row:Option<(Vec<u8>,Vec<u8>,bool)>=c.query_row("SELECT d.sender_id,d.recipient_id,m.read_seq IS NULL AND m.dismissed_seq IS NULL AND d.superseded_by IS NULL FROM messages d JOIN marks m ON m.message_seq=d.sent_seq WHERE d.project_id=? AND d.message_id=?",rusqlite::params![p,old],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(sql)?;
    let (sender, recipient, unread) = row.ok_or_else(|| {
        fail(
            StoreErrorCode::ReferenceMissing,
            "replaced source message is absent",
        )
    })?;
    let actor = key(
        c,
        h.actor.kind(),
        h.actor.wire(),
        if matches!(h.actor, Actor::Human(_)) {
            &[0]
        } else {
            &scope
        },
        false,
    )?;
    let valid:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM messages WHERE project_id=? AND message_id=? AND sender_id=? AND recipient_id=?)",rusqlite::params![p,new,sender,recipient],|r|r.get(0)).map_err(sql)?;
    if sender != actor || !valid {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "replacement must preserve the exact recorded sender and recipient",
        ));
    }
    let changed=c.execute("UPDATE messages SET superseded_by=?,revision=? WHERE project_id=? AND message_id=? AND superseded_by IS NULL",crate::sql_value::sql_params![new,rev,p,old]).map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "source message already has a replacement",
        ));
    }
    if unread {
        count(c, &p, &recipient, -1, seq)?;
    }
    codec::aux(c, seq, facts)
}
