//! Read-only schema 1/2 mail selection until the native host performs migration.
use super::*;
use rusqlite::types::Value;
pub(super) fn sql(
    p: &[u8],
    to: Option<&[u8]>,
    from: Option<&[u8]>,
    query: &MessageQuery,
    h: u64,
    after: u64,
    projection: &str,
) -> (String, Vec<Value>) {
    let unread = query.unread_only && to.is_some();
    let index = if to.is_some() {
        "messages_recipient_seq"
    } else if from.is_some() {
        "messages_sender_seq"
    } else if query.kind.is_some() {
        "messages_kind_seq"
    } else {
        "messages_project_seq"
    };
    let mut statement = if unread {
        format!(
            "SELECT {projection} FROM marks m INDEXED BY marks_unread JOIN messages d ON d.sent_seq=m.message_seq WHERE m.project_id=? AND m.read_seq IS NULL AND m.dismissed_seq IS NULL AND m.message_seq>? AND m.message_seq<=?"
        )
    } else {
        format!(
            "SELECT {projection} FROM messages d INDEXED BY {index} JOIN marks m ON m.message_seq=d.sent_seq WHERE d.project_id=? AND d.sent_seq>? AND d.sent_seq<=?"
        )
    };
    let mut args = vec![
        Value::Blob(p.into()),
        Value::Integer(after as i64),
        Value::Integer(h as i64),
    ];
    if let Some(to) = to {
        statement.push_str(if unread {
            " AND m.recipient_id=?"
        } else {
            " AND d.recipient_id=?"
        });
        args.push(Value::Blob(to.into()));
    }
    if let Some(from) = from {
        statement.push_str(" AND d.sender_id=?");
        args.push(Value::Blob(from.into()));
    }
    if let Some(kind) = &query.kind {
        statement.push_str(" AND d.message_kind=?");
        args.push(Value::Text(kind.clone()));
    }
    if query.unread_only && !unread {
        statement.push_str(" AND m.read_seq IS NULL AND m.dismissed_seq IS NULL");
    }
    if query.unread_only {
        statement.push_str(" AND d.superseded_by IS NULL");
    }
    (statement, args)
}
