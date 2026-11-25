//! Read-only schema 1/2 mail selection until the native host performs migration.
use super::*;
use rusqlite::types::Value;
pub(super) fn sql(w: MailWindow<'_>, projection: &str) -> (String, Vec<Value>) {
    let unread = w.query.unread_only && w.to.is_some();
    let index = if w.to.is_some() {
        "messages_recipient_seq"
    } else if w.from.is_some() {
        "messages_sender_seq"
    } else if w.query.kind.is_some() {
        "messages_kind_seq"
    } else {
        "messages_project_seq"
    };
    // A newest-first cursor carries the page frontier (its oldest returned
    // delivery); the next page resumes strictly below it from the floor.
    let (lower, upper_op, upper) = if w.query.direction == MailDirection::NewestFirst && w.after > 0
    {
        (0, "<", w.after)
    } else {
        (w.after, "<=", w.high)
    };
    let mut statement = if unread {
        format!(
            "SELECT {projection} FROM marks m INDEXED BY marks_unread JOIN messages d ON d.sent_seq=m.message_seq WHERE m.project_id=? AND m.read_seq IS NULL AND m.dismissed_seq IS NULL AND m.message_seq>? AND m.message_seq{upper_op}?"
        )
    } else {
        format!(
            "SELECT {projection} FROM messages d INDEXED BY {index} JOIN marks m ON m.message_seq=d.sent_seq WHERE d.project_id=? AND d.sent_seq>? AND d.sent_seq{upper_op}?"
        )
    };
    let mut args = vec![
        Value::Blob(w.project.into()),
        Value::Integer(lower as i64),
        Value::Integer(upper as i64),
    ];
    if let Some(to) = w.to {
        statement.push_str(if unread {
            " AND m.recipient_id=?"
        } else {
            " AND d.recipient_id=?"
        });
        args.push(Value::Blob(to.into()));
    }
    if let Some(from) = w.from {
        statement.push_str(" AND d.sender_id=?");
        args.push(Value::Blob(from.into()));
    }
    if let Some(kind) = &w.query.kind {
        statement.push_str(" AND d.message_kind=?");
        args.push(Value::Text(kind.clone()));
    }
    if w.query.unread_only && !unread {
        statement.push_str(" AND m.read_seq IS NULL AND m.dismissed_seq IS NULL");
    }
    if w.query.unread_only {
        statement.push_str(" AND d.superseded_by IS NULL");
    }
    (statement, args)
}
