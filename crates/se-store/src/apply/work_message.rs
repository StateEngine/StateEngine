//! Shared work bodies and independent, recipient-bound delivery projections.
use super::*;

pub(super) fn send(
    c: &Connection,
    header: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    revision: u64,
    facts: Value,
) -> StoreResult<()> {
    let EventBody::WorkMessageSent {
        message,
        work,
        kind,
        body,
        refs,
        reply_to: _,
        quiet,
    } = body
    else {
        return Err(invalid("work message dispatch"));
    };
    if connection::mail_table(c)? != "message_deliveries" {
        return Err(fail(
            StoreErrorCode::MigrationFailed,
            "shared work mail requires schema 3; start the native host with se up to perform its verified migration",
        ));
    }
    notification::require_schema(c, quiet)?;
    work.validate().map_err(invalid)?;
    if refs.len() > 20
        || !matches!(
            kind.as_str(),
            "note" | "task" | "question" | "answer" | "blocker" | "done" | "handoff" | "finding"
        )
        || (kind == "finding") != (work.action == se_types::WorkAction::Finding)
    {
        return Err(invalid("work message refs, kind or finding action"));
    }
    let scope = scope_key(c, &header.scope, true)?;
    let project = project_id(c, &header.scope, false)?;
    let message = key(c, "message", message.as_str(), &scope, true)?;
    let sender = key(
        c,
        header.actor.kind(),
        header.actor.wire(),
        if header.actor.kind() == "human" {
            &[0]
        } else {
            &scope
        },
        false,
    )?;
    for reference in &refs {
        let event = key(c, "event", reference.as_str(), &scope, false)?;
        let exists: bool = c
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE project_id=? AND event_id=?)",
                crate::sql_value::sql_params![project, event],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if !exists {
            return Err(fail(
                StoreErrorCode::ReferenceMissing,
                "work message ref outside scope or absent",
            ));
        }
    }
    // Exactly one owning payload; recipient rows contain only its sequence.
    payload(
        c,
        seq,
        "body",
        &codec::text(body.as_materialized()?, se_types::MESSAGE_BODY_MAX_BYTES)?,
    )?;
    for agent in &work.addressees {
        let recipient = key(c, "agent", agent.as_str(), &scope, false)?;
        let exists: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE project_id=? AND principal_id=? AND principal_kind='agent')",crate::sql_value::sql_params![project,recipient],|r|r.get(0)).map_err(sql)?;
        if !exists {
            return Err(fail(
                StoreErrorCode::ReferenceMissing,
                "work addressee is not registered in this project",
            ));
        }
        c.execute("INSERT INTO message_deliveries(project_id,message_id,sent_seq,sender_id,recipient_id,message_kind,is_floor,revision) VALUES(?,?,?,?,?,?,1,?)",crate::sql_value::sql_params![project,message,seq,sender,recipient,kind,revision]).map_err(sql)?;
        notification::sent(c, seq, &recipient, quiet)?;
        count(c, &project, &recipient, 1, seq)?;
    }
    codec::aux(c, seq, facts)
}

pub(super) fn mark(
    c: &Connection,
    header: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    revision: u64,
) -> StoreResult<()> {
    let (message, recipient, column, tag, evidence) = match body {
        EventBody::MessageRead { message, recipient } => {
            (message, recipient, "read_seq", "read", None)
        }
        EventBody::MessageDismissed { message, recipient } => {
            (message, recipient, "dismissed_seq", "dismissed", None)
        }
        EventBody::MessageDelivered {
            message,
            recipient,
            evidence,
        } => (
            message,
            recipient,
            "delivered_seq",
            "delivered",
            Some(evidence),
        ),
        _ => return Err(invalid("message mark dispatch")),
    };
    if header.actor != recipient && tag != "delivered" {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "recipient marker actor differs",
        ));
    }
    let scope = scope_key(c, &header.scope, false)?;
    let project = project_id(c, &header.scope, false)?;
    let message_id = message.clone();
    let message = key(c, "message", message.as_str(), &scope, false)?;
    let recipient = key(
        c,
        recipient.kind(),
        recipient.wire(),
        if recipient.kind() == "human" {
            &[0]
        } else {
            &scope
        },
        false,
    )?;
    let current = connection::mail_table(c)? == "message_deliveries";
    let selection = if current {
        "SELECT sent_seq,read_seq IS NULL AND dismissed_seq IS NULL AND superseded_by IS NULL,is_floor FROM message_deliveries WHERE project_id=? AND message_id=? AND recipient_id=?"
    } else {
        "SELECT d.sent_seq,m.read_seq IS NULL AND m.dismissed_seq IS NULL AND d.superseded_by IS NULL,0 FROM messages d JOIN marks m ON m.message_seq=d.sent_seq WHERE d.project_id=? AND d.message_id=? AND d.recipient_id=?"
    };
    let (sent, unread, floor): (i64, bool, bool) = c
        .query_row(
            selection,
            crate::sql_value::sql_params![project, message, recipient],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(sql)?
        .ok_or_else(|| {
            fail(
                StoreErrorCode::ScopeMismatch,
                format!("message {message_id} unavailable to the named recipient"),
            )
        })?;
    let evidence = evidence
        .map(|v| key(c, "event", v.as_str(), &scope, false))
        .transpose()?;
    if floor {
        c.execute("INSERT INTO work_mark_data(event_seq,message_seq,message_id,recipient_id,disposition,evidence_event) VALUES(?,?,?,?,?,?)",crate::sql_value::sql_params![seq,sent,message,recipient,tag,evidence]).map_err(sql)?;
    } else {
        c.execute("INSERT INTO mark_data(event_seq,message_seq,recipient_id,disposition,evidence_event) VALUES(?,?,?,?,?)",crate::sql_value::sql_params![seq,sent,recipient,tag,evidence]).map_err(sql)?;
        c.execute(
            &format!("UPDATE marks SET {column}=? WHERE message_seq=? AND {column} IS NULL"),
            crate::sql_value::sql_params![seq, sent],
        )
        .map_err(sql)?;
        c.execute(
            "UPDATE messages SET revision=? WHERE project_id=? AND message_id=?",
            crate::sql_value::sql_params![revision, project, message],
        )
        .map_err(sql)?;
    }
    if current {
        c.execute(&format!("UPDATE message_deliveries SET {column}=? WHERE project_id=? AND message_id=? AND recipient_id=? AND {column} IS NULL"),crate::sql_value::sql_params![seq,project,message,recipient]).map_err(sql)?;
        c.execute(
            "UPDATE message_deliveries SET revision=? WHERE project_id=? AND message_id=?",
            crate::sql_value::sql_params![revision, project, message],
        )
        .map_err(sql)?;
    }
    if unread && tag != "delivered" {
        count(c, &project, &recipient, -1, seq)?;
    }
    Ok(())
}
