//! Incoming provider dispositions and private output release fences.
use super::*;
use crate::channel::{Disposition, OutputOutcome};

pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    state: &ChannelConnection,
    change: &Change,
    seq: i64,
) -> StoreResult<()> {
    match change {
        Change::CursorAdvanced {
            binding_revision,
            update,
            cursor,
            ..
        } => {
            let handled: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM channel_updates WHERE connection_id=? AND update_id=?)", rusqlite::params![state.id.as_str(), update], |r| r.get(0)).map_err(sql)?;
            if *binding_revision != state.revision || !handled {
                return Err(invalid(
                    "checkpoint requires an already committed exact input",
                ));
            }
            checkpoint(c, state, cursor.as_str(), false)?;
        }
        Change::UpdateHandled {
            binding_revision,
            update,
            cursor,
            disposition,
            ..
        } => {
            if *binding_revision != state.revision {
                return Err(invalid("stale channel binding or invalid provider update"));
            }
            let (receipt, message) = match disposition {
                Disposition::Saved {
                    receipt,
                    message,
                    subject,
                    private_chat,
                } => {
                    if !super::capacity(c, &state.id)? {
                        return Err(fail(
                            StoreErrorCode::Backpressure,
                            "channel pending input or output limit",
                        ));
                    }
                    let Pairing::Paired { phone } = &state.pairing else {
                        return Err(invalid("unpaired channel cannot save Owner mail"));
                    };
                    if phone.subject != *subject || phone.private_chat != *private_chat {
                        return Err(invalid("phone is outside exact approved binding"));
                    }
                    let scope = scope_key(c, &h.scope, false)?;
                    let p = project_id(c, &h.scope, false)?;
                    let m = key(c, "message", message.as_str(), &scope, false)?;
                    let sender = key(c, "human", state.owner.as_str(), &[0], false)?;
                    let recipient = key(c, "agent", state.target.agent.as_str(), &scope, false)?;
                    // Must be ordinary mail from the same writer operation, not a
                    // historical ID or a message saved after the provider ACK.
                    let valid: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM messages m JOIN events e ON e.seq=m.sent_seq JOIN events current ON current.seq=? WHERE m.project_id=? AND m.message_id=? AND m.sender_id=? AND m.recipient_id=? AND e.operation_id=current.operation_id)", crate::sql_value::sql_params![seq,p,m,sender,recipient], |r| crate::sql_value::value(r, 0)).map_err(sql)?;
                    if !valid {
                        return Err(invalid(
                            "Saved requires ordinary exact-recipient Owner mail in this transaction",
                        ));
                    }
                    (Some(receipt.as_str()), Some(m))
                }
                Disposition::Action { action } => {
                    let value = super::resume::action(c, action)?;
                    if value.connection != state.id || value.state != "confirmed" {
                        return Err(invalid("provider callback has no confirmed scoped action"));
                    }
                    (None, None)
                }
                Disposition::RejectedPaired {
                    reason,
                    subject,
                    private_chat,
                } => {
                    let Pairing::Paired { phone } = &state.pairing else {
                        return Err(invalid("private rejection requires current approved phone"));
                    };
                    if phone.subject != *subject
                        || phone.private_chat != *private_chat
                        || !matches!(
                            reason,
                            crate::channel::Rejection::TooLarge
                                | crate::channel::Rejection::QueueFull
                                | crate::channel::Rejection::Unsupported
                                | crate::channel::Rejection::Expired
                        )
                    {
                        return Err(invalid("private rejection scope/reason differs"));
                    }
                    (None, None)
                }
                Disposition::Rejected { .. } => (None, None),
            };
            let pending = message.is_some();
            let at: i64 = c
                .query_row(
                    "SELECT recorded_at_us FROM events WHERE seq=?",
                    [seq],
                    |r| crate::sql_value::value(r, 0),
                )
                .map_err(sql)?;
            let due = if pending {
                Some(at.saturating_add(60000000))
            } else {
                None
            };
            c.execute("INSERT INTO channel_updates(bot_id,update_id,cursor,connection_id,handled_seq,disposition,receipt_id,message_id,pending,status_due_at_us) VALUES(?,?,?,?,?,?,?,?,?,?)", crate::sql_value::sql_params![state.bot.id,update,cursor,state.id.as_str(),seq,codec::encode(disposition)?,receipt,message,pending,due]).map_err(sql)?;
            checkpoint(
                c,
                state,
                cursor
                    .as_ref()
                    .map(|v| v.as_str())
                    .unwrap_or(update.as_str()),
                cursor.is_none(),
            )?;
            if let Some(message) = message {
                c.execute(
                    "UPDATE channel_connections SET saved_count=saved_count+1 WHERE id=?",
                    [state.id.as_str()],
                )
                .map_err(sql)?;
                enqueue(c, state, Some(&message), None, "saved", seq)?;
            } else if matches!(disposition, Disposition::RejectedPaired { .. }) {
                enqueue_rejected(c, state, update, cursor.is_none(), seq)?;
            }
        }
        Change::DelayQueued {
            binding_revision,
            message,
            ..
        } => {
            if *binding_revision != state.revision
                || !matches!(state.pairing, Pairing::Paired { .. })
            {
                return Err(invalid("delayed status requires current paired binding"));
            }
            let scope = scope_key(c, &h.scope, false)?;
            let m = key(c, "message", message.as_str(), &scope, false)?;
            let due:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM channel_updates u JOIN events e ON e.seq=u.handled_seq JOIN events current ON current.seq=? WHERE u.connection_id=? AND u.message_id=? AND u.receipt_id IS NOT NULL AND e.recorded_at_us<=current.recorded_at_us-60000000 AND NOT EXISTS(SELECT 1 FROM channel_outbox o WHERE o.connection_id=u.connection_id AND o.original_id=u.message_id AND o.kind='reply'))",crate::sql_value::sql_params![seq,state.id.as_str(),m],|r|crate::sql_value::value(r,0)).map_err(sql)?;
            if !due {
                return Err(invalid(
                    "delayed status is not due or a linked reply already exists",
                ));
            }
            enqueue(c, state, Some(&m), None, "delay", seq)?;
            c.execute("UPDATE channel_updates SET status_due_at_us=NULL WHERE connection_id=? AND message_id=?",crate::sql_value::sql_params![state.id.as_str(),m]).map_err(sql)?;
        }
        Change::OutputStarted {
            binding_revision,
            output,
            expected_attempt,
            ..
        } => {
            if *expected_attempt >= 8
                || *binding_revision != state.revision
                || !matches!(state.pairing, Pairing::Paired { .. })
            {
                return Err(invalid("private output binding revoked or changed"));
            }
            let output = output.as_str();
            let now: i64 = c
                .query_row(
                    "SELECT recorded_at_us FROM events WHERE seq=?",
                    [seq],
                    |r| crate::sql_value::value(r, 0),
                )
                .map_err(sql)?;
            let changed = c.execute("UPDATE channel_outbox SET state='sending',last_seq=?,attempt=attempt+1 WHERE connection_id=? AND output_id=? AND binding_revision=? AND attempt=? AND state='queued' AND (retry_at_us IS NULL OR retry_at_us<=?)",crate::sql_value::sql_params![seq,state.id.as_str(),output,binding_revision,expected_attempt,now]).map_err(sql)?;
            if changed != 1 {
                return Err(invalid("outbox entry is not ready for a new attempt"));
            }
        }
        Change::OutputFinished {
            output,
            attempt,
            outcome,
            ..
        } => {
            let output = output.as_str();
            let revoked = matches!(state.pairing, Pairing::Revoked);
            let (status, provider, retry) = match outcome {
                OutputOutcome::Sent { provider_message } => {
                    ("sent", Some(provider_message.clone()), None)
                }
                OutputOutcome::PartSent {
                    part,
                    provider_message,
                } => {
                    let changed = c.execute("UPDATE channel_outbox SET provider_messages=json_insert(provider_messages,'$[#]',?),last_seq=? WHERE connection_id=? AND output_id=? AND attempt=? AND state='sending' AND json_array_length(provider_messages)=? AND ?<32", rusqlite::params![provider_message,seq,state.id.as_str(),output,i64::try_from(*attempt).map_err(invalid)?,part,part]).map_err(sql)?;
                    if changed != 1 {
                        return Err(invalid("output part has no exact in-flight predecessor"));
                    }
                    return Ok(());
                }
                OutputOutcome::Unknown => ("unknown", None, None),
                OutputOutcome::Failed { .. } => ("failed", None, None),
                OutputOutcome::Retry { after_us } if *after_us > 0 => (
                    if revoked { "revoked" } else { "queued" },
                    None,
                    Some(*after_us),
                ),
                OutputOutcome::Retry { .. } => {
                    return Err(invalid("retry requires a positive deadline"));
                }
            };
            // A revoke cannot recall bytes released before it: retain Sent/Unknown.
            let failure = match outcome {
                OutputOutcome::Failed { reason } => Some(codec::encode(reason)?),
                _ => None,
            };
            let changed = c.execute("UPDATE channel_outbox SET provider_messages=CASE WHEN ?='sent' AND json_array_length(provider_messages)=0 THEN json_array(?) ELSE provider_messages END,state=?,provider_message=?,retry_at_us=?,last_seq=?,failure=? WHERE connection_id=? AND output_id=? AND attempt=? AND state='sending'",crate::sql_value::sql_params![status,provider,status,provider,retry,seq,failure,state.id.as_str(),output,attempt]).map_err(sql)?;
            if changed != 1 {
                return Err(invalid("outbox completion has no owned in-flight attempt"));
            }
            if matches!(outcome, OutputOutcome::Failed { .. }) && !revoked {
                let reply:Option<(Vec<u8>,Vec<u8>)>=c.query_row("SELECT original_id,reply_id FROM channel_outbox WHERE output_id=? AND kind='reply'",[output],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?))).optional().map_err(sql)?;
                if let Some((original, reply)) = reply {
                    enqueue(c, state, Some(&original), Some(&reply), "reply_failed", seq)?;
                }
            }
        }
        _ => return Err(invalid("channel update dispatch")),
    }
    Ok(())
}

/// Called in the reply's own mail transaction. Only the exact approved recipient
/// replying to the exact Owner's original channel mail creates private output.
pub(crate) fn enqueue_reply(
    c: &Connection,
    h: &EventHeader,
    message: &[u8],
    reply: Option<&[u8]>,
    seq: i64,
) -> StoreResult<()> {
    if connection::info(c)?.schema_version < 6 {
        return Ok(());
    }
    let (Actor::Agent(agent), Some(original)) = (&h.actor, reply) else {
        return Ok(());
    };
    let p = project_id(c, &h.scope, false)?;
    let rows: Vec<String> = c.prepare_cached("SELECT cc.state_json FROM channel_connections cc JOIN channel_updates u ON u.connection_id=cc.id WHERE cc.project_id=? AND cc.active=1 AND u.message_id=? AND u.receipt_id IS NOT NULL").map_err(sql)?.query_map(crate::sql_value::sql_params![p,original], |r| crate::sql_value::value(r, 0)).map_err(sql)?.collect::<Result<_,_>>().map_err(sql)?;
    for row in rows {
        let state: ChannelConnection = serde_json::from_str(&row).map_err(invalid)?;
        if state.target.agent != *agent || !matches!(state.pairing, Pairing::Paired { .. }) {
            continue;
        }
        let owner = key(c, "human", state.owner.as_str(), &[0], false)?;
        let correct_recipient: bool = c
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM message_data WHERE event_seq=? AND recipient_id=?)",
                crate::sql_value::sql_params![seq, owner],
                |r| crate::sql_value::value(r, 0),
            )
            .map_err(sql)?;
        if !correct_recipient {
            continue;
        }
        c.execute("UPDATE channel_updates SET status_due_at_us=NULL WHERE connection_id=? AND message_id=?",crate::sql_value::sql_params![state.id.as_str(),original]).map_err(sql)?;
        let pending: i64 = c.query_row("SELECT count(*) FROM channel_outbox WHERE connection_id=? AND state IN ('queued','sending')", [state.id.as_str()], |r|crate::sql_value::value(r, 0)).map_err(sql)?;
        // Retain the reply even when the transport queue is full, with a visible
        // failed entry instead of rejecting the agent's ordinary mail commit.
        let status = if pending >= crate::channel::MAX_PENDING as i64 {
            "failed"
        } else {
            "queued"
        };
        enqueue(c, &state, Some(original), Some(message), "reply", seq)?;
        if status == "failed" {
            c.execute(
                "UPDATE channel_outbox SET state='failed',failure=? WHERE connection_id=? AND reply_id=?",
                crate::sql_value::sql_params![codec::encode(&se_types::MessagingChannelError::QueueFull)?,state.id.as_str(), message],
            )
            .map_err(sql)?;
        }
    }
    Ok(())
}

pub(super) fn enqueue(
    c: &Connection,
    state: &ChannelConnection,
    original: Option<&[u8]>,
    reply: Option<&[u8]>,
    kind: &str,
    seq: i64,
) -> StoreResult<()> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(state.id.as_str());
    hash.update(kind);
    hash.update(original.unwrap_or_default());
    hash.update(reply.unwrap_or_default());
    let id = format!("cho-{}", se_types::hex_lower(&hash.finalize()[..16]));
    let pending:i64=c.query_row("SELECT count(*) FROM(SELECT 1 FROM channel_outbox WHERE connection_id=? AND state IN ('queued','sending') LIMIT ?)",crate::sql_value::sql_params![state.id.as_str(),crate::channel::MAX_PENDING as i64],|r|crate::sql_value::value(r,0)).map_err(sql)?;
    let status = if pending >= crate::channel::MAX_PENDING as i64 {
        "failed"
    } else {
        "queued"
    };
    let failure = if status == "failed" {
        Some(codec::encode(&se_types::MessagingChannelError::QueueFull)?)
    } else {
        None
    };
    c.execute("INSERT INTO channel_outbox(output_id,connection_id,binding_revision,kind,original_id,reply_id,queued_seq,last_seq,state,failure) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(output_id) DO NOTHING",crate::sql_value::sql_params![id,state.id.as_str(),state.revision,kind,original,reply,seq,seq,status,failure]).map_err(sql)?;
    Ok(())
}

pub(crate) fn enqueue_mark(
    c: &Connection,
    h: &EventHeader,
    message: &se_types::MessageId,
    kind: &str,
    seq: i64,
) -> StoreResult<()> {
    if connection::info(c)?.schema_version < 6 {
        return Ok(());
    }
    let p = project_id(c, &h.scope, false)?;
    let scope = scope_key(c, &h.scope, false)?;
    let message = key(c, "message", message.as_str(), &scope, false)?;
    let rows:Vec<String>=c.prepare_cached("SELECT cc.state_json FROM channel_updates u JOIN channel_connections cc ON cc.id=u.connection_id WHERE cc.project_id=? AND cc.active=1 AND u.message_id=? AND u.receipt_id IS NOT NULL").map_err(sql)?.query_map(crate::sql_value::sql_params![p,message],|r|r.get(0)).map_err(sql)?.collect::<Result<_,_>>().map_err(sql)?;
    for row in rows {
        let state: ChannelConnection = serde_json::from_str(&row).map_err(invalid)?;
        if matches!(state.pairing, Pairing::Paired { .. }) {
            if matches!(kind, "read" | "dismiss") {
                c.execute(
                    "UPDATE channel_updates SET pending=0 WHERE connection_id=? AND message_id=?",
                    crate::sql_value::sql_params![state.id.as_str(), message],
                )
                .map_err(sql)?;
            }
            if kind != "dismiss" {
                enqueue(c, &state, Some(&message), None, kind, seq)?;
            }
        }
    }
    Ok(())
}

fn enqueue_rejected(
    c: &Connection,
    state: &ChannelConnection,
    update: &crate::channel::ExternalId,
    legacy: bool,
    seq: i64,
) -> StoreResult<()> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(state.id.as_str());
    hash.update(b"rejected");
    if legacy {
        hash.update(
            update
                .as_str()
                .parse::<i64>()
                .map_err(invalid)?
                .to_be_bytes(),
        );
    } else {
        hash.update(update.as_str().as_bytes());
    }
    let id = format!("cho-{}", se_types::hex_lower(&hash.finalize()[..16]));
    let pending:i64=c.query_row("SELECT count(*) FROM(SELECT 1 FROM channel_outbox WHERE connection_id=? AND state IN ('queued','sending') LIMIT ?)",crate::sql_value::sql_params![state.id.as_str(),crate::channel::MAX_PENDING as i64],|r|crate::sql_value::value(r,0)).map_err(sql)?;
    let status = if pending >= crate::channel::MAX_PENDING as i64 {
        "failed"
    } else {
        "queued"
    };
    let failure = if status == "failed" {
        Some(codec::encode(&se_types::MessagingChannelError::QueueFull)?)
    } else {
        None
    };
    c.execute("INSERT INTO channel_outbox(output_id,connection_id,binding_revision,kind,provider_update,queued_seq,last_seq,state,failure) VALUES(?,?,?,'rejected',?,?,?,?,?) ON CONFLICT(output_id) DO NOTHING",crate::sql_value::sql_params![id,state.id.as_str(),state.revision,update,seq,seq,status,failure]).map_err(sql)?;
    Ok(())
}

fn checkpoint(
    c: &Connection,
    state: &ChannelConnection,
    cursor: &str,
    legacy: bool,
) -> StoreResult<()> {
    // Only historical integer events lack a cursor. Preserve their old maximum
    // during replay; modern connector cursors are opaque and never compared.
    c.execute("INSERT INTO channel_receive(connector,bot_id,cursor) VALUES(?,?,?) ON CONFLICT(connector,bot_id) DO UPDATE SET cursor=CASE WHEN ? AND CAST(excluded.cursor AS INTEGER)<CAST(channel_receive.cursor AS INTEGER) THEN channel_receive.cursor ELSE excluded.cursor END", rusqlite::params![state.connector.as_str(),state.bot.id,cursor,legacy]).map_err(sql)?;
    Ok(())
}
