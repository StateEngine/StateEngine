pub(crate) mod event;
// Closed wave-1 metadata codec; text lives only in its typed payload column.
use crate::{error::*, identity::*, *};
use rusqlite::{Connection, params};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
pub(crate) fn encode<T: Serialize>(v: &T) -> StoreResult<String> {
    serde_json::to_string(v).map_err(invalid)
}
pub(crate) fn field<T: DeserializeOwned>(v: &Value, k: &str) -> StoreResult<T> {
    serde_json::from_value(
        v.get(k)
            .cloned()
            .ok_or_else(|| invalid(format!("missing stored field {k}")))?,
    )
    .map_err(invalid)
}
pub(crate) fn aux(c: &Connection, seq: i64, v: Value) -> StoreResult<()> {
    c.execute(
        "INSERT INTO aux_data(event_seq,facts) VALUES(?,?)",
        crate::sql_value::sql_params![seq, encode(&v)?],
    )
    .map_err(sql)?;
    Ok(())
}
pub(crate) fn facts(c: &Connection, seq: i64) -> StoreResult<Value> {
    let s: String = c
        .query_row("SELECT facts FROM aux_data WHERE event_seq=?", [seq], |r| {
            crate::sql_value::value(r, 0)
        })
        .map_err(sql)?;
    serde_json::from_str(&s).map_err(invalid)
}
pub(crate) fn text(input: InputText, max: usize) -> StoreResult<String> {
    let s = match input {
        InputText::Inline(s) => s,
        InputText::Staged(_) => return later("staged capture text"),
    };
    if s.len() > max {
        return Err(fail(
            StoreErrorCode::BodyTooLarge,
            format!("text is {} bytes; limit {max}", s.len()),
        ));
    }
    Ok(s)
}
pub(crate) fn stored_text(c: &Connection, seq: i64, field: &str) -> StoreResult<StoredText> {
    let bytes: Vec<u8> = c
        .query_row(
            "SELECT content FROM payloads WHERE event_seq=? AND field=?",
            crate::sql_value::sql_params![seq, field],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    Ok(StoredText::Present(
        String::from_utf8(bytes).map_err(invalid)?,
    ))
}
pub(crate) fn body(
    c: &Connection,
    seq: i64,
    kind: &str,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    Ok(match kind {
        "message.sent" => {
            let (message,recipient,kind,refs,reply):(Vec<u8>,Vec<u8>,String,String,Option<Vec<u8>>)=c.query_row("SELECT message_id,recipient_id,message_kind,refs,reply_to FROM message_data WHERE event_seq=?",[seq],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?,crate::sql_value::value(r,3)?,crate::sql_value::value(r,4)?))).map_err(sql)?;
            let s = scope_key(c, scope, false)?;
            MessageSent {
                message: wire(c, "message", &message, &s)?.parse().map_err(invalid)?,
                recipient: actor(c, &recipient, &s)?,
                kind,
                body: stored_text(c, seq, "body")?,
                refs: serde_json::from_str(&refs).map_err(invalid)?,
                reply_to: reply
                    .map(|v| wire(c, "message", &v, &s).and_then(|v| v.parse().map_err(invalid)))
                    .transpose()?,
            }
        }
        "message.read" | "message.dismissed" | "message.delivered" => {
            let (message,recipient,evidence):(Vec<u8>,Vec<u8>,Option<Vec<u8>>)=c.query_row("SELECT d.message_id,m.recipient_id,m.evidence_event FROM mark_data m JOIN message_data d ON d.event_seq=m.message_seq WHERE m.event_seq=?",[seq],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?))).map_err(sql)?;
            let s = scope_key(c, scope, false)?;
            let message = wire(c, "message", &message, &s)?.parse().map_err(invalid)?;
            let recipient = actor(c, &recipient, &s)?;
            match kind {
                "message.read" => MessageRead { message, recipient },
                "message.dismissed" => MessageDismissed { message, recipient },
                _ => MessageDelivered {
                    message,
                    recipient,
                    evidence: wire(
                        c,
                        "event",
                        &evidence.ok_or_else(|| invalid("delivered without evidence"))?,
                        &s,
                    )?
                    .parse()
                    .map_err(invalid)?,
                },
            }
        }
        "working_state.set" => {
            let (agent, expected): (Vec<u8>, Option<u64>) = c
                .query_row(
                    "SELECT agent_id,expected_revision FROM working_state_data WHERE event_seq=?",
                    [seq],
                    |r| {
                        Ok((
                            crate::sql_value::value(r, 0)?,
                            crate::sql_value::value(r, 1)?,
                        ))
                    },
                )
                .map_err(sql)?;
            WorkingStateSet {
                agent: wire(c, "agent", &agent, &scope_key(c, scope, false)?)?
                    .parse()
                    .map_err(invalid)?,
                text: stored_text(c, seq, "body")?,
                expected: expected
                    .map(revision)
                    .transpose()?
                    .map(Expected::Revision)
                    .unwrap_or(Expected::Absent),
            }
        }
        "decision.proposed"
        | "decision.ratified"
        | "decision.rejected"
        | "decision.retracted"
        | "decision.superseded" => crate::apply::decision::decode(c, seq, kind, scope)?,
        _ => {
            let v = facts(c, seq)?;
            match kind {
                "project.registered" => ProjectRegistered {
                    project: field(&v, "project")?,
                    name: field(&v, "name")?,
                    roots: field(&v, "roots")?,
                    owner: field(&v, "owner")?,
                    history_from: field(&v, "history_from")?,
                    expected: field(&v, "expected")?,
                },
                "principal.registered" => PrincipalRegistered {
                    principal: field(&v, "principal")?,
                    kind: field(&v, "kind")?,
                    owner: field(&v, "owner")?,
                    created_by: field(&v, "created_by")?,
                    name: field(&v, "name")?,
                    role: field(&v, "role")?,
                    expected: field(&v, "expected")?,
                },
                "principal.renamed" => PrincipalRenamed {
                    principal: field(&v, "principal")?,
                    name: field(&v, "name")?,
                    expected: field(&v, "expected")?,
                },
                "profile.saved" => ProfileSaved {
                    agent: field(&v, "agent")?,
                    profile: field(&v, "profile")?,
                    expected: field(&v, "expected")?,
                },
                "grant.recorded" => GrantRecorded {
                    principal: field(&v, "principal")?,
                    key: field(&v, "key")?,
                    active: field(&v, "active")?,
                    expected: field(&v, "expected")?,
                },
                "runtime.owner" => RuntimeOwnerEstablished {
                    epoch: field(&v, "epoch")?,
                    generation: field(&v, "generation")?,
                    expected_owner_generation: field(&v, "expected_owner_generation")?,
                    expected: field(&v, "expected")?,
                    witnesses: field(&v, "witnesses")?,
                    recovered: None,
                },
                _ => {
                    return Err(fail(
                        StoreErrorCode::Unreadable,
                        format!("unsupported stored event kind {kind}"),
                    ));
                }
            }
        }
    })
}
pub(crate) fn revision(value: u64) -> StoreResult<Revision> {
    if value > i64::MAX as u64 {
        return Err(invalid("entity revision exceeds store range"));
    }
    Ok(Revision {
        value: std::num::NonZeroU64::new(value).ok_or_else(|| invalid("zero entity revision"))?,
    })
}
pub(crate) fn metadata<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    use EventBody::*;
    Ok(match body {
        ProjectRegistered {
            project,
            name,
            roots,
            owner,
            history_from,
            expected,
        } => (
            "project.registered",
            json!({"project":project,"name":name,"roots":roots,"owner":owner,"history_from":history_from,"expected":expected}),
        ),
        PrincipalRegistered {
            principal,
            kind,
            owner,
            created_by,
            name,
            role,
            expected,
        } => (
            "principal.registered",
            json!({"principal":principal,"kind":kind,"owner":owner,"created_by":created_by,"name":name,"role":role,"expected":expected}),
        ),
        PrincipalRenamed {
            principal,
            name,
            expected,
        } => (
            "principal.renamed",
            json!({"principal":principal,"name":name,"expected":expected}),
        ),
        ProfileSaved {
            agent,
            profile,
            expected,
        } => (
            "profile.saved",
            json!({"agent":agent,"profile":profile,"expected":expected}),
        ),
        GrantRecorded {
            principal,
            key,
            active,
            expected,
        } => (
            "grant.recorded",
            json!({"principal":principal,"key":key,"active":active,"expected":expected}),
        ),
        MessageSent { .. } => ("message.sent", Value::Null),
        MessageRead { .. } => ("message.read", Value::Null),
        MessageDismissed { .. } => ("message.dismissed", Value::Null),
        MessageDelivered { .. } => ("message.delivered", Value::Null),
        WorkingStateSet { .. } => ("working_state.set", Value::Null),
        RuntimeOwnerEstablished {
            epoch,
            generation,
            expected_owner_generation,
            expected,
            witnesses,
            recovered,
        } if recovered.is_none() => (
            "runtime.owner",
            json!({"epoch":epoch,"generation":generation,"expected_owner_generation":expected_owner_generation,"expected":expected,"witnesses":witnesses}),
        ),
        DecisionProposed { .. } => ("decision.proposed", Value::Null),
        DecisionRatified { .. } => ("decision.ratified", Value::Null),
        DecisionRejected { .. } => ("decision.rejected", Value::Null),
        DecisionRetracted { .. } => ("decision.retracted", Value::Null),
        DecisionSuperseded { .. } => ("decision.superseded", Value::Null),
        _ => return later("this event kind"),
    })
}
