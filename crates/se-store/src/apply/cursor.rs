//! Context and mail cursors. Issuance records the exact snapshot window it
//! presented; only an acknowledgment with consumer evidence marks that exact
//! cursor read. Neither can turn an incomplete window into a complete one.
use super::*;
use se_types::{Cursor, Window, WindowFields};
/// The window's accounting facts, which its public wire form omits.
pub(crate) fn window_facts(window: &Window) -> StoreResult<Value> {
    let f = window
        .fields()
        .ok_or_else(|| invalid("a recorded cursor needs its snapshot window bounds"))?;
    Ok(serde_json::json!({
        "source": f.source,
        "from": f.from,
        "to": f.to,
        "start_cursor": f.start_cursor,
        "end_cursor": f.end_cursor,
        "returned": f.returned,
        "limit": f.limit.get(),
        "bytes": f.bytes,
        "max_bytes": f.max_bytes.get(),
        "omitted_before": f.omitted_before,
        "omitted_after": f.omitted_after,
        "unreadable": f.unreadable,
        "stop_reason": f.stop_reason,
    }))
}
fn window_from(v: &Value) -> StoreResult<Window> {
    let nonzero = |k: &str| -> StoreResult<std::num::NonZeroU32> {
        std::num::NonZeroU32::new(codec::field::<u32>(v, k)?)
            .ok_or_else(|| invalid(format!("stored window {k} is zero")))
    };
    Window::new(WindowFields {
        source: codec::field(v, "source")?,
        from: codec::field(v, "from")?,
        to: codec::field(v, "to")?,
        start_cursor: codec::field(v, "start_cursor")?,
        end_cursor: codec::field(v, "end_cursor")?,
        returned: codec::field(v, "returned")?,
        limit: nonzero("limit")?,
        bytes: codec::field(v, "bytes")?,
        max_bytes: nonzero("max_bytes")?,
        omitted_before: codec::field(v, "omitted_before")?,
        omitted_after: codec::field(v, "omitted_after")?,
        unreadable: codec::field(v, "unreadable")?,
        stop_reason: codec::field(v, "stop_reason")?,
    })
    .map_err(invalid)
}
pub(crate) fn metadata(record: &CursorRecord) -> StoreResult<Value> {
    Ok(serde_json::json!({
        "id": record.id,
        "agent": record.agent,
        "purpose": record.purpose,
        "value": record.value,
        "window": window_facts(&record.window)?,
        "expected": record.expected,
    }))
}
pub(crate) fn decode(v: &Value) -> StoreResult<CursorRecord> {
    Ok(CursorRecord {
        id: codec::field(v, "id")?,
        agent: codec::field(v, "agent")?,
        purpose: codec::field(v, "purpose")?,
        value: codec::field::<Cursor>(v, "value")?,
        window: window_from(
            v.get("window")
                .ok_or_else(|| invalid("stored cursor window missing"))?,
        )?,
        expected: codec::field(v, "expected")?,
    })
}
pub(super) fn revision(c: &Connection, e: &NewEvent) -> StoreResult<u64> {
    let p = project_id(c, &e.header.scope, false)?;
    let s = scope_key(c, &e.header.scope, false)?;
    match &e.body {
        EventBody::CursorRecorded { cursor } => {
            let a = key(c, "agent", cursor.agent.as_str(), &s, false)?;
            expected(
                c,
                "cursors",
                "project_id=? AND agent_id=? AND purpose=?",
                &[&p, &a, &cursor.purpose],
                cursor.expected,
            )
        }
        // A superseded or foreign cursor ID is not the current head: refused.
        EventBody::CursorAcknowledged {
            cursor,
            expected: want,
            ..
        } => expected(
            c,
            "cursors",
            "project_id=? AND cursor_id=?",
            &[&p, &cursor.as_bytes().as_slice()],
            Expected::Revision(*want),
        ),
        _ => Err(invalid("cursor revision dispatch")),
    }
}
/// The last item an issued window actually returned, from its own store
/// end cursor; None when the window carries no store-issued end cursor.
fn confirmed_end(c: &Connection, issued: i64) -> StoreResult<Option<u64>> {
    let v = codec::facts(c, issued)?;
    let end: Option<Cursor> = v
        .get("cursor")
        .and_then(|cursor| cursor.get("window"))
        .and_then(|window| window.get("end_cursor"))
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(invalid)?
        .flatten();
    let Some(end) = end else { return Ok(None) };
    match checked_end(c, &end) {
        Ok(end) => Ok(Some(end)),
        Err(error)
            if matches!(
                error.code,
                StoreErrorCode::CursorInvalid | StoreErrorCode::CursorStale
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}
fn checked_end(c: &Connection, end: &Cursor) -> StoreResult<u64> {
    let (store, incarnation): (Vec<u8>, u64) = c
        .query_row(
            "SELECT store_id,incarnation FROM store_info WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, crate::sql_value::value(r, 1)?)),
        )
        .map_err(sql)?;
    crate::read::checked_window_end(end.as_str(), &store, incarnation)
}
/// The window's snapshot bounds as stored columns: (from, to, returned, complete, omitted).
fn bounds(window: &Window) -> StoreResult<(u64, u64, u64, bool, Option<u64>)> {
    let f = window
        .fields()
        .ok_or_else(|| invalid("a recorded cursor needs its snapshot window bounds"))?;
    Ok((
        f.from.get(),
        f.to.get(),
        f.returned,
        window.complete(),
        window.omitted().count,
    ))
}
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    facts: Value,
) -> StoreResult<()> {
    let p = project_id(c, &h.scope, false)?;
    let s = scope_key(c, &h.scope, false)?;
    let agent = match body {
        EventBody::CursorRecorded { cursor } => {
            let purpose_ok = !cursor.purpose.is_empty()
                && cursor.purpose.len() <= 128
                && cursor
                    .purpose
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
            if !purpose_ok || cursor.value.as_str().len() > 192 {
                return Err(invalid("cursor purpose grammar or value bounds"));
            }
            let a = key(c, "agent", cursor.agent.as_str(), &s, false)?;
            permitted(c, h, &p, &cursor.agent, &a)?;
            let (from, to, returned, complete, omitted) = bounds(&cursor.window)?;
            // A store-backed window must name this store and this project.
            if let Some(se_types::Source::Store { store, project }) =
                cursor.window.fields().map(|f| &f.source)
            {
                let this: Vec<u8> = c
                    .query_row(
                        "SELECT store_id FROM store_info WHERE singleton=1",
                        [],
                        |r| r.get(0),
                    )
                    .map_err(sql)?;
                let scoped = matches!(&h.scope, Scope::Project(id) if project.as_ref() == Some(id));
                if canonical(store.as_str()).as_deref() != Some(this.as_slice()) || !scoped {
                    return Err(fail(
                        StoreErrorCode::ScopeMismatch,
                        "cursor window names another store or project",
                    ));
                }
            }
            // Validate a supplied opaque end when issuing, before it can become
            // durable cursor history. Later frontier fallback is not admission.
            if let Some(end) = cursor.window.fields().and_then(|f| f.end_cursor.as_ref()) {
                let end = checked_end(c, end)?;
                if !(from..=to).contains(&end) {
                    return Err(fail(
                        StoreErrorCode::CursorInvalid,
                        "cursor end is outside its window bounds",
                    ));
                }
            }
            // The window cannot claim events this store has not committed.
            if to >= seq as u64 {
                return Err(invalid(
                    "cursor window extends past the committed store head",
                ));
            }
            // A new window may re-read, but never start past work its
            // predecessor did not confirm: after an ack, past that window's
            // last returned item; before one, past the unacknowledged start.
            let prior: Option<(i64, u64, u64, bool, Option<i64>)> = c
                .query_row(
                    "SELECT d.event_seq,d.from_seq,d.to_seq,d.complete,h.acknowledged_seq FROM cursors h JOIN cursor_data d ON d.cursor_id=h.cursor_id AND d.acknowledged_event IS NULL WHERE h.project_id=? AND h.agent_id=? AND h.purpose=?",
                    rusqlite::params![p, a, cursor.purpose],
                    |r| {
                        Ok((
                            r.get(0)?,
                            crate::sql_value::value(r, 1)?,
                            crate::sql_value::value(r, 2)?,
                            r.get(3)?,
                            r.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(sql)?;
            if let Some((issued, prior_from, prior_to, complete, acked)) = prior {
                // A complete window returned everything up to `to`. An
                // incomplete one confirms its last returned item, clamped into
                // its own bounds, or only `from` without this store's cursor.
                let limit = match (acked, complete) {
                    (None, _) => prior_from,
                    (Some(_), true) => prior_to,
                    (Some(_), false) => confirmed_end(c, issued)?
                        .map_or(prior_from, |last| last.clamp(prior_from, prior_to)),
                };
                if from > limit {
                    return Err(fail(
                        StoreErrorCode::InvalidTransition,
                        format!(
                            "cursor window would skip unconfirmed work: it must start at or before {limit}"
                        ),
                    ));
                }
            }
            let id = cursor.id.as_bytes().to_vec();
            let reused: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM cursor_data d CROSS JOIN events e ON e.seq=d.event_seq WHERE e.project_id=? AND d.cursor_id=?)",
                    rusqlite::params![p, id],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            if reused {
                return Err(fail(
                    StoreErrorCode::NaturalKeyConflict,
                    "cursor ID was already issued; issue a fresh cursor",
                ));
            }
            let expected = match cursor.expected {
                Expected::Absent => None,
                Expected::Revision(r) => Some(r.value.get()),
            };
            c.execute(
                "INSERT INTO cursor_data(event_seq,cursor_id,agent_id,purpose,value,expected_revision,from_seq,to_seq,returned,complete,omitted,acknowledged_event) VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL)",
                crate::sql_value::sql_params![seq, id, a, cursor.purpose, cursor.value.as_str().as_bytes().to_vec(), expected, from, to, returned, complete, omitted],
            )
            .map_err(sql)?;
            let changed = c
                .execute(
                    "INSERT INTO cursors(project_id,agent_id,purpose,cursor_id,revision,last_seq,acknowledged_seq) VALUES(?,?,?,?,?,?,NULL)
                     ON CONFLICT(project_id,agent_id,purpose) DO UPDATE SET cursor_id=excluded.cursor_id,revision=excluded.revision,last_seq=excluded.last_seq,acknowledged_seq=NULL
                     WHERE cursors.revision=excluded.revision-1",
                    crate::sql_value::sql_params![p, a, cursor.purpose, id, rev, seq],
                )
                .map_err(sql)?;
            if changed != 1 {
                return Err(fail(
                    StoreErrorCode::RevisionConflict,
                    "cursor head changed",
                ));
            }
            a
        }
        EventBody::CursorAcknowledged {
            cursor, evidence, ..
        } => {
            session::reference(c, &p, &s, &evidence)?;
            let id = cursor.as_bytes().to_vec();
            let (a, last, acknowledged): (Vec<u8>, i64, Option<i64>) = c
                .query_row(
                    "SELECT agent_id,last_seq,acknowledged_seq FROM cursors WHERE project_id=? AND cursor_id=?",
                    rusqlite::params![p, id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .map_err(sql)?;
            if acknowledged.is_some() {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "this cursor was already acknowledged",
                ));
            }
            let evidence_seq: Option<i64> = c
                .query_row(
                    "SELECT seq FROM events WHERE project_id=? AND event_id=?",
                    rusqlite::params![p, key(c, "event", evidence.as_str(), &s, false)?],
                    |r| r.get(0),
                )
                .optional()
                .map_err(sql)?;
            if evidence_seq.is_none_or(|e| e <= last) {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "acknowledgment evidence must be committed after the cursor was issued",
                ));
            }
            let agent = wire(c, "agent", &a, &s)?.try_into().map_err(invalid)?;
            permitted(c, h, &p, &agent, &a)?;
            let evidence_key = key(c, "event", evidence.as_str(), &s, false)?;
            c.execute(
                "INSERT INTO cursor_data(event_seq,cursor_id,agent_id,purpose,value,expected_revision,from_seq,to_seq,returned,complete,omitted,acknowledged_event)
                 SELECT ?,cursor_id,agent_id,purpose,value,?,from_seq,to_seq,returned,complete,omitted,? FROM cursor_data WHERE event_seq=?",
                crate::sql_value::sql_params![seq, rev - 1, evidence_key, last],
            )
            .map_err(sql)?;
            let changed = c
                .execute(
                    "UPDATE cursors SET revision=?,last_seq=?,acknowledged_seq=? WHERE project_id=? AND cursor_id=? AND revision=?",
                    crate::sql_value::sql_params![rev, seq, seq, p, id, rev - 1],
                )
                .map_err(sql)?;
            if changed != 1 {
                return Err(fail(
                    StoreErrorCode::RevisionConflict,
                    "cursor head changed",
                ));
            }
            a
        }
        _ => return Err(invalid("cursor apply dispatch")),
    };
    let changed = c
        .execute(
            "UPDATE resume_heads SET last_cursor_seq=?,last_seq=? WHERE project_id=? AND principal_id=?",
            crate::sql_value::sql_params![seq, seq, p, agent],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "cursor agent resume head absent",
        ));
    }
    codec::aux(c, seq, facts)
}
/// The agent itself or its owner records and acknowledges its cursors.
fn permitted(
    c: &Connection,
    h: &EventHeader,
    p: &[u8],
    agent: &se_types::AgentId,
    a: &[u8],
) -> StoreResult<()> {
    let ok = match &h.actor {
        Actor::Agent(actor) => actor == agent,
        Actor::Human(human) => {
            let owner: Option<Vec<u8>> = c
                .query_row(
                    "SELECT owner_id FROM principals WHERE project_id=? AND principal_id=? AND principal_kind='agent'",
                    rusqlite::params![p, a],
                    |r| r.get(0),
                )
                .optional()
                .map_err(sql)?;
            owner == Some(key(c, "human", human.as_str(), &[0], false)?)
        }
    };
    if ok {
        Ok(())
    } else {
        Err(fail(
            StoreErrorCode::ScopeMismatch,
            "cursor actor differs from its agent and owner",
        ))
    }
}
