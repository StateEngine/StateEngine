use super::*;
use crate::codec::capture::{consent, provider, role};
use se_types::{AgentId, SessionId};
pub(super) fn revision(c: &Connection, e: &NewEvent) -> StoreResult<u64> {
    let (source, want) = match &e.body {
        EventBody::SessionTurn { .. }
        | EventBody::CaptureFailed { .. }
        | EventBody::CaptureVerified { .. } => return Ok(1),
        EventBody::CaptureSource {
            source, expected, ..
        }
        | EventBody::CaptureProgress {
            source, expected, ..
        }
        | EventBody::CaptureSuppressed {
            source, expected, ..
        } => (source, *expected),
        _ => return Err(invalid("capture revision dispatch")),
    };
    let p = project_id(c, &e.header.scope, false)?;
    expected(
        c,
        "capture_sources",
        "project_id=? AND source_id=?",
        &[&p, &source.as_bytes().as_slice()],
        want,
    )
}
pub(crate) fn canonicalize(c: &Connection, batch: &mut AtomicBatch) -> StoreResult<()> {
    let mut ids = Vec::new();
    for e in &mut batch.events {
        if matches!(e.body, EventBody::SessionTurn { .. })
            && let Some(seq) = codec::capture::natural(c, e)?
        {
            let (retained, session): (Vec<u8>, Vec<u8>) = c
                .query_row(
                    "SELECT turn_id,session_id FROM turn_data WHERE event_seq=?",
                    [seq],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(sql)?;
            if let EventBody::SessionTurn {
                turn,
                session: current,
                evidence,
                ..
            } = &mut e.body
            {
                let actual = codec::capture::record(retained)?;
                let scope = scope_key(c, &e.header.scope, false)?;
                let replay = (key(c, "session", current.as_str(), &scope, false)? != session)
                    .then(|| evidence.clone());
                ids.push((*turn, actual, replay));
                *turn = actual;
            }
        }
    }
    for e in &mut batch.events {
        if let EventBody::CaptureProgress {
            last_turn,
            replay_evidence,
            ..
        } = &mut e.body
            && let Some((_, actual, replay)) = ids.iter().find(|(draft, _, _)| draft == last_turn)
        {
            *last_turn = *actual;
            *replay_evidence = replay.clone();
        }
    }
    Ok(())
}
pub(crate) fn validate_batch(c: &Connection, batch: &AtomicBatch) -> StoreResult<()> {
    use EventBody::*;
    let mut turns = Vec::new();
    for e in &batch.events {
        if let SessionTurn {
            session,
            provider,
            vendor_ref,
            ..
        } = &e.body
        {
            if turns
                .iter()
                .any(|key| key == &(session, provider, vendor_ref))
            {
                return Err(fail(
                    StoreErrorCode::NaturalKeyConflict,
                    "duplicate native turn identity in one new capture batch",
                ));
            }
            turns.push((session, provider, vendor_ref));
        }
    }
    let progress: Vec<_> = batch
        .events
        .iter()
        .filter_map(|e| match &e.body {
            CaptureProgress {
                source,
                incarnation,
                old_offset,
                new_offset,
                last_turn,
                replay_evidence,
                ..
            } => Some((
                source,
                incarnation,
                *old_offset,
                *new_offset,
                last_turn,
                replay_evidence,
            )),
            _ => None,
        })
        .collect();
    for (source, incarnation, old, new, last, replay) in &progress {
        if new <= old || *new > i64::MAX as u64 {
            return Err(invalid("capture progress must advance a bounded offset"));
        }
        let selected = batch
            .events
            .iter()
            .find_map(|e| match &e.body {
                SessionTurn {
                    turn,
                    session,
                    evidence,
                    ..
                } if turn == *last => Some((session, evidence)),
                _ => None,
            })
            .ok_or_else(|| {
                fail(
                    StoreErrorCode::ReferenceMissing,
                    "capture progress requires its last turn in the same atomic batch",
                )
            })?;
        if replay.as_ref().is_some_and(|range| range != selected.1)
            || &selected.1.incarnation != *incarnation
            || selected.1.offset.checked_add(selected.1.length) != Some(*new)
        {
            return Err(fail(
                StoreErrorCode::SourceChanged,
                "capture progress does not end at its last turn evidence",
            ));
        }
        let (bound, _) = source_binding(c, batch, source)?;
        if bound != *selected.0 {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "capture progress last turn belongs to another session",
            ));
        }
    }
    for e in &batch.events {
        if let SessionTurn {
            session, evidence, ..
        } = &e.body
        {
            let end = evidence
                .offset
                .checked_add(evidence.length)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or_else(|| invalid("turn source range overflow"))?;
            let mut matches = 0;
            for (source, incarnation, old, new, _, _) in &progress {
                if evidence.incarnation == **incarnation
                    && evidence.offset >= *old
                    && end <= *new
                    && source_binding(c, batch, source)?.0 == *session
                {
                    matches += 1;
                }
            }
            if matches != 1 {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "each captured turn needs exactly one matching same-batch progress event",
                ));
            }
        }
    }
    Ok(())
}
fn source_binding(
    c: &Connection,
    batch: &AtomicBatch,
    source: &RecordId,
) -> StoreResult<(SessionId, Vec<u8>)> {
    if let Some((session, incarnation)) = batch.events.iter().find_map(|e| match &e.body {
        EventBody::CaptureSource {
            source: id,
            session,
            incarnation,
            ..
        } if id == source => Some((session.clone(), incarnation.clone())),
        _ => None,
    }) {
        return Ok((session, incarnation));
    }
    let p = project_id(c, &batch.admission.scope, false)?;
    let scope = scope_key(c, &batch.admission.scope, false)?;
    let (session, incarnation): (Vec<u8>, Vec<u8>) = c
        .query_row(
            "SELECT session_id,source_incarnation FROM capture_sources
             WHERE project_id=? AND source_id=?",
            rusqlite::params![p, source.as_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql)?
        .ok_or_else(|| {
            fail(
                StoreErrorCode::ReferenceMissing,
                format!(
                    "capture source {} is absent",
                    uuid::Uuid::from_bytes(*source.as_bytes())
                ),
            )
        })?;
    Ok((
        wire(c, "session", &session, &scope)?
            .try_into()
            .map_err(invalid)?,
        incarnation,
    ))
}
fn bound_session(
    c: &Connection,
    p: &[u8],
    scope: &[u8],
    session: &SessionId,
    h: &EventHeader,
    initial_source: bool,
) -> StoreResult<(Vec<u8>, crate::codec::session::SessionHead)> {
    let id = key(c, "session", session.as_str(), scope, false)?;
    let head = codec::session::head(c, p, &id)?;
    let agent: AgentId = decode_agent(c, wire(c, "agent", &head.agent, scope)?, scope)?;
    if let Actor::Agent(actor) = &h.actor
        && (*actor != agent || h.session.as_ref() != Some(session))
    {
        if initial_source && *actor != agent {
            // Launch C3 registers its first source under the creator's
            // admission. Recheck direct-child control in this write; this
            // never authorizes turns, progress, or source replacement.
            crate::creator::require(c, p, scope, actor, &head.agent)?;
        } else {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "capture actor differs from the bound session agent",
            ));
        }
    }
    if !matches!(head.state.as_str(), "active" | "prepared")
        && !(h.door == Door::Import && head.state == "ended")
    {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "capture session is terminal",
        ));
    }
    Ok((id, head))
}
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    mut facts: Value,
) -> StoreResult<()> {
    use EventBody::*;
    let p = project_id(c, &h.scope, true)?;
    let scope = scope_key(c, &h.scope, true)?;
    match body {
        SessionTurn {
            turn,
            agent,
            session,
            provider: backend,
            vendor_ref,
            role: turn_role,
            text,
            evidence,
        } => {
            let (session, head) = bound_session(c, &p, &scope, &session, h, false)?;
            let a = key(c, "agent", agent.as_str(), &scope, false)?;
            if !(head.state == "active" || h.door == Door::Import && head.state == "ended")
                || head.consent != "capture"
                || head.agent != a
                || head.provider != provider(backend)
            {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "turn requires its active consented provider/agent binding",
                ));
            }
            if (evidence.path.is_none() && backend != Provider::SeCode)
                || vendor_ref.is_empty()
                || vendor_ref.len() > 4096
                || evidence.incarnation.is_empty()
                || evidence.incarnation.len() > 4096
                || evidence.length == 0
            {
                return Err(invalid("turn native reference/evidence bounds"));
            }
            let sources:u64=c.query_row("SELECT count(*) FROM capture_sources WHERE project_id=? AND session_id=? AND source_incarnation=?
                    AND consent='capture' AND byte_offset<=?",crate::sql_value::sql_params![p,session,evidence.incarnation,evidence.offset],|r|crate::sql_value::value(r,0)).map_err(sql)?;
            if sources != 1 {
                return Err(fail(
                    StoreErrorCode::SourceChanged,
                    "turn source incarnation/cursor is absent or ambiguous",
                ));
            }
            let text = codec::text(text, 1024 * 1024)?;
            let payload = payload(c, seq, "body", &text)?;
            let path = symbol(c, codec::encode(&evidence.path)?.as_bytes())?;
            c.execute("INSERT INTO turn_data(event_seq,turn_id,project_id,agent_id,session_id,provider,vendor_ref,role,text_payload,source_path,source_offset,source_length,source_sha256)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",crate::sql_value::sql_params![seq,turn.as_bytes().as_slice(),p,a,session,provider(backend),vendor_ref,role(turn_role),payload,path,evidence.offset,evidence.length,evidence.sha256.map(|s|s.to_vec())]).map_err(sql)?;
            codec::aux(
                c,
                seq,
                serde_json::json!({"source_incarnation":evidence.incarnation}),
            )?;
            let changed=c.execute("UPDATE resume_heads SET last_turn_seq=?,last_seq=? WHERE project_id=? AND principal_id=?",rusqlite::params![seq,seq,p,a]).map_err(sql)?;
            if changed != 1 {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "turn agent resume head absent",
                ));
            }
        }
        CaptureSource {
            source,
            session,
            consent: capture,
            native_ref,
            incarnation,
            ..
        } => {
            let (session, head) = bound_session(c, &p, &scope, &session, h, rev == 1)?;
            if head.consent != consent(capture)
                || native_ref.is_empty()
                || native_ref.len() > 32768
                || incarnation.is_empty()
                || incarnation.len() > 4096
            {
                return Err(invalid(
                    "source consent/native reference/incarnation bounds",
                ));
            }
            if rev == 1 {
                c.execute("INSERT INTO capture_sources(project_id,source_id,session_id,revision,last_seq,source_incarnation,byte_offset,consent,suppressed_count)
                    VALUES(?,?,?,?,?,?,0,?,0)",crate::sql_value::sql_params![p,source.as_bytes().as_slice(),session,rev,seq,incarnation,consent(capture)]).map_err(sql)?;
            } else {
                let changed=c.execute("UPDATE capture_sources SET revision=?,last_seq=?,source_incarnation=?,byte_offset=0,consent=?,suppressed_count=0
                    WHERE project_id=? AND source_id=? AND session_id=? AND revision=? AND source_incarnation<>?",crate::sql_value::sql_params![rev,seq,incarnation,consent(capture),p,source.as_bytes().as_slice(),session,rev-1,incarnation]).map_err(sql)?;
                if changed != 1 {
                    return Err(fail(
                        StoreErrorCode::SourceChanged,
                        "source rotation requires its same session and a new incarnation",
                    ));
                }
            }
            facts
                .as_object_mut()
                .ok_or_else(|| invalid("capture source metadata"))?
                .insert("project".into(), serde_json::json!(project(&h.scope)?));
            codec::aux(c, seq, facts)?;
        }
        CaptureProgress {
            source,
            incarnation,
            old_offset,
            new_offset,
            ..
        } => {
            let changed=c.execute("UPDATE capture_sources SET revision=?,last_seq=?,byte_offset=? WHERE project_id=? AND source_id=?
                    AND revision=? AND source_incarnation=? AND byte_offset=? AND consent='capture'",crate::sql_value::sql_params![rev,seq,new_offset,p,source.as_bytes().as_slice(),rev-1,incarnation,old_offset]).map_err(sql)?;
            if changed != 1 {
                return Err(fail(
                    StoreErrorCode::SourceChanged,
                    "capture progress source incarnation/offset changed",
                ));
            }
            facts
                .as_object_mut()
                .ok_or_else(|| invalid("capture progress metadata"))?
                .insert("project".into(), serde_json::json!(project(&h.scope)?));
            codec::aux(c, seq, facts)?;
        }
        CaptureVerified {
            source,
            session,
            offset,
        } => {
            let (id, _) = bound_session(c, &p, &scope, &session, h, false)?;
            let valid: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM capture_sources WHERE project_id=? AND source_id=? AND session_id=? AND byte_offset=? AND consent='capture')", crate::sql_value::sql_params![p,source.as_bytes().as_slice(),id,offset], |r| r.get(0)).map_err(sql)?;
            if !valid {
                return Err(fail(
                    StoreErrorCode::SourceChanged,
                    "final capture verification differs from the committed session/source cursor",
                ));
            }
            // A failure can arrive at the same byte offset after EOF planning.
            // Compare its identity inside this writer transaction, not only in
            // the planning snapshot. Legacy unbound acknowledgements may verify
            // a healthy cursor, but cannot clear a retained failure.
            let (cursor, failure): (Vec<u8>, Option<Vec<u8>>) = c.query_row(
                "SELECT e.event_id,(SELECT f.event_id FROM events f INDEXED BY events_session_seq
                 WHERE f.project_id=c.project_id AND f.session_id=c.session_id
                 AND f.seq>c.last_seq AND f.kind='capture.failed' ORDER BY f.seq DESC LIMIT 1)
                 FROM capture_sources c JOIN events e ON e.seq=c.last_seq
                 WHERE c.project_id=? AND c.source_id=?",
                crate::sql_value::sql_params![p, source.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ).map_err(sql)?;
            let unchanged = match &h.cause {
                Some(observed) => {
                    let observed = key(c, "event", observed.as_str(), &scope, false)?;
                    observed == *failure.as_ref().unwrap_or(&cursor)
                }
                None => failure.is_none(),
            };
            if !unchanged {
                return Err(fail(
                    StoreErrorCode::SourceChanged,
                    "capture failure changed after the EOF observation; retry its current binding",
                ));
            }
            codec::aux(c, seq, facts)?;
        }
        CaptureFailed {
            source,
            session,
            from_offset,
            to_offset,
            cause,
            ..
        } => {
            bound_session(c, &p, &scope, &session, h, false)?;
            let valid:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM capture_sources WHERE project_id=? AND source_id=? AND session_id=?)",rusqlite::params![p,source.as_bytes().as_slice(),key(c,"session",session.as_str(),&scope,false)?],|r|r.get(0)).map_err(sql)?;
            if !valid
                || from_offset > to_offset
                || to_offset > i64::MAX as u64
                || cause.len() > 16384
            {
                return Err(invalid("capture failure source/range/cause bounds"));
            }
            codec::aux(c, seq, facts)?;
        }
        CaptureSuppressed {
            source,
            session,
            from_offset,
            to_offset,
            count,
            reason,
            ..
        } => {
            bound_session(c, &p, &scope, &session, h, false)?;
            if to_offset < from_offset || to_offset > i64::MAX as u64 || reason.len() > 16384 {
                return Err(invalid("capture suppression range/reason bounds"));
            }
            let changed=c.execute("UPDATE capture_sources SET revision=?,last_seq=?,byte_offset=?,suppressed_count=suppressed_count+?
                    WHERE project_id=? AND source_id=? AND session_id=? AND revision=? AND byte_offset=? AND
                    consent='suppressed'",crate::sql_value::sql_params![rev,seq,to_offset,count,p,source.as_bytes().as_slice(),key(c,"session",session.as_str(),&scope,false)?,rev-1,from_offset]).map_err(sql)?;
            if changed != 1 {
                return Err(fail(
                    StoreErrorCode::SourceChanged,
                    "suppressed capture source/offset changed",
                ));
            }
            codec::aux(c, seq, facts)?;
        }
        _ => return Err(invalid("capture apply dispatch")),
    }
    Ok(())
}
