use super::*;
use crate::codec::{
    capture::{consent, provider},
    session::SessionHead,
};
pub(super) fn revision(c: &Connection, e: &NewEvent) -> StoreResult<u64> {
    let (session, want) = match &e.body {
        EventBody::SessionPrepared {
            session, expected, ..
        }
        | EventBody::SessionActivated {
            session, expected, ..
        }
        | EventBody::SessionEnded {
            session, expected, ..
        }
        | EventBody::SessionRevoked {
            session, expected, ..
        } => (session, *expected),
        _ => return Err(invalid("session revision dispatch")),
    };
    let s = scope_key(c, &e.header.scope, false)?;
    let p = project_id(c, &e.header.scope, false)?;
    let id = key(c, "session", session.as_str(), &s, false)?;
    expected(
        c,
        "sessions",
        "project_id=? AND session_id=?",
        &[&p, &id],
        want,
    )
}
pub(super) fn reference(
    c: &Connection,
    p: &[u8],
    scope: &[u8],
    id: &se_types::EventId,
) -> StoreResult<()> {
    let id = key(c, "event", id.as_str(), scope, false)?;
    let exists: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM events WHERE project_id=? AND event_id=?)",
            rusqlite::params![p, id],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !exists {
        return Err(fail(
            StoreErrorCode::ReferenceMissing,
            "session witness/final event is outside this project",
        ));
    }
    Ok(())
}
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    lease: &LeaseIdentity,
) -> StoreResult<()> {
    use EventBody::*;
    let p = project_id(c, &h.scope, true)?;
    let scope = scope_key(c, &h.scope, true)?;
    let (session, want) = match &body {
        SessionPrepared {
            session, expected, ..
        }
        | SessionActivated {
            session, expected, ..
        }
        | SessionEnded {
            session, expected, ..
        }
        | SessionRevoked {
            session, expected, ..
        } => (session, *expected),
        _ => return Err(invalid("session apply dispatch")),
    };
    let id = key(c, "session", session.as_str(), &scope, true)?;
    let expected = match want {
        Expected::Absent => None,
        Expected::Revision(r) => Some(r.value.get()),
    };
    let mut incumbent = None;
    let mut incumbent_revision = None;
    let mut process = None;
    let mut containment = None;
    let mut witnesses = Vec::new();
    let mut reason = None;
    let (data, state) = match body {
        SessionPrepared {
            agent,
            provider: backend,
            surface,
            native_ref,
            consent: capture,
            generation,
            ..
        } => {
            if want != Expected::Absent {
                return Err(invalid("session preparation requires an absent session"));
            }
            if generation != lease.generation
                || native_ref.is_empty() && h.door != Door::Import
                || native_ref.len() > 32768
            {
                return Err(invalid("session generation/native reference bounds"));
            }
            codec::aux(c, seq, serde_json::json!({"surface": surface}))?;
            let a = key(c, "agent", agent.as_str(), &scope, false)?;
            let owner:Option<Vec<u8>>=c.query_row("SELECT owner_id FROM principals WHERE project_id=? AND principal_id=? AND principal_kind='agent'",rusqlite::params![p,a],|r|r.get(0)).optional().map_err(sql)?;
            let owner = owner
                .ok_or_else(|| fail(StoreErrorCode::ReferenceMissing, "session agent absent"))?;
            let permitted = match &h.actor {
                Actor::Remote(_) => false,
                Actor::Agent(actor) if *actor == agent => true,
                Actor::Agent(creator) => {
                    crate::creator::require(c, &p, &scope, creator, &a)?;
                    true
                }
                Actor::Human(human) => key(c, "human", human.as_str(), &[0], false)? == owner,
            };
            if !permitted {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "session preparation actor differs from agent/owner",
                ));
            }
            (
                SessionHead {
                    agent: a,
                    provider: provider(backend).into(),
                    native_ref: symbol(c, native_ref.as_bytes())?,
                    generation,
                    consent: consent(capture).into(),
                    state: "prepared".into(),
                },
                "prepared",
            )
        }
        SessionActivated {
            incumbent: old,
            process: root,
            containment: fact,
            witnesses: refs,
            ..
        } => {
            let data = codec::session::head(c, &p, &id)?;
            if data.state != "prepared" || data.generation != lease.generation {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "session activation requires the current prepared generation",
                ));
            }
            if let Some((old, r)) = old {
                let old = key(c, "session", old.as_str(), &scope, false)?;
                let valid:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sessions s JOIN events e ON e.seq=s.last_seq WHERE s.project_id=? AND s.session_id=? AND s.agent_id=? AND s.state='revoked' AND s.revision=? AND e.kind='session.revoked' AND e.operation_id=(SELECT operation_id FROM events WHERE seq=?))",crate::sql_value::sql_params![p,old,data.agent,r.value.get().checked_add(1).ok_or_else(||invalid("incumbent revision overflow"))?,seq],|r|r.get(0)).map_err(sql)?;
                if !valid {
                    return Err(fail(
                        StoreErrorCode::InvalidTransition,
                        "incumbent must be revoked earlier in the same atomic operation",
                    ));
                }
                incumbent = Some(old);
                incumbent_revision = Some(r.value.get());
            }
            if refs.len() > 16 {
                return Err(invalid("session witness bound"));
            }
            for witness in &refs {
                reference(c, &p, &scope, witness)?;
            }
            if let Some(root) = root {
                let k = key(c, "lifecycle", root.as_str(), &scope, false)?;
                let valid:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM processes p JOIN process_data d ON d.event_seq=p.last_seq WHERE p.project_id=? AND p.process_id=? AND p.ownership_released=0 AND p.state='running' AND d.principal_id=? AND d.target_session_id=?)",rusqlite::params![p,k,data.agent,id],|r|r.get(0)).map_err(sql)?;
                if !valid {
                    return Err(fail(
                        StoreErrorCode::ReferenceMissing,
                        "session process lacks its committed live binding",
                    ));
                }
                process = Some(k);
            } else if !matches!(fact, ContainmentFact::NotLaunched) {
                return Err(invalid(
                    "process-free embedded session has no native containment",
                ));
            }
            containment = Some(codec::encode(&fact)?);
            witnesses = refs;
            (data, "active")
        }
        SessionEnded {
            reason: text,
            final_turn,
            final_cursor,
            ..
        } => {
            let data = codec::session::head(c, &p, &id)?;
            if data.state != "active" && !(h.door == Door::Import && data.state == "prepared") {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "only an active session can end",
                ));
            }
            let live:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM credentials WHERE project_id=? AND session_id=? AND state IN ('prepared','active'))",rusqlite::params![p,id],|r|r.get(0)).map_err(sql)?;
            if live {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "revoke all session credentials in the same operation before ending the session",
                ));
            }
            for witness in final_turn.iter().chain(final_cursor.iter()) {
                reference(c, &p, &scope, witness)?;
            }
            codec::aux(
                c,
                seq,
                serde_json::json!({"final_turn":final_turn,"final_cursor":final_cursor}),
            )?;
            reason = Some(payload(c, seq, "reason", &codec::text(text, 16384)?)?);
            (data, "ended")
        }
        SessionRevoked { reason: text, .. } => {
            let data = codec::session::head(c, &p, &id)?;
            if !matches!(data.state.as_str(), "prepared" | "active") {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "terminal sessions cannot be revoked again",
                ));
            }
            let live:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM credentials WHERE project_id=? AND session_id=? AND state IN ('prepared','active'))",rusqlite::params![p,id],|r|r.get(0)).map_err(sql)?;
            if live {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "revoke session credentials before session revocation",
                ));
            }
            reason = Some(payload(c, seq, "reason", &codec::text(text, 16384)?)?);
            (data, "revoked")
        }
        _ => return Err(invalid("session apply kind")),
    };
    c.execute("INSERT INTO session_data(event_seq,session_id,agent_id,provider,native_ref,generation,consent,state,expected_revision,incumbent_id,incumbent_expected_revision,process_id,containment_fact,reason_payload,witness_refs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",crate::sql_value::sql_params![seq,id,data.agent,data.provider,data.native_ref,data.generation,data.consent,state,expected,incumbent,incumbent_revision,process,containment,reason,codec::encode(&witnesses)?]).map_err(sql)?;
    if rev == 1 {
        c.execute("INSERT INTO sessions(project_id,session_id,agent_id,first_seq,revision,last_seq,state) VALUES(?,?,?,?,?,?,?)",crate::sql_value::sql_params![p,id,data.agent,seq,rev,seq,state]).map_err(sql)?;
    } else {
        let changed=c.execute("UPDATE sessions SET revision=?,last_seq=?,state=? WHERE project_id=? AND session_id=? AND revision=?",crate::sql_value::sql_params![rev,seq,state,p,id,rev-1]).map_err(sql)?;
        if changed != 1 {
            return Err(fail(
                StoreErrorCode::RevisionConflict,
                "session head changed",
            ));
        }
    }
    let changed=c.execute("UPDATE resume_heads SET last_session_seq=?,last_seq=? WHERE project_id=? AND principal_id=?",rusqlite::params![seq,seq,p,data.agent]).map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "session agent resume head absent",
        ));
    }
    Ok(())
}
