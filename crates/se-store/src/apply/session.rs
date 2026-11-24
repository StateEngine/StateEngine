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
        return Err(reference_missing(
            "session witness/final event is outside this project",
        ));
    }
    Ok(())
}
#[derive(Default)]
struct TransitionExtras {
    incumbent: Option<Vec<u8>>,
    incumbent_revision: Option<u64>,
    process: Option<Vec<u8>>,
    containment: Option<String>,
    witnesses: Vec<se_types::EventId>,
    reason: Option<i64>,
}
fn apply_prepared(
    c: &Connection,
    h: &EventHeader,
    keys: (&[u8], &[u8], i64),
    want: Expected,
    authority: &ApplyAuthority<'_>,
    fields: (
        se_types::AgentId,
        Provider,
        Option<SessionSurface>,
        String,
        Consent,
        u64,
    ),
) -> StoreResult<SessionHead> {
    let ((p, scope, seq), (agent, backend, surface, native_ref, capture, generation)) =
        (keys, fields);
    if want != Expected::Absent {
        return Err(invalid("session preparation requires an absent session"));
    }
    if generation != authority.lease.generation
        || native_ref.is_empty() && h.door != Door::Import
        || native_ref.len() > 32768
    {
        return Err(invalid("session generation/native reference bounds"));
    }
    codec::aux(c, seq, serde_json::json!({"surface": surface}))?;
    let a = key(c, "agent", agent.as_str(), scope, false)?;
    let owner:Vec<u8>=c.query_row("SELECT owner_id FROM principals WHERE project_id=? AND principal_id=? AND principal_kind='agent'",rusqlite::params![p,a],|r|r.get(0)).optional().map_err(sql)?.ok_or_else(|| reference_missing("session agent absent"))?;
    if h.door != Door::Import {
        principal::refuse_retired(c, p, &a)?;
    }
    let permitted = match &h.actor {
        Actor::Remote(_) => authority.remote_launch.is_some(),
        Actor::Guest => false,
        Actor::Agent(actor) if *actor == agent => true,
        Actor::Agent(creator) => {
            crate::creator::require(c, p, scope, creator, &a)?;
            true
        }
        Actor::Human(human) => key(c, "human", human.as_str(), &[0], false)? == owner,
    };
    if !permitted {
        return Err(scope_mismatch(
            "session preparation actor differs from agent/owner",
        ));
    }
    Ok(SessionHead {
        agent: a,
        provider: provider(backend).into(),
        native_ref: symbol(c, native_ref.as_bytes())?,
        generation,
        consent: consent(capture).into(),
        state: "prepared".into(),
    })
}
fn apply_activated(
    c: &Connection,
    keys: (&[u8], &[u8], &[u8], i64),
    lease: &LeaseIdentity,
    old: Option<(se_types::SessionId, Revision)>,
    root: Option<se_types::LifecycleId>,
    fact: ContainmentFact,
    refs: Vec<se_types::EventId>,
) -> StoreResult<(SessionHead, TransitionExtras)> {
    let (p, scope, id, seq) = keys;
    let data = codec::session::head(c, p, id)?;
    if data.state != "prepared" || data.generation != lease.generation {
        return Err(invalid_transition(
            "session activation requires the current prepared generation",
        ));
    }
    let mut extras = TransitionExtras::default();
    if let Some((old, r)) = old {
        let old = key(c, "session", old.as_str(), scope, false)?;
        let valid:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sessions s JOIN events e ON e.seq=s.last_seq WHERE s.project_id=? AND s.session_id=? AND s.agent_id=? AND s.state='revoked' AND s.revision=? AND e.kind='session.revoked' AND e.operation_id=(SELECT operation_id FROM events WHERE seq=?))",crate::sql_value::sql_params![p,old,data.agent,r.value.get().checked_add(1).ok_or_else(||invalid("incumbent revision overflow"))?,seq],|r|r.get(0)).map_err(sql)?;
        if !valid {
            return Err(invalid_transition(
                "incumbent must be revoked earlier in the same atomic operation",
            ));
        }
        extras.incumbent = Some(old);
        extras.incumbent_revision = Some(r.value.get());
    }
    if refs.len() > 16 {
        return Err(invalid("session witness bound"));
    }
    for witness in &refs {
        reference(c, p, scope, witness)?;
    }
    if let Some(root) = root {
        let k = key(c, "lifecycle", root.as_str(), scope, false)?;
        let valid:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM processes p JOIN process_data d ON d.event_seq=p.last_seq WHERE p.project_id=? AND p.process_id=? AND p.ownership_released=0 AND p.state='running' AND d.principal_id=? AND d.target_session_id=?)",rusqlite::params![p,k,data.agent,id],|r|r.get(0)).map_err(sql)?;
        if !valid {
            return Err(reference_missing(
                "session process lacks its committed live binding",
            ));
        }
        extras.process = Some(k);
    } else if !matches!(fact, ContainmentFact::NotLaunched) {
        return Err(invalid(
            "process-free embedded session has no native containment",
        ));
    }
    extras.containment = Some(codec::encode(&fact)?);
    extras.witnesses = refs;
    Ok((data, extras))
}
fn apply_terminal(
    c: &Connection,
    h: &EventHeader,
    keys: (&[u8], &[u8], &[u8], i64),
    text: InputText,
    finals: Option<(Option<se_types::EventId>, Option<se_types::EventId>)>,
) -> StoreResult<(SessionHead, &'static str, i64)> {
    let (p, scope, id, seq) = keys;
    let data = codec::session::head(c, p, id)?;
    let (state, cred_msg) = if finals.is_some() {
        if data.state != "active" && !(h.door == Door::Import && data.state == "prepared") {
            return Err(invalid_transition("only an active session can end"));
        }
        (
            "ended",
            "revoke all session credentials in the same operation before ending the session",
        )
    } else {
        if !matches!(data.state.as_str(), "prepared" | "active") {
            return Err(invalid_transition(
                "terminal sessions cannot be revoked again",
            ));
        }
        (
            "revoked",
            "revoke session credentials before session revocation",
        )
    };
    let live:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM credentials WHERE project_id=? AND session_id=? AND state IN ('prepared','active'))",rusqlite::params![p,id],|r|r.get(0)).map_err(sql)?;
    if live {
        return Err(invalid_transition(cred_msg));
    }
    if let Some((final_turn, final_cursor)) = finals {
        for witness in final_turn.iter().chain(final_cursor.iter()) {
            reference(c, p, scope, witness)?;
        }
        codec::aux(
            c,
            seq,
            serde_json::json!({"final_turn":final_turn,"final_cursor":final_cursor}),
        )?;
    }
    let reason = payload(
        c,
        seq,
        "reason",
        &codec::text(text.as_materialized()?, 16384)?,
    )?;
    Ok((data, state, reason))
}
fn persist_session(
    c: &Connection,
    keys: (&[u8], &[u8], i64, u64),
    data: &SessionHead,
    state: &str,
    expected: Option<u64>,
    extras: &TransitionExtras,
) -> StoreResult<()> {
    let (p, id, seq, rev) = keys;
    c.execute("INSERT INTO session_data(event_seq,session_id,agent_id,provider,native_ref,generation,consent,state,expected_revision,incumbent_id,incumbent_expected_revision,process_id,containment_fact,reason_payload,witness_refs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",crate::sql_value::sql_params![seq,id,data.agent,data.provider,data.native_ref,data.generation,data.consent,state,expected,extras.incumbent,extras.incumbent_revision,extras.process,extras.containment,extras.reason,codec::encode(&extras.witnesses)?]).map_err(sql)?;
    if rev == 1 {
        c.execute("INSERT INTO sessions(project_id,session_id,agent_id,first_seq,revision,last_seq,state) VALUES(?,?,?,?,?,?,?)",crate::sql_value::sql_params![p,id,data.agent,seq,rev,seq,state]).map_err(sql)?;
    } else {
        let changed=c.execute("UPDATE sessions SET revision=?,last_seq=?,state=? WHERE project_id=? AND session_id=? AND revision=?",crate::sql_value::sql_params![rev,seq,state,p,id,rev-1]).map_err(sql)?;
        if changed != 1 {
            return Err(revision_conflict("session head changed"));
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
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    authority: &ApplyAuthority<'_>,
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
    let mut extras = TransitionExtras::default();
    let (data, state) = match body {
        SessionPrepared {
            agent,
            provider: backend,
            surface,
            native_ref,
            consent: capture,
            generation,
            ..
        } => (
            apply_prepared(
                c,
                h,
                (&p, &scope, seq),
                want,
                authority,
                (agent, backend, surface, native_ref, capture, generation),
            )?,
            "prepared",
        ),
        SessionActivated {
            incumbent,
            process,
            containment,
            witnesses,
            ..
        } => {
            let (data, act) = apply_activated(
                c,
                (&p, &scope, &id, seq),
                authority.lease,
                incumbent,
                process,
                containment,
                witnesses,
            )?;
            extras = act;
            (data, "active")
        }
        SessionEnded {
            reason,
            final_turn,
            final_cursor,
            ..
        } => {
            let (data, state, r) = apply_terminal(
                c,
                h,
                (&p, &scope, &id, seq),
                reason,
                Some((final_turn, final_cursor)),
            )?;
            extras.reason = Some(r);
            (data, state)
        }
        SessionRevoked { reason, .. } => {
            let (data, state, r) = apply_terminal(c, h, (&p, &scope, &id, seq), reason, None)?;
            extras.reason = Some(r);
            (data, state)
        }
        _ => return Err(invalid("session apply kind")),
    };
    persist_session(c, (&p, &id, seq, rev), &data, state, expected, &extras)
}
