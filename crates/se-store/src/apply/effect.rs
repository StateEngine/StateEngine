//! Durable effect intentions and owned integration edits. Recording never
//! executes the effect; only outside evidence can settle one as witnessed.
use super::*;
fn effect_key(id: &RecordId) -> Vec<u8> {
    id.as_bytes().to_vec()
}
fn principal_key(c: &Connection, a: &Actor, scope: &[u8]) -> StoreResult<Vec<u8>> {
    key(
        c,
        a.kind(),
        a.wire(),
        if a.kind() == "human" { &[0] } else { scope },
        false,
    )
}
/// Current effect head: (revision, state, principal key).
type EffectHead = (u64, String, Option<Vec<u8>>);
fn head(c: &Connection, p: &[u8], effect: &[u8]) -> StoreResult<Option<EffectHead>> {
    c.query_row(
        "SELECT revision,state,principal_id FROM effects WHERE project_id=? AND effect_id=?",
        rusqlite::params![p, effect],
        |r| Ok((crate::sql_value::value(r, 0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()
    .map_err(sql)
}
pub(super) fn revision(c: &Connection, e: &NewEvent) -> StoreResult<u64> {
    let p = project_id(c, &e.header.scope, false)?;
    match &e.body {
        EventBody::EffectRequested { effect, .. } => {
            let taken: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM effects WHERE effect_id=? AND project_id IS NOT ?)",
                    rusqlite::params![effect_key(effect), p],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            if taken {
                return Err(fail(
                    StoreErrorCode::NaturalKeyConflict,
                    "effect ID is already used in another project; allocate a fresh effect ID",
                ));
            }
            expected(
                c,
                "effects",
                "project_id=? AND effect_id=?",
                &[&p, &effect_key(effect)],
                Expected::Absent,
            )
        }
        // An offer advances the current head; it carries no caller revision.
        EventBody::EffectOffered { effect, .. } => match head(c, &p, &effect_key(effect))? {
            Some((current, ..)) => current
                .checked_add(1)
                .ok_or_else(|| invalid("effect revision exhausted")),
            None => Err(fail(
                StoreErrorCode::ReferenceMissing,
                "offered effect was never requested",
            )),
        },
        EventBody::EffectSettled {
            effect,
            expected: want,
            ..
        } => expected(
            c,
            "effects",
            "project_id=? AND effect_id=?",
            &[&p, &effect_key(effect)],
            *want,
        ),
        EventBody::IntegrationRecorded {
            integration,
            expected: want,
            ..
        } => expected(
            c,
            "integrations",
            "project_id=? AND integration_id=?",
            &[&p, &effect_key(integration)],
            *want,
        ),
        _ => Err(invalid("effect revision dispatch")),
    }
}
fn intent_matches(kind: EffectKind, intent: &EffectIntent) -> bool {
    matches!(
        (kind, intent),
        (
            EffectKind::Bell,
            EffectIntent::Mail { .. } | EffectIntent::MailNotice(_)
        ) | (EffectKind::Packet, EffectIntent::Packet { .. })
            | (
                EffectKind::IntegrationWrite,
                EffectIntent::Integration { .. }
            )
            | (
                EffectKind::AgentLaunch | EffectKind::AgentStop,
                EffectIntent::Process { .. }
            )
            | (
                EffectKind::RuntimeStart | EffectKind::RuntimeStop,
                EffectIntent::Runtime { .. }
            )
    )
}
fn kind_name(kind: EffectKind) -> &'static str {
    match kind {
        EffectKind::Bell => "bell",
        EffectKind::Packet => "packet",
        EffectKind::IntegrationWrite => "integration-write",
        EffectKind::AgentLaunch => "agent-launch",
        EffectKind::AgentStop => "agent-stop",
        EffectKind::RuntimeStart => "runtime-start",
        EffectKind::RuntimeStop => "runtime-stop",
    }
}
/// Pending debt on the affected agent's resume head; humans carry none.
fn debt(
    c: &Connection,
    p: &[u8],
    principal: &Option<Vec<u8>>,
    kind: &str,
    delta: i64,
    seq: i64,
) -> StoreResult<()> {
    let Some(a) = principal else { return Ok(()) };
    if kind != "agent" {
        return Ok(());
    }
    let changed = c
        .execute(
            "UPDATE resume_heads SET pending_effect_count=pending_effect_count+?,last_seq=? WHERE project_id=? AND principal_id=?",
            crate::sql_value::sql_params![delta, seq, p, a],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "effect principal resume head absent",
        ));
    }
    Ok(())
}
fn principal_kind(c: &Connection, p: &[u8], a: &[u8]) -> StoreResult<String> {
    c.query_row(
        "SELECT principal_kind FROM principals WHERE project_id=? AND principal_id=?",
        rusqlite::params![p, a],
        |r| r.get(0),
    )
    .optional()
    .map_err(sql)?
    .ok_or_else(|| {
        fail(
            StoreErrorCode::ReferenceMissing,
            "effect principal is not registered in this project",
        )
    })
}
/// Only the project owner or the effect's own agent may request, offer or
/// settle it; another agent can never add debt to, or cancel, someone's work.
fn authorize(
    c: &Connection,
    h: &EventHeader,
    p: &[u8],
    scope: &[u8],
    principal: Option<&[u8]>,
) -> StoreResult<()> {
    let own = match (&h.actor, principal) {
        (Actor::Agent(_), Some(a)) => principal_key(c, &h.actor, scope)? == a,
        (Actor::Agent(_), None) => false,
        (Actor::Human(_), _) => super::project::is_owner(c, h, p)?,
    };
    if own {
        Ok(())
    } else {
        Err(fail(
            StoreErrorCode::ScopeMismatch,
            "only the project owner or the effect's own agent may record this effect",
        ))
    }
}
/// Evidence must be a project event committed after the effect's request.
fn after_request(
    c: &Connection,
    p: &[u8],
    scope: &[u8],
    effect: &[u8],
    evidence: &se_types::EventId,
) -> StoreResult<()> {
    session::reference(c, p, scope, evidence)?;
    let e = key(c, "event", evidence.as_str(), scope, false)?;
    let later: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM events v JOIN effects f ON f.project_id=v.project_id AND f.effect_id=? WHERE v.event_id=? AND v.seq>f.requested_seq)",
            rusqlite::params![effect, e],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if later {
        Ok(())
    } else {
        Err(fail(
            StoreErrorCode::InvalidTransition,
            "effect evidence must be committed after the effect was requested",
        ))
    }
}
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    facts: Value,
    lease: &LeaseIdentity,
) -> StoreResult<()> {
    let p = project_id(c, &h.scope, false)?;
    let scope = scope_key(c, &h.scope, false)?;
    match body {
        EventBody::EffectRequested {
            principal,
            effect,
            kind,
            intent,
            cause,
            ..
        } => {
            if !intent_matches(kind, &intent) {
                return Err(invalid("effect kind and intent disagree"));
            }
            session::reference(c, &p, &scope, &cause)?;
            let a = principal
                .as_ref()
                .map(|a| principal_key(c, a, &scope))
                .transpose()?;
            authorize(c, h, &p, &scope, a.as_deref())?;
            if let EffectIntent::MailNotice(notice) = &intent {
                super::mail::validate(c, h, &principal, notice)?;
            }
            let k = a.as_ref().map(|a| principal_kind(c, &p, a)).transpose()?;
            c.execute(
                "INSERT INTO effects(effect_id,project_id,kind,principal_id,requested_seq,revision,last_seq,state) VALUES(?,?,?,?,?,?,?,'pending')",
                crate::sql_value::sql_params![effect_key(&effect), p, kind_name(kind), a, seq, rev, seq],
            )
            .map_err(sql)?;
            debt(c, &p, &a, k.as_deref().unwrap_or("human"), 1, seq)?;
            if let EffectIntent::MailNotice(notice) = &intent {
                super::notification::reserved(c, h, notice, seq)?;
            }
        }
        EventBody::EffectOffered {
            effect,
            principal,
            attempt,
            evidence,
        } => {
            let id = effect_key(&effect);
            let (_, state, owner) = head(c, &p, &id)?.ok_or_else(|| {
                fail(
                    StoreErrorCode::ReferenceMissing,
                    "offered effect was never requested",
                )
            })?;
            if !matches!(state.as_str(), "pending" | "offered") {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "only a pending effect can be offered",
                ));
            }
            authorize(c, h, &p, &scope, owner.as_deref())?;
            let offered_to = principal_key(c, &principal, &scope)?;
            let matches = match &owner {
                Some(o) => *o == offered_to,
                None => principal == h.actor,
            };
            if !matches {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "offer principal differs from the requested principal",
                ));
            }
            match &evidence {
                crate::mail::OfferEvidence::Committed(event) => {
                    if event == &h.event {
                        return Err(invalid("an effect offer cannot witness itself"));
                    }
                    after_request(c, &p, &scope, &id, event)?
                }
                crate::mail::OfferEvidence::Observed(observation) => {
                    super::mail::validate_offer(c, h, &effect, observation, lease)?
                }
            }
            let reused: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM aux_data a JOIN events e ON e.seq=a.event_seq WHERE json_extract(a.facts,'$.attempt') IS NOT NULL AND json_extract(a.facts,'$.effect')=? AND json_extract(a.facts,'$.attempt')=? AND e.project_id=? AND e.kind='effect.offered')",
                    rusqlite::params![codec::encode(&effect)?.trim_matches('"'), codec::encode(&attempt)?.trim_matches('"'), p],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            if reused {
                return Err(fail(
                    StoreErrorCode::NaturalKeyConflict,
                    "effect attempt was already offered",
                ));
            }
            update(c, &p, &id, rev, seq, "offered")?;
            if let crate::mail::OfferEvidence::Observed(observation) = &evidence {
                super::notification::observed(c, h, &effect, observation, seq)?;
            }
        }
        EventBody::EffectSettled {
            effect,
            outcome,
            evidence,
            failure,
            ..
        } => {
            let id = effect_key(&effect);
            let (_, state, owner) = head(c, &p, &id)?.ok_or_else(|| {
                fail(
                    StoreErrorCode::ReferenceMissing,
                    "settled effect was never requested",
                )
            })?;
            if !matches!(state.as_str(), "pending" | "offered") {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "a terminal effect cannot settle again",
                ));
            }
            authorize(c, h, &p, &scope, owner.as_deref())?;
            let reason_ok = failure
                .as_ref()
                .is_some_and(|f| !f.is_empty() && f.len() <= 16384);
            let shape_ok = match outcome {
                EffectOutcome::Witnessed => !evidence.is_empty() && failure.is_none(),
                EffectOutcome::Failed | EffectOutcome::Abandoned => reason_ok,
            };
            if !shape_ok || evidence.len() > 16 {
                return Err(invalid(
                    "witnessed needs outside evidence and no failure; failed/abandoned need a bounded reason",
                ));
            }
            for e in &evidence {
                after_request(c, &p, &scope, &id, e)?;
            }
            let state = match outcome {
                EffectOutcome::Witnessed => "witnessed",
                EffectOutcome::Failed => "failed",
                EffectOutcome::Abandoned => "abandoned",
            };
            update(c, &p, &id, rev, seq, state)?;
            let k = owner
                .as_ref()
                .map(|a| principal_kind(c, &p, a))
                .transpose()?;
            debt(c, &p, &owner, k.as_deref().unwrap_or("human"), -1, seq)?;
        }
        EventBody::IntegrationRecorded {
            integration,
            key: k,
            marker,
            written_sha256,
            state,
            witness,
            ..
        } => {
            if !super::project::is_owner(c, h, &p)? {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "only the project owner records owned integrations",
                ));
            }
            if k.is_empty() || k.len() > 1024 || marker.is_empty() || marker.len() > 1024 {
                return Err(invalid("integration key/marker bounds"));
            }
            if state == IntegrationState::Installed && written_sha256.is_none() {
                return Err(invalid(
                    "an installed integration records its written digest",
                ));
            }
            session::reference(c, &p, &scope, &witness)?;
            let id = effect_key(&integration);
            let name = match state {
                IntegrationState::Installed => "installed",
                IntegrationState::Removed => "removed",
                IntegrationState::Conflict => "conflict",
            };
            let changed = c
                .execute(
                    "INSERT INTO integrations(project_id,integration_id,revision,last_seq,state) VALUES(?,?,?,?,?)
                     ON CONFLICT(project_id,integration_id) DO UPDATE SET revision=excluded.revision,last_seq=excluded.last_seq,state=excluded.state
                     WHERE integrations.revision=excluded.revision-1",
                    crate::sql_value::sql_params![p, id, rev, seq, name],
                )
                .map_err(sql)?;
            if changed != 1 {
                return Err(fail(
                    StoreErrorCode::RevisionConflict,
                    "integration head changed",
                ));
            }
        }
        _ => return Err(invalid("effect apply dispatch")),
    }
    codec::aux(c, seq, facts)
}
fn update(c: &Connection, p: &[u8], id: &[u8], rev: u64, seq: i64, state: &str) -> StoreResult<()> {
    let changed = c
        .execute(
            "UPDATE effects SET revision=?,last_seq=?,state=? WHERE project_id=? AND effect_id=? AND revision=?",
            crate::sql_value::sql_params![rev, seq, state, p, id, rev - 1],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::RevisionConflict,
            "effect head changed",
        ));
    }
    Ok(())
}
