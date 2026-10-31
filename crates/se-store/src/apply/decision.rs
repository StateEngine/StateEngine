type DecisionRow = (
    Vec<u8>,
    Option<String>,
    Option<u64>,
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
    Option<u64>,
);
use super::*;
use crate::sql_value::{sql_params, value};
pub(super) fn revision(c: &Connection, e: &NewEvent) -> StoreResult<u64> {
    let s = scope_key(c, &e.header.scope, false)?;
    let p = project_id(c, &e.header.scope, false)?;
    let (id, want) = match &e.body {
        EventBody::DecisionProposed { decision, .. } => (decision, Expected::Absent),
        EventBody::DecisionRatified {
            decision, expected, ..
        }
        | EventBody::DecisionRejected {
            decision, expected, ..
        }
        | EventBody::DecisionRetracted {
            decision, expected, ..
        } => (decision, *expected),
        EventBody::DecisionSuperseded {
            prior,
            prior_expected,
            ..
        } => (prior, Expected::Revision(*prior_expected)),
        _ => return Err(invalid("decision revision dispatch")),
    };
    let id = key(c, "decision", id.as_str(), &s, false)?;
    expected(
        c,
        "decisions",
        "project_id=? AND decision_id=?",
        &[&p, &id],
        want,
    )
}
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    b: EventBody<InputText>,
    seq: i64,
    rev: u64,
) -> StoreResult<()> {
    use EventBody::*;
    let scope = scope_key(c, &h.scope, true)?;
    let p = project_id(c, &h.scope, true)?;
    let k = |id: &se_types::DecisionId| key(c, "decision", id.as_str(), &scope, true);
    if let DecisionProposed {
        decision,
        key: label,
        statement,
        rationale,
        prior,
        kind,
    } = b
    {
        if label.is_empty()
            || label.len() > 128
            || !label.as_bytes()[0].is_ascii_lowercase() && !label.as_bytes()[0].is_ascii_digit()
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            return Err(invalid("decision key bounds"));
        }
        let id = k(&decision)?;
        let statement = payload(c, seq, "statement", &codec::text(statement, 8 * 1024)?)?;
        let rationale = rationale
            .map(|v| codec::text(v, 2 * 1024).and_then(|v| payload(c, seq, "rationale", &v)))
            .transpose()?;
        let prior = prior.map(|v| k(&v)).transpose()?;
        c.execute("INSERT INTO decision_data(event_seq,decision_id,project_id,decision_key,state,statement_payload,rationale_payload,prior_proposal_id,decision_kind) VALUES(?,?,?,?,'proposed',?,?,?,?)",sql_params![seq,id,p,label,statement,rationale,prior,match kind{DecisionKind::Note=>"note",DecisionKind::Decision=>"decision"}]).map_err(sql)?;
        c.execute("INSERT INTO decisions(project_id,decision_id,proposed_seq,revision,last_seq,state) VALUES(?,?,?,?,?,'proposed')",sql_params![p,id,seq,rev,seq]).map_err(sql)?;
        return Ok(());
    }
    if !matches!(h.actor, Actor::Human(_)) {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "decision transitions require admitted human owner",
        ));
    }
    let (id, want, target, reason, approval, replacement) = match b {
        DecisionRatified {
            decision,
            expected,
            approval,
        } => (decision, expected, "ratified", None, Some(approval), None),
        DecisionRejected {
            decision,
            expected,
            reason,
        } => (decision, expected, "rejected", Some(reason), None, None),
        DecisionRetracted {
            decision,
            expected,
            reason,
        } => (decision, expected, "retracted", Some(reason), None, None),
        DecisionSuperseded {
            prior,
            replacement,
            prior_expected,
            replacement_expected,
            approval,
        } => (
            prior,
            Expected::Revision(prior_expected),
            "superseded",
            None,
            Some(approval),
            Some((replacement, replacement_expected)),
        ),
        _ => return Err(invalid("decision apply dispatch")),
    };
    let id = k(&id)?;
    let old: String = c
        .query_row(
            "SELECT state FROM decisions WHERE project_id=? AND decision_id=?",
            sql_params![p, id],
            |r| value(r, 0),
        )
        .map_err(sql)?;
    let legal = match target {
        "ratified" | "rejected" => old == "proposed",
        "retracted" => matches!(old.as_str(), "proposed" | "ratified"),
        "superseded" => old == "ratified",
        _ => false,
    };
    if !legal {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            format!("decision {old} cannot become {target}"),
        ));
    }
    let replacement = replacement
        .map(|(id, expected)| {
            let id = k(&id)?;
            let (state, revision): (String, u64) = c
                .query_row(
                    "SELECT state,revision FROM decisions WHERE project_id=? AND decision_id=?",
                    sql_params![p, id],
                    |r| Ok((value(r, 0)?, value(r, 1)?)),
                )
                .map_err(sql)?;
            if state != "ratified" || revision != expected.value.get() {
                return Err(fail(
                    StoreErrorCode::RevisionConflict,
                    "replacement must be ratified at the expected revision",
                ));
            }
            Ok((id, revision))
        })
        .transpose()?;
    let reason = reason
        .map(|v| codec::text(v, 2 * 1024).and_then(|v| payload(c, seq, "reason", &v)))
        .transpose()?;
    let want = match want {
        Expected::Absent => None,
        Expected::Revision(r) => Some(r.value.get()),
    };
    if let Some(approval) = approval {
        let a = key(c, "event", approval.as_str(), &scope, false)?;
        let exists: bool = c
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE project_id=? AND event_id=?)",
                sql_params![p, a],
                |r| value(r, 0),
            )
            .map_err(sql)?;
        if !exists {
            return Err(fail(
                StoreErrorCode::ReferenceMissing,
                "decision approval outside project or absent",
            ));
        }
        codec::aux(c, seq, serde_json::json!({"approval":approval}))?;
    }
    c.execute("INSERT INTO decision_data(event_seq,decision_id,project_id,state,reason_payload,expected_revision,replacement_id,replacement_expected_revision) VALUES(?,?,?,?,?,?,?,?)",sql_params![seq,id,p,target,reason,want,replacement.as_ref().map(|r|&r.0),replacement.as_ref().map(|r|r.1)]).map_err(sql)?;
    let changed=c.execute("UPDATE decisions SET state=?,revision=?,last_seq=? WHERE project_id=? AND decision_id=? AND revision=?",sql_params![target,rev,seq,p,id,want]).map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::RevisionConflict,
            "decision predecessor changed",
        ));
    }
    Ok(())
}
pub(crate) fn decode(
    c: &Connection,
    seq: i64,
    kind: &str,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    let s = scope_key(c, scope, false)?;
    let (id,label,expected,prior,tag,replacement,replacement_rev):DecisionRow=c.query_row("SELECT decision_id,decision_key,expected_revision,prior_proposal_id,decision_kind,replacement_id,replacement_expected_revision FROM decision_data WHERE event_seq=?",sql_params![seq],|r|Ok((value(r,0)?,value(r,1)?,value(r,2)?,value(r,3)?,value(r,4)?,value(r,5)?,value(r,6)?))).map_err(sql)?;
    let decode = |v: &[u8]| wire(c, "decision", v, &s).and_then(|s| s.parse().map_err(invalid));
    let decision = decode(&id)?;
    if kind == "decision.proposed" {
        let rationale: bool = c
            .query_row(
                "SELECT rationale_payload IS NOT NULL FROM decision_data WHERE event_seq=?",
                sql_params![seq],
                |r| value(r, 0),
            )
            .map_err(sql)?;
        return Ok(DecisionProposed {
            decision,
            key: label.ok_or_else(|| invalid("proposal key absent"))?,
            statement: codec::stored_text(c, seq, "statement")?,
            rationale: if rationale {
                Some(codec::stored_text(c, seq, "rationale")?)
            } else {
                None
            },
            prior: prior.map(|v| decode(&v)).transpose()?,
            kind: match tag.as_deref() {
                Some("note") => DecisionKind::Note,
                Some("decision") => DecisionKind::Decision,
                _ => return Err(invalid("unknown decision kind")),
            },
        });
    }
    let revision =
        codec::revision(expected.ok_or_else(|| invalid("decision expected revision absent"))?)?;
    let expected = Expected::Revision(revision);
    Ok(match kind {
        "decision.ratified" => DecisionRatified {
            decision,
            expected,
            approval: codec::field(&codec::facts(c, seq)?, "approval")?,
        },
        "decision.rejected" => DecisionRejected {
            decision,
            expected,
            reason: codec::stored_text(c, seq, "reason")?,
        },
        "decision.retracted" => DecisionRetracted {
            decision,
            expected,
            reason: codec::stored_text(c, seq, "reason")?,
        },
        "decision.superseded" => DecisionSuperseded {
            prior: decision,
            replacement: decode(&replacement.ok_or_else(|| invalid("replacement absent"))?)?,
            prior_expected: revision,
            replacement_expected: codec::revision(
                replacement_rev.ok_or_else(|| invalid("replacement revision absent"))?,
            )?,
            approval: codec::field(&codec::facts(c, seq)?, "approval")?,
        },
        _ => return Err(invalid("unknown decision event kind")),
    })
}
