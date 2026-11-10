//! Read-only compatibility for decision events committed before ledger retirement.
use super::*;
use crate::sql_value::{sql_params, value};
type DecisionRow = (
    Vec<u8>,
    Option<String>,
    Option<u64>,
    Option<Vec<u8>>,
    Option<String>,
    Option<Vec<u8>>,
    Option<u64>,
);
pub(crate) fn decode(
    c: &Connection,
    seq: i64,
    kind: &str,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    let s = scope_key(c, scope, false)?;
    let (id,label,expected,prior,tag,replacement,replacement_rev):DecisionRow=c.prepare_cached("SELECT decision_id,decision_key,expected_revision,prior_proposal_id,decision_kind,replacement_id,replacement_expected_revision FROM decision_data WHERE event_seq=?").map_err(sql)?.query_row(sql_params![seq],|r|Ok((value(r,0)?,value(r,1)?,value(r,2)?,value(r,3)?,value(r,4)?,value(r,5)?,value(r,6)?))).map_err(sql)?;
    let decode = |v: &[u8]| wire(c, "decision", v, &s).and_then(|s| s.try_into().map_err(invalid));
    let decision = decode(&id)?;
    if kind == "decision.proposed" {
        let rationale: bool = c
            .prepare_cached(
                "SELECT rationale_payload IS NOT NULL FROM decision_data WHERE event_seq=?",
            )
            .map_err(sql)?
            .query_row(sql_params![seq], |r| value(r, 0))
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
