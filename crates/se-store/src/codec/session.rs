use super::*;
use crate::codec::capture::{parse_consent, parse_provider};
use rusqlite::OptionalExtension;
use se_types::{AgentId, SessionId};
pub(crate) struct SessionHead {
    pub agent: Vec<u8>,
    pub provider: String,
    pub native_ref: i64,
    pub generation: u64,
    pub consent: String,
    pub state: String,
}
pub(crate) fn head(c: &Connection, project: &[u8], session: &[u8]) -> StoreResult<SessionHead> {
    c.query_row("SELECT s.agent_id,d.provider,d.native_ref,d.generation,d.consent,s.state FROM sessions s JOIN session_data d ON d.event_seq=s.last_seq WHERE s.project_id=? AND s.session_id=?",rusqlite::params![project,session],|r|Ok(SessionHead {agent:r.get(0)?,provider:r.get(1)?,native_ref:r.get(2)?,generation:crate::sql_value::value(r,3)?,consent:r.get(4)?,state:r.get(5)?})).optional().map_err(sql)?.ok_or_else(||fail(StoreErrorCode::ReferenceMissing,"session head/data absent"))
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(crate) fn decode(
    c: &Connection,
    seq: i64,
    kind: &str,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    let mut q = c
        .prepare("SELECT * FROM session_data WHERE event_seq=?")
        .map_err(sql)?;
    let mut rows = q.query([seq]).map_err(sql)?;
    let row = rows
        .next()
        .map_err(sql)?
        .ok_or_else(|| invalid("session fact absent"))?;
    let s = scope_key(c, scope, false)?;
    let session: SessionId = wire(
        c,
        "session",
        &row.get::<_, Vec<u8>>("session_id").map_err(sql)?,
        &s,
    )?
    .try_into()
    .map_err(invalid)?;
    let agent: AgentId = decode_agent(
        c,
        wire(
            c,
            "agent",
            &row.get::<_, Vec<u8>>("agent_id").map_err(sql)?,
            &s,
        )?,
        &s,
    )?;
    let expected = row
        .get::<_, Option<i64>>("expected_revision")
        .map_err(sql)?
        .map(|v| revision(u64::try_from(v).map_err(invalid)?))
        .transpose()?
        .map(Expected::Revision)
        .unwrap_or(Expected::Absent);
    Ok(match kind {
        "session.prepared" => {
            let reference: Vec<u8> = c
                .query_row(
                    "SELECT value FROM symbols WHERE id=?",
                    [row.get::<_, i64>("native_ref").map_err(sql)?],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            EventBody::SessionPrepared {
                session,
                agent,
                provider: parse_provider(&row.get::<_, String>("provider").map_err(sql)?)?,
                surface: prepared_surface(c, seq)?,
                native_ref: String::from_utf8(reference).map_err(invalid)?,
                consent: parse_consent(&row.get::<_, String>("consent").map_err(sql)?)?,
                generation: u64::try_from(row.get::<_, i64>("generation").map_err(sql)?)
                    .map_err(invalid)?,
                expected,
            }
        }
        "session.activated" => {
            let incumbent = row
                .get::<_, Option<Vec<u8>>>("incumbent_id")
                .map_err(sql)?
                .map(|id| -> StoreResult<_> {
                    Ok((
                        wire(c, "session", &id, &s)?.try_into().map_err(invalid)?,
                        revision(
                            u64::try_from(
                                row.get::<_, i64>("incumbent_expected_revision")
                                    .map_err(sql)?,
                            )
                            .map_err(invalid)?,
                        )?,
                    ))
                })
                .transpose()?;
            EventBody::SessionActivated {
                session,
                expected,
                incumbent,
                process: row
                    .get::<_, Option<Vec<u8>>>("process_id")
                    .map_err(sql)?
                    .map(|id| {
                        wire(c, "lifecycle", &id, &s).and_then(|v| v.try_into().map_err(invalid))
                    })
                    .transpose()?,
                containment: serde_json::from_str(
                    &row.get::<_, String>("containment_fact").map_err(sql)?,
                )
                .map_err(invalid)?,
                witnesses: serde_json::from_str(
                    &row.get::<_, String>("witness_refs").map_err(sql)?,
                )
                .map_err(invalid)?,
            }
        }
        "session.ended" => {
            let facts = facts(c, seq)?;
            EventBody::SessionEnded {
                session,
                expected,
                reason: stored_text(c, seq, "reason")?,
                final_turn: field(&facts, "final_turn")?,
                final_cursor: field(&facts, "final_cursor")?,
            }
        }
        "session.revoked" => EventBody::SessionRevoked {
            session,
            expected,
            reason: stored_text(c, seq, "reason")?,
        },
        _ => return Err(invalid("session kind")),
    })
}

// Legacy preparations have no aux row. Missing metadata is unrecorded, while
// malformed or unknown present values remain unreadable.
fn prepared_surface(c: &Connection, seq: i64) -> StoreResult<Option<SessionSurface>> {
    #[derive(serde::Deserialize)]
    struct Metadata {
        #[serde(default)]
        surface: Option<SessionSurface>,
    }
    let facts: Option<String> = c
        .query_row(
            "SELECT facts FROM aux_data WHERE event_seq=?",
            [seq],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    facts
        .map(|facts| {
            serde_json::from_str::<Metadata>(&facts)
                .map(|value| value.surface)
                .map_err(invalid)
        })
        .transpose()
        .map(Option::flatten)
}
