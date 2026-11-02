//! Project tombstone: releases the active root lookup and keeps all history.
//! Removal follows the outside stop/revocation/integration effects, so live
//! authority or unsettled work left in the project refuses by name.
use super::*;
pub(super) fn revision(c: &Connection, e: &NewEvent) -> StoreResult<u64> {
    let EventBody::ProjectRemoved {
        project,
        expected: want,
        ..
    } = &e.body
    else {
        return Err(invalid("project removal revision dispatch"));
    };
    let p = key(c, "project", project.as_str(), &[0], false)?;
    expected(c, "projects", "project_id=?", &[&p], *want)
}
/// The project's registered owner, from its immutable registration facts.
pub(super) fn owner(c: &Connection, p: &[u8]) -> StoreResult<Option<String>> {
    Ok(c
        .query_row(
            "SELECT json_extract(a.facts,'$.owner') FROM projects p JOIN aux_data a ON a.event_seq=p.first_seq WHERE p.project_id=?",
            [p],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?
        .flatten())
}
/// Whether the admitted actor is the project's owner.
pub(super) fn is_owner(c: &Connection, h: &EventHeader, p: &[u8]) -> StoreResult<bool> {
    Ok(match &h.actor {
        Actor::Human(human) => owner(c, p)?.as_deref() == Some(human.as_str()),
        Actor::Agent(_) => false,
    })
}
/// Each live fact that must be gone before a tombstone, with its remedy.
const LIVE: [(&str, &str); 5] = [
    (
        "SELECT EXISTS(SELECT 1 FROM credentials WHERE project_id=? AND state IN ('prepared','active'))",
        "revoke the project's prepared or active credentials first",
    ),
    (
        "SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND state IN ('prepared','active'))",
        "end or revoke the project's live sessions first",
    ),
    (
        "SELECT EXISTS(SELECT 1 FROM processes WHERE project_id=? AND ownership_released=0 AND state NOT IN ('exited','historical'))",
        "stop the project's owned processes first",
    ),
    (
        "SELECT EXISTS(SELECT 1 FROM effects WHERE project_id=? AND state IN ('pending','offered'))",
        "settle the project's pending effects first",
    ),
    (
        "SELECT EXISTS(SELECT 1 FROM integrations WHERE project_id=? AND state='installed')",
        "remove the project's installed integrations or record them as conflicts first",
    ),
];
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    facts: Value,
) -> StoreResult<()> {
    let EventBody::ProjectRemoved {
        project,
        witnesses,
        preserved,
        ..
    } = body
    else {
        return Err(invalid("project removal apply dispatch"));
    };
    let p = project_id(c, &h.scope, false)?;
    let scope = scope_key(c, &h.scope, false)?;
    if key(c, "project", project.as_str(), &[0], false)? != p {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "removed project differs from event scope",
        ));
    }
    if !is_owner(c, h, &p)? {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "only the project's owner removes it",
        ));
    }
    if witnesses.is_empty() || witnesses.len() > 64 || preserved.len() > 64 {
        return Err(invalid(
            "project removal needs 1-64 witnesses and at most 64 preserved facts",
        ));
    }
    if preserved.iter().any(|f| f.is_empty() || f.len() > 1024) {
        return Err(invalid("preserved-history fact bounds"));
    }
    for witness in &witnesses {
        session::reference(c, &p, &scope, witness)?;
    }
    for (query, remedy) in LIVE {
        let live: bool = c.query_row(query, [&p], |r| r.get(0)).map_err(sql)?;
        if live {
            return Err(fail(StoreErrorCode::InvalidTransition, remedy));
        }
    }
    let changed = c
        .execute(
            "UPDATE projects SET state='removed',revision=?,last_seq=? WHERE project_id=? AND revision=? AND state='active'",
            crate::sql_value::sql_params![rev, seq, p, rev - 1],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "only an active project at the expected revision can be removed",
        ));
    }
    c.execute("DELETE FROM roots WHERE project_id=?", [&p])
        .map_err(sql)?;
    codec::aux(c, seq, facts)
}
