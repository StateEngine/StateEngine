//! Project tombstone: releases the active root lookup and keeps all history.
//! Removal follows the outside stop/revocation/integration effects, so live
//! authority or unsettled work left in the project refuses by name.
use super::*;
pub(super) fn revision(c: &Connection, e: &NewEvent) -> StoreResult<u64> {
    let (project, want) = match &e.body {
        EventBody::ProjectRemoved {
            project, expected, ..
        }
        | EventBody::ProjectUpdated {
            project, expected, ..
        }
        | EventBody::ProjectMoved {
            project, expected, ..
        } => (project, *expected),
        _ => return Err(invalid("project metadata revision dispatch")),
    };
    let p = key(c, "project", project.as_str(), &[0], false)?;
    expected(c, "projects", "project_id=?", &[&p], want)
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
        Actor::Agent(_) | Actor::Remote(_) => false,
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
/// A project with no outside effects cites its current registration. That
/// metadata lives in Registry scope; the projection binds it to this exact
/// target without admitting any other Registry event or widening event reads.
fn removal_reference(
    c: &Connection,
    project: &[u8],
    scope: &[u8],
    witness: &se_types::EventId,
) -> StoreResult<()> {
    let registry_id = key(c, "event", witness.as_str(), &[0], false)?;
    let current_registration: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM projects p JOIN events e ON e.seq=p.last_seq WHERE p.project_id=? AND e.event_id=? AND e.project_id IS NULL AND e.kind IN ('project.registered','project.updated'))",
            rusqlite::params![project, registry_id],
            |row| row.get(0),
        )
        .map_err(sql)?;
    if current_registration {
        Ok(())
    } else {
        session::reference(c, project, scope, witness)
    }
}
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
        removal_reference(c, &p, &scope, witness)?;
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

/// A moved-root revision: the CLI door verified the target's recorded git
/// identity (matching project, recorded HEAD ancestry) and owner admission
/// before proposing it; the store re-enforces the door, scope, owner and
/// live-custody rules so no other surface can rebind a project's root.
pub(super) fn move_root(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    facts: Value,
) -> StoreResult<()> {
    let EventBody::ProjectMoved {
        project,
        name,
        from,
        to,
        head,
        branch,
        ..
    } = body
    else {
        return Err(invalid("project move dispatch"));
    };
    if name.is_empty() || name.len() > 128 {
        return Err(invalid(
            "project move must keep the bounded registered name",
        ));
    }
    if h.scope != Scope::Project(project.clone()) || h.door != Door::Cli {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "project moves require the owner CLI admitted in the project's scope",
        ));
    }
    let p = key(c, "project", project.as_str(), &[0], false)?;
    if !is_owner(c, h, &p)? {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "only the current project owner moves a root",
        ));
    }
    for (query, remedy) in LIVE {
        if c.query_row(query, [&p], |r| r.get::<_, bool>(0))
            .map_err(sql)?
        {
            return Err(fail(StoreErrorCode::InvalidTransition, remedy));
        }
    }
    if from.is_empty() || from.len() > 64 {
        return Err(invalid("project move needs the bounded previous roots"));
    }
    if from.iter().any(|root| root.path == to.path) {
        return Err(invalid(
            "project move target must differ from the previous roots",
        ));
    }
    if head.as_deref().is_some_and(|value| {
        !matches!(value.len(), 40 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit())
    }) {
        return Err(invalid("project move git identity bounds"));
    }
    if branch
        .as_deref()
        .is_some_and(|value| value.is_empty() || value.len() > 256)
    {
        return Err(invalid("project move git identity bounds"));
    }
    let changed = c
        .execute(
            "UPDATE projects SET revision=?,last_seq=? WHERE project_id=? AND revision=? AND state='active'",
            crate::sql_value::sql_params![rev, seq, p, rev - 1],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "project move requires the current active registration",
        ));
    }
    c.execute("DELETE FROM roots WHERE project_id=?", [&p])
        .map_err(sql)?;
    let encoded = symbol(c, codec::encode(&to.path)?.as_bytes())?;
    c.execute(
        "INSERT INTO roots(project_id,canonical_key,encoded_path,last_seq) VALUES(?,?,?,?)",
        crate::sql_value::sql_params![p, to.canonical_key, encoded, seq],
    )
    .map_err(sql)?;
    codec::aux(c, seq, facts)
}

/// Imported root/name revisions use the ordinary owner and live-custody rules.
pub(super) fn update(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    facts: Value,
) -> StoreResult<()> {
    let EventBody::ProjectUpdated { project, roots, .. } = body else {
        return Err(invalid("project update dispatch"));
    };
    if h.scope != Scope::Registry || h.door != Door::Import {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "historical project revisions require the owner import in registry scope",
        ));
    }
    let p = key(c, "project", project.as_str(), &[0], false)?;
    if !is_owner(c, h, &p)? {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "only the current project owner adopts a historical root revision",
        ));
    }
    for (query, remedy) in LIVE {
        if c.query_row(query, [&p], |r| r.get::<_, bool>(0))
            .map_err(sql)?
        {
            return Err(fail(StoreErrorCode::InvalidTransition, remedy));
        }
    }
    if roots.is_empty() || roots.len() > 64 {
        return Err(invalid("project revision needs bounded roots"));
    }
    let changed=c.execute("UPDATE projects SET revision=?,last_seq=? WHERE project_id=? AND revision=? AND state='active'",crate::sql_value::sql_params![rev,seq,p,rev-1]).map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "historical root revision requires the current active registration",
        ));
    }
    c.execute("DELETE FROM roots WHERE project_id=?", [&p])
        .map_err(sql)?;
    for root in roots {
        let encoded = symbol(c, codec::encode(&root.path)?.as_bytes())?;
        c.execute(
            "INSERT INTO roots(project_id,canonical_key,encoded_path,last_seq) VALUES(?,?,?,?)",
            crate::sql_value::sql_params![p, root.canonical_key, encoded, seq],
        )
        .map_err(sql)?;
    }
    codec::aux(c, seq, facts)
}
