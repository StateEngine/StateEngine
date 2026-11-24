//! Assignment projections, checked against current project authority.
use super::*;
use se_store_contract::assignment::{
    Assignment, AssignmentState, AssignmentTransition, transition,
};

fn captain(c: &Connection, p: &[u8]) -> StoreResult<Option<Actor>> {
    let seq: Option<i64> = c
        .query_row(
            "SELECT last_seq FROM project_captain WHERE project_id=?",
            [p],
            |row| crate::sql_value::value(row, 0),
        )
        .optional()
        .map_err(sql)?;
    match seq {
        None => Ok(None),
        Some(seq) => codec::field(&codec::facts(c, seq)?, "captain"),
    }
}

pub(super) fn require_closed(c: &Connection, project: &[u8]) -> StoreResult<()> {
    let open: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM assignments WHERE project_id=? AND state IN ('open','working','blocked'))",
        [project], |row| row.get(0),
    ).map_err(sql)?;
    if open {
        return Err(invalid_transition(
            "finish or hand back open and blocked assignments first",
        ));
    }
    Ok(())
}

pub(super) fn check_route(c: &Connection, h: &EventHeader, expected: &Actor) -> StoreResult<()> {
    let project = project_id(c, &h.scope, false)?;
    if !matches!(h.actor, Actor::Agent(_))
        || &h.actor == expected
        || captain(c, &project)?.as_ref() != Some(expected)
    {
        return Err(revision_conflict(
            "captain changed or sender is not crew; retry with the same request key",
        ));
    }
    Ok(())
}

fn state(value: &str) -> StoreResult<AssignmentState> {
    match value {
        "open" => Ok(AssignmentState::Open),
        "working" => Ok(AssignmentState::Working),
        "done" => Ok(AssignmentState::Done),
        "blocked" => Ok(AssignmentState::Blocked),
        "handed_back" => Ok(AssignmentState::HandedBack),
        _ => Err(invalid("unknown assignment state")),
    }
}
fn state_name(value: &AssignmentState) -> &'static str {
    match value {
        AssignmentState::Open => "open",
        AssignmentState::Working => "working",
        AssignmentState::Done => "done",
        AssignmentState::Blocked => "blocked",
        AssignmentState::HandedBack => "handed_back",
    }
}

fn floor_text(
    c: &Connection,
    h: &EventHeader,
    project: &[u8],
    scope: &[u8],
    floor_event: &se_types::EventId,
    assignee: &se_types::AgentId,
    captain: Option<&Actor>,
) -> StoreResult<String> {
    let key = key(c, "event", floor_event.as_str(), scope, false)?;
    let seq: i64 = c
        .query_row(
            "SELECT seq FROM events WHERE event_id=? AND project_id=?",
            crate::sql_value::sql_params![key, project],
            |row| row.get(0),
        )
        .map_err(sql)?;
    let EventBody::WorkMessageSent {
        work,
        body: StoredText::Present(text),
        ..
    } = codec::body(c, seq, "message.work_sent", &h.scope)?
    else {
        return Err(invalid("assignment floor message is unavailable"));
    };
    if !work.addressees.contains(assignee) {
        return Err(invalid(
            "assignment floor message must address its assignee",
        ));
    }
    if let Some(Actor::Agent(id)) = captain
        && !work.addressees.contains(id)
    {
        return Err(invalid(
            "assignment floor message must address its current captain",
        ));
    }
    Ok(text)
}

fn event_at(c: &Connection, seq: i64, scope: &[u8]) -> StoreResult<se_types::EventId> {
    let key: Vec<u8> = c
        .query_row("SELECT event_id FROM events WHERE seq=?", [seq], |row| {
            row.get(0)
        })
        .map_err(sql)?;
    wire(c, "event", &key, scope)?.try_into().map_err(invalid)
}

fn read_assignment(
    c: &Connection,
    project: &[u8],
    scope: &[u8],
    project_id: &se_types::ProjectId,
    id: &se_types::EventId,
) -> StoreResult<(Vec<u8>, Assignment)> {
    let key = key(c, "event", id.as_str(), scope, false)?;
    let (assignee, prior, last_seq): (Vec<u8>, String, i64) = c.query_row("SELECT assignee_id,state,last_seq FROM assignments WHERE project_id=? AND assignment_id=?", crate::sql_value::sql_params![project,key], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).map_err(sql)?;
    let agent = wire(c, "agent", &assignee, scope)?
        .try_into()
        .map_err(invalid)?;
    let record = Assignment {
        id: id.clone(),
        project: project_id.clone(),
        assignee: agent,
        state: state(&prior)?,
        latest_event: event_at(c, last_seq, scope)?,
    };
    Ok((assignee, record))
}

fn require_current_captain(
    body: &EventBody<InputText>,
    current_captain: Option<&Actor>,
) -> StoreResult<()> {
    let expected_captain = match body {
        EventBody::AssignmentOpened { captain, .. }
        | EventBody::AssignmentTransitioned { captain, .. } => captain,
        _ => return Err(invalid("assignment projection dispatch")),
    };
    if current_captain != Some(expected_captain) {
        return Err(revision_conflict(
            "captain changed; retry the same assignment request key",
        ));
    }
    Ok(())
}

pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    revision: u64,
    facts: Value,
) -> StoreResult<()> {
    let p = project_id(c, &h.scope, false)?;
    let scope = scope_key(c, &h.scope, false)?;
    let Scope::Project(project_id) = &h.scope else {
        return Err(invalid("assignment project scope"));
    };
    let current_captain = captain(c, &p)?;
    let owner = project::is_owner(c, h, &p)?;
    require_current_captain(&body, current_captain.as_ref())?;
    let floor_event = match &body {
        EventBody::AssignmentOpened { floor_event, .. }
        | EventBody::AssignmentTransitioned { floor_event, .. } => floor_event.clone(),
        _ => return Err(invalid("assignment projection dispatch")),
    };
    let (id, assignee, next, opened) = match body {
        EventBody::AssignmentOpened {
            project,
            assignment,
            assignee,
            floor_event,
            ..
        } => {
            if &project != project_id || !(owner || current_captain.as_ref() == Some(&h.actor)) {
                return Err(scope_mismatch(
                    "only the project owner or captain can assign work",
                ));
            }
            floor_text(
                c,
                h,
                &p,
                &scope,
                &floor_event,
                &assignee,
                current_captain.as_ref(),
            )?;
            let a = key(c, "agent", assignee.as_str(), &scope, false)?;
            let registered: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE project_id=? AND principal_id=? AND principal_kind='agent')", crate::sql_value::sql_params![p, a], |row| row.get(0)).map_err(sql)?;
            if !registered {
                return Err(reference_missing("choose a registered project agent"));
            }
            (assignment, a, AssignmentState::Open, true)
        }
        EventBody::AssignmentTransitioned {
            assignment,
            action,
            floor_event,
            ..
        } => {
            let (assignee, record) = read_assignment(c, &p, &scope, project_id, &assignment)?;
            let text = floor_text(
                c,
                h,
                &p,
                &scope,
                &floor_event,
                &record.assignee,
                current_captain.as_ref(),
            )?;
            let next = transition(
                &record,
                &action,
                &h.actor,
                owner,
                current_captain.as_ref(),
                matches!(action, AssignmentTransition::Block).then_some(text.as_str()),
            )
            .map_err(invalid)?;
            (assignment, assignee, next, false)
        }
        _ => return Err(invalid("assignment projection dispatch")),
    };
    write_projection(
        c,
        &p,
        &scope,
        Projection {
            id: &id,
            assignee: &assignee,
            state: &next,
            opened,
            seq,
            revision,
        },
    )?;
    record_floor(c, &p, &scope, &floor_event, &id)?;
    codec::aux(c, seq, facts)
}

fn record_floor(
    c: &Connection,
    project: &[u8],
    scope: &[u8],
    floor_event: &se_types::EventId,
    assignment: &se_types::EventId,
) -> StoreResult<()> {
    let floor_key = key(c, "event", floor_event.as_str(), scope, false)?;
    let assignment_key = key(c, "event", assignment.as_str(), scope, false)?;
    c.execute("INSERT INTO assignment_floor_events(project_id,floor_event_id,assignment_id) VALUES(?,?,?)", crate::sql_value::sql_params![project,floor_key,assignment_key]).map_err(sql)?;
    Ok(())
}

struct Projection<'a> {
    id: &'a se_types::EventId,
    assignee: &'a [u8],
    state: &'a AssignmentState,
    opened: bool,
    seq: i64,
    revision: u64,
}

fn write_projection(
    c: &Connection,
    project: &[u8],
    scope: &[u8],
    change: Projection<'_>,
) -> StoreResult<()> {
    let Projection {
        id: assignment,
        assignee,
        state: next,
        opened,
        seq,
        revision,
    } = change;
    let id = key(c, "event", assignment.as_str(), scope, false)?;
    if opened {
        c.execute("INSERT INTO assignments(project_id,assignment_id,assignee_id,state,revision,opened_seq,last_seq) VALUES(?,?,?,?,?,?,?)", crate::sql_value::sql_params![project,id,assignee,state_name(next),revision,seq,seq]).map_err(sql)?;
    } else {
        let changed = c.execute("UPDATE assignments SET state=?,revision=?,last_seq=? WHERE project_id=? AND assignment_id=? AND revision=?", crate::sql_value::sql_params![state_name(next),revision,seq,project,id,revision-1]).map_err(sql)?;
        if changed != 1 {
            return Err(revision_conflict("assignment changed before update"));
        }
    }
    Ok(())
}
