//! Name uniqueness, terminal retirement, and retired-target guards inside the writer transaction.
use crate::{connection, error::*, identity, *};
use rusqlite::{Connection, OptionalExtension};

pub(crate) const RETIRED_REFUSAL: &str =
    "This temporary agent is retired; start a new helper with se delegate --handoff ...";

pub(super) fn require_ephemeral_schema(c: &Connection) -> StoreResult<()> {
    if connection::info(c)?.schema_version < 17 {
        return Err(fail(
            StoreErrorCode::MigrationFailed,
            "ephemeral agent lifecycle requires schema 17; start se up for the verified migration",
        ));
    }
    Ok(())
}

pub(super) fn refuse_retired(
    c: &Connection,
    project: &[u8],
    principal_key: &[u8],
) -> StoreResult<()> {
    if connection::info(c)?.schema_version < 17 {
        return Ok(());
    }
    let retired: Option<Option<i64>> = c
        .query_row(
            "SELECT retired_seq FROM principals WHERE project_id=? AND principal_id=?",
            crate::sql_value::sql_params![project, principal_key],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql)?;
    if matches!(retired, Some(Some(_))) {
        return Err(fail(StoreErrorCode::InvalidTransition, RETIRED_REFUSAL));
    }
    Ok(())
}

pub(super) fn retire(
    c: &Connection,
    header: &EventHeader,
    scope: &[u8],
    project: &[u8],
    agent: &se_types::AgentId,
    final_session: Option<&se_types::SessionId>,
    seq: i64,
) -> StoreResult<()> {
    require_ephemeral_schema(c)?;
    let target = identity::key(c, "agent", agent.as_str(), scope, false)?;
    let row: Option<(Vec<u8>, Option<i64>)> = c
        .query_row(
            "SELECT owner_id, retired_seq FROM principals WHERE project_id=? AND principal_id=? AND principal_kind='agent'",
            crate::sql_value::sql_params![project, target],
            |r| Ok((crate::sql_value::value(r, 0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    let Some((owner_bytes, retired_seq)) = row else {
        return Err(fail(
            StoreErrorCode::ReferenceMissing,
            "retirement target agent is not registered in this project",
        ));
    };
    if retired_seq.is_some() {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "agent is already retired",
        ));
    }
    match &header.actor {
        Actor::Human(human) => {
            let actor_bytes = identity::key(c, "human", human.as_str(), &[0], false)?;
            if actor_bytes != owner_bytes {
                return Err(fail(
                    StoreErrorCode::CreatorControlRefused,
                    "only the project owner or direct creator with can-create may retire an agent",
                ));
            }
        }
        Actor::Agent(creator) => {
            crate::creator::require(c, project, scope, creator, &target)?;
        }
        _ => {
            return Err(fail(
                StoreErrorCode::CreatorControlRefused,
                "only the project owner or direct creator with can-create may retire an agent",
            ));
        }
    }
    if let Some(session) = final_session {
        let session_key = identity::key(c, "session", session.as_str(), scope, false)?;
        let exists: bool = c
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND agent_id=? AND session_id=?)",
                crate::sql_value::sql_params![project, target, session_key],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if !exists {
            return Err(fail(
                StoreErrorCode::ReferenceMissing,
                "final_session does not belong to this agent in this project",
            ));
        }
    }
    // Intentionally update ONLY retired_seq — never advance principals.last_seq
    // or principals.revision so principal_metadata and existing readers stay intact.
    let changed = c
        .execute(
            "UPDATE principals SET retired_seq=? WHERE project_id=? AND principal_id=? AND retired_seq IS NULL",
            crate::sql_value::sql_params![seq, project, target],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "agent is already retired",
        ));
    }
    Ok(())
}

pub(super) fn name_available(
    c: &Connection,
    scope: &Scope,
    principal: &Actor,
    name: &str,
) -> StoreResult<()> {
    let Scope::Project(project) = scope else {
        return Ok(());
    };
    let key = identity::scope_key(c, scope, false)?;
    let existing: Option<Vec<u8>> = c
        .query_row(
            "SELECT principal_id FROM principals WHERE project_id=? AND display_name=?",
            crate::sql_value::sql_params![crate::connection::project_id(c, scope, false)?, name],
            |row| crate::sql_value::value(row, 0),
        )
        .optional()
        .map_err(sql)?;
    if let Some(existing) = existing {
        let existing = identity::actor(c, &existing, &key)?;
        if existing != *principal {
            let mut error = fail(
                StoreErrorCode::AlreadyExists,
                "a principal already has this name in the selected project",
            );
            error.detail = StoreDetail::PrincipalNameConflict {
                project: project.clone(),
                name: name.into(),
                existing,
            };
            error.remedy.text = "Choose another name, or use the existing principal.".into();
            return Err(error);
        }
    }
    Ok(())
}
