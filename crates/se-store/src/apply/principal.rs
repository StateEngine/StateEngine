//! Name uniqueness, terminal retirement, and retired-target guards inside the writer transaction.
use crate::{connection, error::*, identity, *};
use rusqlite::{Connection, OptionalExtension};

pub(crate) const RETIRED_REFUSAL: &str = "This temporary agent is retired; export its history with se handoff export --from <agent> and create a new agent with se agent add.";

pub(super) fn require_ephemeral_schema(c: &Connection) -> StoreResult<()> {
    if connection::info(c)?.schema_version < 17 {
        return Err(fail(
            StoreErrorCode::MigrationFailed,
            "ephemeral agent lifecycle requires schema 17; start se up for the verified migration",
        ));
    }
    Ok(())
}

pub(super) fn register(x: &super::Ctx<'_>, body: EventBody<InputText>) -> StoreResult<()> {
    let (c, header, seq, revision) = (x.c, x.header, x.seq, x.revision);
    let EventBody::PrincipalRegistered {
        principal,
        kind,
        owner,
        created_by,
        name,
        ephemeral,
        ..
    } = body
    else {
        return Err(invalid("principal registration dispatch"));
    };
    if let Some(spec) = ephemeral {
        require_ephemeral_schema(c)?;
        if !matches!(kind, PrincipalKind::Agent) || x.pk.is_none() {
            return Err(invalid("ephemeral registration requires a project agent"));
        }
        if spec.ttl_seconds == 0 || spec.ttl_seconds > 86_400 {
            return Err(invalid("ephemeral ttl_seconds must be within 1..=86400"));
        }
    }
    if name.is_empty() || name.len() > 64 {
        return Err(invalid("principal name bounds"));
    }
    if matches!(principal, Actor::Agent(_))
        && (!name.as_bytes()[0].is_ascii_alphanumeric()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b" ._-".contains(&b)))
    {
        return Err(invalid("agent name grammar"));
    }
    if matches!(kind, PrincipalKind::Agent) != matches!(principal, Actor::Agent(_)) {
        return Err(invalid("principal kind differs from ID"));
    }
    name_available(c, &header.scope, &principal, &name)?;
    let a = x.actor(&principal)?;
    if matches!(principal, Actor::Agent(_)) {
        let collision: bool = c
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM owners WHERE human_id=?)",
                [&a],
                |r| crate::sql_value::value(r, 0),
            )
            .map_err(sql)?;
        if collision {
            return Err(fail(
                StoreErrorCode::EventIdConflict,
                "agent identity bytes collide with an existing human; allocate a fresh agent ID",
            ));
        }
    }
    let own = identity::key(c, "human", owner.as_str(), &[0], true)?;
    if x.pk.is_none() {
        if principal != Actor::Human(owner) || header.actor != principal || created_by.is_some() {
            return Err(invalid(
                "registry owner bootstrap requires self owner, no invented creator",
            ));
        }
        c.execute(
            "INSERT INTO owners(human_id,display_name,first_seq,revision,last_seq) VALUES(?,?,?,?,?)",
            crate::sql_value::sql_params![a, name, seq, revision, seq],
        )
        .map_err(sql)?;
    } else {
        if header.door != Door::Import
            && header.actor != Actor::Human(owner.clone())
            && created_by.as_ref() != Some(&header.actor)
        {
            return Err(fail(
                StoreErrorCode::CreatorControlRefused,
                "creator differs from admitted actor",
            ));
        }
        let creator = created_by.as_ref().map(|a| x.actor(a)).transpose()?;
        insert_project_principal(
            c,
            ProjectPrincipal {
                project: x.project()?,
                key: &a,
                kind,
                owner: &own,
                creator,
                name: &name,
                seq,
                revision,
                ephemeral,
            },
        )?;
        c.execute(
            "INSERT INTO resume_heads(project_id,principal_id,unread_count,pending_effect_count,last_seq) VALUES(?,?,0,0,?)",
            crate::sql_value::sql_params![x.project()?, a, seq],
        )
        .map_err(sql)?;
    }
    Ok(())
}

pub(super) struct ProjectPrincipal<'a> {
    pub(super) project: &'a [u8],
    pub(super) key: &'a [u8],
    pub(super) kind: PrincipalKind,
    pub(super) owner: &'a [u8],
    pub(super) creator: Option<Vec<u8>>,
    pub(super) name: &'a str,
    pub(super) seq: i64,
    pub(super) revision: u64,
    pub(super) ephemeral: Option<EphemeralSpec>,
}

pub(super) fn insert_project_principal(
    c: &Connection,
    row: ProjectPrincipal<'_>,
) -> StoreResult<()> {
    let kind_wire = if matches!(row.kind, PrincipalKind::Agent) {
        "agent"
    } else {
        "human"
    };
    if connection::info(c)?.schema_version >= 17 {
        let (one_shot, ttl): (i64, Option<i64>) = match row.ephemeral {
            Some(spec) => (i64::from(spec.one_shot), Some(i64::from(spec.ttl_seconds))),
            None => (0, None),
        };
        c.execute(
            "INSERT INTO principals(project_id,principal_id,principal_kind,owner_id,created_by,display_name,first_seq,revision,last_seq,ephemeral_one_shot,ephemeral_ttl_seconds)
             VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            crate::sql_value::sql_params![
                row.project,
                row.key,
                kind_wire,
                row.owner,
                row.creator,
                row.name,
                row.seq,
                row.revision,
                row.seq,
                one_shot,
                ttl
            ],
        )
        .map_err(sql)?;
    } else {
        c.execute(
            "INSERT INTO principals(project_id,principal_id,principal_kind,owner_id,created_by,display_name,first_seq,revision,last_seq)
             VALUES(?,?,?,?,?,?,?,?,?)",
            crate::sql_value::sql_params![
                row.project,
                row.key,
                kind_wire,
                row.owner,
                row.creator,
                row.name,
                row.seq,
                row.revision,
                row.seq
            ],
        )
        .map_err(sql)?;
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
    let row: Option<(Vec<u8>, Option<i64>, bool)> = c
        .query_row(
            "SELECT owner_id, retired_seq, ephemeral_one_shot, ephemeral_ttl_seconds FROM principals WHERE project_id=? AND principal_id=? AND principal_kind='agent'",
            crate::sql_value::sql_params![project, target],
            |r| {
                let one_shot: i64 = crate::sql_value::value(r, 2)?;
                let ttl: Option<i64> = r.get(3)?;
                Ok((
                    crate::sql_value::value(r, 0)?,
                    r.get(1)?,
                    one_shot != 0 || ttl.is_some(),
                ))
            },
        )
        .optional()
        .map_err(sql)?;
    let Some((owner_bytes, retired_seq, is_ephemeral)) = row else {
        return Err(fail(
            StoreErrorCode::ReferenceMissing,
            "retirement target agent is not registered in this project",
        ));
    };
    if !is_ephemeral {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "only ephemeral temporary agents can be retired; saved seats remain permanent",
        ));
    }
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
