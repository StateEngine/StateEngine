use crate::{error::*, identity, *};
use rusqlite::Connection;
use se_types::{NativePath, ProcessFields, ProcessInstance, Sha256, StartIdentity};
use std::num::NonZeroU32;
pub(crate) fn name(value: ProcessState) -> &'static str {
    value.as_str()
}

pub(crate) fn body(
    c: &Connection,
    seq: i64,
    kind: &str,
    scope: &Scope,
) -> StoreResult<EventBody<StoredText>> {
    let p = crate::connection::project_id(c, scope, false)?;
    let (id,rev,to,expected,observation): (Vec<u8>,u64,String,Option<u64>,Option<Vec<u8>>) = c.query_row(
        "SELECT d.process_id,e.entity_revision,d.state,d.expected_revision,d.observation_event FROM process_data d JOIN events e ON e.seq=d.event_seq WHERE d.event_seq=?",
        [seq], |r|Ok((r.get(0)?,crate::sql_value::value(r,1)?,r.get(2)?,crate::sql_value::value(r,3)?,r.get(4)?))).map_err(sql)?;
    let value = Box::new(identity(c, seq, &p, &id, rev, &to, false)?);
    let to = state(&to)?;
    if kind == "process.registered" {
        if rev != 1 || expected.is_some() || observation.is_some() {
            return Err(invalid("process registration has transition facts"));
        }
        return Ok(EventBody::ProcessRegistered {
            identity: value,
            initial: to,
        });
    }
    let facts = super::facts(c, seq)?;
    let scope = crate::identity::scope_key(c, scope, false)?;
    Ok(EventBody::ProcessTransition {
        process: value.record.clone(),
        expected: Expected::Revision(super::revision(
            expected.ok_or_else(|| invalid("process expected revision absent"))?,
        )?),
        from: super::field(&facts, "from")?,
        to,
        observation: crate::identity::wire(
            c,
            "event",
            &observation.ok_or_else(|| invalid("process observation absent"))?,
            &scope,
        )?
        .parse()
        .map_err(invalid)?,
        outcome: super::field(&facts, "outcome")?,
        containment: value.containment.clone(),
        identity: value,
    })
}
pub(crate) fn stored_size(db: &Connection, seq: i64) -> StoreResult<usize> {
    let size:i64=db.query_row("SELECT length(d.custody)+COALESCE(length(d.birth_identity),0)+COALESCE(length(d.identity_cause),0)+COALESCE(length(d.containment_unknown_reason),0)+COALESCE(length(m.value),0)+COALESCE(length(b.value),0)+COALESCE(length(x.value),0) FROM process_data d LEFT JOIN symbols m ON m.id=d.machine_id LEFT JOIN symbols b ON b.id=d.boot_identity LEFT JOIN symbols x ON x.id=d.executable WHERE d.event_seq=?",[seq],|r|r.get(0)).map_err(sql)?;
    usize::try_from(size).map_err(invalid)
}
pub(crate) fn state(value: &str) -> StoreResult<ProcessState> {
    Ok(match value {
        "reserved" => ProcessState::Reserved,
        "starting" => ProcessState::Starting,
        "running" => ProcessState::Running,
        "leader-exited" => ProcessState::LeaderExited,
        "stop-requested" => ProcessState::StopRequested,
        "stop-unproved" => ProcessState::StopUnproved,
        "exited" => ProcessState::Exited,
        "lost" => ProcessState::Lost,
        "historical" => ProcessState::Historical,
        _ => {
            return Err(fail(
                StoreErrorCode::Unreadable,
                "unknown recorded process state",
            ));
        }
    })
}
fn symbol(db: &Connection, id: Option<i64>) -> StoreResult<Vec<u8>> {
    db.query_row(
        "SELECT value FROM symbols WHERE id=?",
        [id.ok_or_else(|| invalid("process identity symbol missing"))?],
        |r| r.get(0),
    )
    .map_err(sql)
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(crate) fn identity(
    db: &Connection,
    seq: i64,
    project: &[u8],
    id: &[u8],
    expected_revision: u64,
    expected_state: &str,
    owner_only: bool,
) -> StoreResult<ProcessIdentityRecord> {
    if stored_size(db, seq)? > 2 * 1024 * 1024 {
        return Err(fail(
            StoreErrorCode::Unreadable,
            "process identity row exceeds the materialization bound",
        ));
    }
    let mut q=db.prepare("SELECT d.*,e.project_id,e.kind,e.schema_version,e.entity_revision FROM process_data d JOIN events e ON e.seq=d.event_seq WHERE d.event_seq=?").map_err(sql)?;
    let mut rows = q.query([seq]).map_err(sql)?;
    let row = rows.next().map_err(sql)?.ok_or_else(|| {
        fail(
            StoreErrorCode::Unreadable,
            "recorded process head has no immutable fact",
        )
    })?;
    let blob = |name: &str| row.get::<_, Vec<u8>>(name).map_err(sql);
    let text = |name: &str| row.get::<_, String>(name).map_err(sql);
    let number = |name: &str| row.get::<_, Option<i64>>(name).map_err(sql);
    if blob("project_id")? != project
        || blob("process_id")? != id
        || u64::try_from(row.get::<_, i64>("entity_revision").map_err(sql)?).map_err(invalid)?
            != expected_revision
        || text("state")? != expected_state
        || row.get::<_, u16>("schema_version").map_err(sql)? != 1
        || !matches!(
            text("kind")?.as_str(),
            "process.registered" | "process.transition"
        )
    {
        return Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "process projection differs from its immutable head",
        ));
    }
    let principal = blob("principal_id")?;
    let registered: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM principals WHERE project_id=? AND principal_id=?)",
            rusqlite::params![project, &principal],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !registered {
        return Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "recorded process principal is not registered in its project",
        ));
    }
    let scope = [&[1u8][..], project].concat();
    let root_identity = match text("root_identity")?.as_str() {
        "no-child-created" => RootIdentityState::NoChildCreated,
        "unpublished" => RootIdentityState::Unpublished,
        "identified" => RootIdentityState::Identified,
        "unknown" => RootIdentityState::Unknown,
        _ => return Err(invalid("process root identity state")),
    };
    let instance = match text("identity_state")?.as_str() {
        "present" => {
            let birth = blob("birth_identity")?;
            let started: StartIdentity = serde_json::from_slice(&birth).map_err(invalid)?;
            let executable: NativePath =
                serde_json::from_slice(&symbol(db, number("executable")?)?).map_err(invalid)?;
            RecordedIdentity::Present(
                ProcessInstance::from_observation(ProcessFields {
                    machine: String::from_utf8(symbol(db, number("machine_id")?)?)
                        .map_err(invalid)?
                        .parse()
                        .map_err(invalid)?,
                    boot: String::from_utf8(symbol(db, number("boot_identity")?)?)
                        .map_err(invalid)?
                        .parse()
                        .map_err(invalid)?,
                    pid: NonZeroU32::new(
                        u32::try_from(
                            number("pid")?.ok_or_else(|| invalid("process pid missing"))?,
                        )
                        .map_err(invalid)?,
                    )
                    .ok_or_else(|| invalid("zero process pid"))?,
                    started,
                    executable,
                    argv_sha256: Sha256::from_bytes(
                        blob("argv_sha256")?
                            .try_into()
                            .map_err(|_| invalid("process argv hash length"))?,
                    ),
                })
                .map_err(invalid)?,
            )
        }
        "absent" => RecordedIdentity::Absent {
            reason: text("identity_cause")?,
        },
        "unreadable" if owner_only => {
            return Err(fail(
                StoreErrorCode::Unreadable,
                format!(
                    "recorded process identity unreadable: {}",
                    text("identity_cause")?
                ),
            ));
        }
        "unreadable" => RecordedIdentity::Unreadable {
            cause: text("identity_cause")?,
        },
        _ => return Err(invalid("process identity state")),
    };
    if !matches!(
        (&root_identity, &instance),
        (RootIdentityState::Identified, RecordedIdentity::Present(_))
            | (
                RootIdentityState::NoChildCreated | RootIdentityState::Unpublished,
                RecordedIdentity::Absent { .. }
            )
    ) && (owner_only
        || !matches!(
            (&root_identity, &instance, expected_state),
            (
                RootIdentityState::Unknown,
                RecordedIdentity::Absent { .. } | RecordedIdentity::Unreadable { .. },
                "lost" | "historical"
            )
        ))
    {
        return Err(fail(
            StoreErrorCode::Unreadable,
            "unresolved process has unknown or inconsistent root identity",
        ));
    }
    let observed = || {
        number("containment_observed_at_us")?
            .ok_or_else(|| invalid("containment observation missing"))
    };
    let containment = match text("containment")?.as_str() {
        "not-launched" => ContainmentFact::NotLaunched,
        "unknown" => ContainmentFact::Unknown {
            reason: text("containment_unknown_reason")?,
        },
        "cgroup" | "job" | "process-group" => ContainmentFact::Contained {
            kind: match text("containment")?.as_str() {
                "cgroup" => ContainmentKind::Cgroup,
                "job" => ContainmentKind::Job,
                _ => ContainmentKind::ProcessGroup,
            },
            observed_at_us: observed()?,
        },
        "uncontained" => ContainmentFact::Uncontained {
            cause: match text("containment_cause")?.as_str() {
                "no-user-manager" => ContainmentCause::NoUserManager,
                "no-delegation" => ContainmentCause::NoDelegation,
                "cgroup-v2-absent" => ContainmentCause::CgroupV2Absent,
                "cgroup-unreadable" => ContainmentCause::CgroupUnreadable,
                "scope-create-failed" => ContainmentCause::ScopeCreateFailed,
                _ => return Err(invalid("containment cause")),
            },
            observed_at_us: observed()?,
            probe: row
                .get::<_, Option<Vec<u8>>>("containment_probe")
                .map_err(sql)?
                .map(|id| {
                    identity::wire(db, "event", &id, &scope)
                        .and_then(|v| v.parse().map_err(invalid))
                })
                .transpose()?,
        },
        _ => return Err(invalid("containment state")),
    };
    let version: u16 = row.get("custody_version").map_err(sql)?;
    let record = blob("custody")?;
    if version != 1 || record.is_empty() || record.len() > 1024 * 1024 {
        return Err(fail(
            StoreErrorCode::Unreadable,
            "process custody version/bytes missing or unsupported",
        ));
    }
    Ok(ProcessIdentityRecord {
        record: identity::wire(db, "lifecycle", id, &scope)?
            .parse()
            .map_err(invalid)?,
        principal: identity::actor(db, &principal, &scope)?,
        session: row
            .get::<_, Option<Vec<u8>>>("target_session_id")
            .map_err(sql)?
            .map(|id| {
                identity::wire(db, "session", &id, &scope).and_then(|v| v.parse().map_err(invalid))
            })
            .transpose()?,
        root_identity,
        instance,
        custody: NativeCustody {
            format_version: version,
            record,
        },
        containment,
    })
}
