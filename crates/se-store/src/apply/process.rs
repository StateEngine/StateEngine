//! Persist witnessed launch/custody facts; no native observation or process action.
use super::*;
use crate::codec::process::{name, state};
pub(super) fn revision(c: &Connection, event: &NewEvent) -> StoreResult<u64> {
    let (id, want) = match &event.body {
        EventBody::ProcessRegistered { identity, .. } => (&identity.record, Expected::Absent),
        EventBody::ProcessTransition {
            process, expected, ..
        } => (process, *expected),
        _ => return Err(invalid("process revision dispatch")),
    };
    let p = project_id(c, &event.header.scope, false)?;
    let scope = scope_key(c, &event.header.scope, false)?;
    let id = key(c, "lifecycle", id.as_str(), &scope, false)?;
    expected(
        c,
        "processes",
        "project_id=? AND process_id=?",
        &[&p, &id],
        want,
    )
}
fn legal(from: ProcessState, to: ProcessState) -> bool {
    use ProcessState::*;
    matches!(
        (from, to),
        (Reserved, Starting | Exited | Lost)
            | (Starting, Running | StopRequested | Exited | Lost)
            | (Running, LeaderExited | StopRequested | Exited | Lost)
            | (LeaderExited, StopRequested | Exited | Lost)
            | (StopRequested, StopUnproved | Exited | Lost)
            | (StopUnproved, StopRequested | Exited | Lost)
            | (Lost, Running | LeaderExited | StopUnproved | Exited)
    )
}
fn shape(identity: &ProcessIdentityRecord, state: ProcessState) -> StoreResult<()> {
    if identity.custody.format_version != 1
        || identity.custody.record.is_empty()
        || identity.custody.record.len() > 1024 * 1024
    {
        return Err(invalid(
            "process custody requires bounded nonempty version-1 bytes",
        ));
    }
    let valid = matches!(
        (&identity.root_identity, &identity.instance),
        (RootIdentityState::Identified, RecordedIdentity::Present(_))
            | (
                RootIdentityState::NoChildCreated | RootIdentityState::Unpublished,
                RecordedIdentity::Absent { .. }
            )
    ) || (matches!(state, ProcessState::Lost | ProcessState::Historical)
        && matches!(
            (&identity.root_identity, &identity.instance),
            (
                RootIdentityState::Unknown,
                RecordedIdentity::Absent { .. } | RecordedIdentity::Unreadable { .. }
            )
        ));
    if !valid
        || (state == ProcessState::Reserved
            && identity.root_identity != RootIdentityState::NoChildCreated)
        || (matches!(state, ProcessState::Running | ProcessState::LeaderExited)
            && identity.root_identity != RootIdentityState::Identified)
        || (matches!(
            state,
            ProcessState::StopRequested | ProcessState::StopUnproved | ProcessState::Exited
        ) && identity.root_identity == RootIdentityState::Unknown)
    {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "process state/root identity facts disagree",
        ));
    }
    if let RecordedIdentity::Absent { reason } | RecordedIdentity::Unreadable { cause: reason } =
        &identity.instance
        && (reason.is_empty() || reason.len() > 16384)
    {
        return Err(invalid("process identity absence/unreadable reason bounds"));
    }
    if let ContainmentFact::Unknown { reason } = &identity.containment
        && (reason.is_empty() || reason.len() > 16384)
    {
        return Err(invalid("process containment unknown reason bounds"));
    }
    Ok(())
}
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    lease: &LeaseIdentity,
) -> StoreResult<()> {
    if lease.mode != LeaseMode::Host {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "native process facts require the owning host writer",
        ));
    }
    let p = project_id(c, &h.scope, false)?;
    let scope = scope_key(c, &h.scope, false)?;
    let (identity, to, expected_revision, observation, outcome, from) = match body {
        EventBody::ProcessRegistered { identity, initial } => {
            if !matches!(
                initial,
                ProcessState::Reserved | ProcessState::Starting | ProcessState::Running
            ) {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "wave-1 registration requires a reservation, prepared scope or witnessed running process",
                ));
            }
            (identity, initial, None, None, None, None)
        }
        EventBody::ProcessTransition {
            process,
            identity,
            expected,
            from,
            to,
            observation,
            outcome,
            containment,
        } => {
            if process != identity.record
                || !legal(from, to)
                || outcome.is_empty()
                || outcome.len() > 16384
                || codec::encode(&containment)? != codec::encode(&identity.containment)?
            {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "process transition identity/state/outcome/containment disagrees",
                ));
            }
            let Expected::Revision(expected) = expected else {
                return Err(invalid("process transition requires an exact revision"));
            };
            session::reference(c, &p, &scope, &observation)?;
            (
                identity,
                to,
                Some(expected.value.get()),
                Some(observation),
                Some(outcome),
                Some(from),
            )
        }
        _ => return Err(invalid("process apply dispatch")),
    };
    shape(&identity, to)?;
    let id = key(c, "lifecycle", identity.record.as_str(), &scope, true)?;
    let principal = key(
        c,
        identity.principal.kind(),
        identity.principal.wire(),
        if identity.principal.kind() == "human" {
            &[0]
        } else {
            &scope
        },
        false,
    )?;
    let owner: Option<Vec<u8>> = c
        .query_row(
            "SELECT owner_id FROM principals WHERE project_id=? AND principal_id=?",
            rusqlite::params![p, principal],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    let owner = owner.ok_or_else(|| {
        fail(
            StoreErrorCode::ReferenceMissing,
            "process principal is not registered in its project",
        )
    })?;
    let permitted = match &h.actor {
        Actor::Human(human) => key(c, "human", human.as_str(), &[0], false)? == owner,
        Actor::Agent(_) => h.actor == identity.principal && h.session == identity.session,
    };
    if !permitted {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "process fact actor differs from its admitted principal/owner",
        ));
    }
    let target = identity
        .session
        .as_ref()
        .map(|s| key(c, "session", s.as_str(), &scope, false))
        .transpose()?;
    if let Some(target) = &target {
        let valid: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND session_id=? AND agent_id=?)",rusqlite::params![p,target,principal],|r|r.get(0)).map_err(sql)?;
        if !valid {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "process session belongs to another principal or is absent",
            ));
        }
    }
    if let Some(from) = from {
        let (old_seq, old_state, released): (i64,String,bool) = c.query_row("SELECT last_seq,state,ownership_released FROM processes WHERE project_id=? AND process_id=?",rusqlite::params![p,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(sql)?;
        if released || state(&old_state)? != from {
            return Err(fail(
                StoreErrorCode::InvalidTransition,
                "process source state or retained ownership differs",
            ));
        }
        let old = codec::process::identity(c, old_seq, &p, &id, rev - 1, &old_state, false)?;
        if old.principal != identity.principal
            || old.session != identity.session
            || matches!((&old.instance,&identity.instance),(RecordedIdentity::Present(a),RecordedIdentity::Present(b)) if a != b)
            || matches!(
                (&old.instance, &identity.instance),
                (
                    RecordedIdentity::Present(_),
                    RecordedIdentity::Absent { .. }
                )
            )
        {
            return Err(fail(
                StoreErrorCode::SourceChanged,
                "process principal/session/native birth identity cannot be replaced",
            ));
        }
    }
    let (identity_state, cause, machine, boot, pid, birth, executable, argv) =
        match &identity.instance {
            RecordedIdentity::Present(instance) => {
                let f = instance.fields();
                (
                    "present",
                    None,
                    Some(symbol(c, f.machine.as_str().as_bytes())?),
                    Some(symbol(c, f.boot.as_str().as_bytes())?),
                    Some(f.pid.get()),
                    Some(codec::encode(&f.started)?.into_bytes()),
                    Some(symbol(c, codec::encode(&f.executable)?.as_bytes())?),
                    Some(f.argv_sha256.as_bytes().to_vec()),
                )
            }
            RecordedIdentity::Absent { reason } => (
                "absent",
                Some(reason.clone()),
                None,
                None,
                None,
                None,
                None,
                None,
            ),
            RecordedIdentity::Unreadable { cause } => (
                "unreadable",
                Some(cause.clone()),
                None,
                None,
                None,
                None,
                None,
                None,
            ),
        };
    let root = match identity.root_identity {
        RootIdentityState::NoChildCreated => "no-child-created",
        RootIdentityState::Unpublished => "unpublished",
        RootIdentityState::Identified => "identified",
        RootIdentityState::Unknown => "unknown",
    };
    let (containment, containment_cause, unknown, observed, probe) = match &identity.containment {
        ContainmentFact::NotLaunched => ("not-launched", None, None, None, None),
        ContainmentFact::Unknown { reason } => ("unknown", None, Some(reason.clone()), None, None),
        ContainmentFact::Contained {
            kind,
            observed_at_us,
        } => (
            match kind {
                ContainmentKind::Cgroup => "cgroup",
                ContainmentKind::Job => "job",
                ContainmentKind::ProcessGroup => "process-group",
            },
            None,
            None,
            Some(*observed_at_us),
            None,
        ),
        ContainmentFact::Uncontained {
            cause,
            observed_at_us,
            probe,
        } => {
            let cause = match cause {
                ContainmentCause::NoUserManager => "no-user-manager",
                ContainmentCause::NoDelegation => "no-delegation",
                ContainmentCause::CgroupV2Absent => "cgroup-v2-absent",
                ContainmentCause::CgroupUnreadable => "cgroup-unreadable",
                ContainmentCause::ScopeCreateFailed => "scope-create-failed",
            };
            if let Some(probe) = probe {
                session::reference(c, &p, &scope, probe)?;
            }
            (
                "uncontained",
                Some(cause),
                None,
                Some(*observed_at_us),
                probe
                    .as_ref()
                    .map(|e| key(c, "event", e.as_str(), &scope, false))
                    .transpose()?,
            )
        }
    };
    let observation = observation
        .as_ref()
        .map(|e| key(c, "event", e.as_str(), &scope, false))
        .transpose()?;
    c.execute("INSERT INTO process_data(event_seq,process_id,principal_id,target_session_id,root_identity,identity_state,identity_cause,machine_id,boot_identity,pid,birth_identity,executable,argv_sha256,custody_version,custody,containment,containment_cause,containment_unknown_reason,containment_observed_at_us,containment_probe,state,expected_revision,observation_event) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",crate::sql_value::sql_params![seq,id,principal,target,root,identity_state,cause,machine,boot,pid,birth,executable,argv,identity.custody.format_version,identity.custody.record,containment,containment_cause,unknown,observed,probe,name(to),expected_revision,observation]).map_err(sql)?;
    if let Some(from) = from {
        codec::aux(c, seq, serde_json::json!({"from":from,"outcome":outcome}))?;
        let changed = c.execute("UPDATE processes SET revision=?,last_seq=?,state=? WHERE project_id=? AND process_id=? AND revision=? AND state=? AND ownership_released=0",crate::sql_value::sql_params![rev,seq,name(to),p,id,rev-1,name(from)]).map_err(sql)?;
        if changed != 1 {
            return Err(fail(
                StoreErrorCode::RevisionConflict,
                "process head changed",
            ));
        }
    } else {
        c.execute("INSERT INTO processes(project_id,process_id,first_seq,revision,last_seq,state) VALUES(?,?,?,?,?,?)",crate::sql_value::sql_params![p,id,seq,rev,seq,name(to)]).map_err(sql)?;
    }
    Ok(())
}
