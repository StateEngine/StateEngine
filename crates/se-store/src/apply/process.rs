//! Persist witnessed launch/custody facts; no native observation or process action.
use super::*;
mod console;
mod release;
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
            // Pre-exec root publication and its single console argv handoff;
            // apply checks the exact retained identity and custody.
            | (Starting, Starting | Running | StopRequested | Exited | Lost)
            | (Running, LeaderExited | StopRequested | Exited | Lost)
            | (LeaderExited, StopRequested | Exited | Lost)
            | (StopRequested, StopUnproved | Exited | Lost)
            // StopUnproved → StopUnproved is only the owner's uncontained
            // ownership release; apply checks its custody marker.
            | (StopUnproved, StopUnproved | StopRequested | Exited | Lost)
            | (Lost, Running | LeaderExited | StopUnproved | Exited)
    )
}
/// The one authorized image change: a checkpointed pre-exec root publishing
/// its verified vendor image. Machine, boot, PID, native
/// birth and argv digest stay identical; only the executable may differ.
fn exec_image(
    from: ProcessState,
    to: ProcessState,
    old: &se_types::ProcessInstance,
    new: &se_types::ProcessInstance,
) -> bool {
    let (a, b) = (old.fields(), new.fields());
    from == ProcessState::Starting
        && matches!(to, ProcessState::Starting | ProcessState::Running)
        && a.machine == b.machine
        && a.boot == b.boot
        && a.pid == b.pid
        && a.started == b.started
        && a.argv_sha256 == b.argv_sha256
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
        return Err(invalid_transition(
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
#[derive(Default)]
struct ContainmentCols {
    kind: &'static str,
    cause: Option<&'static str>,
    unknown: Option<String>,
    observed: Option<i64>,
    probe: Option<Vec<u8>>,
}
fn verify_actor_and_session(
    c: &Connection,
    h: &EventHeader,
    keys: (&[u8], &[u8]),
    identity: &ProcessIdentityRecord,
    authority: &ApplyAuthority<'_>,
) -> StoreResult<(Vec<u8>, Option<Vec<u8>>)> {
    let (p, scope) = keys;
    let principal = actor_key(c, &identity.principal, scope, false)?;
    let owner: Vec<u8> = c
        .query_row(
            "SELECT owner_id FROM principals WHERE project_id=? AND principal_id=?",
            rusqlite::params![p, principal],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?
        .ok_or_else(|| reference_missing("process principal is not registered in its project"))?;
    let permitted = match (&h.actor, &identity.principal) {
        (Actor::Remote(_), Actor::Agent(_)) => authority.remote_launch.is_some(),
        (Actor::Remote(_) | Actor::Guest, _) | (_, Actor::Remote(_) | Actor::Guest) => false,
        (Actor::Human(human), _) => key(c, "human", human.as_str(), &[0], false)? == owner,
        (Actor::Agent(_), _) if h.actor == identity.principal => h.session == identity.session,
        (Actor::Agent(creator), Actor::Agent(_)) => {
            crate::creator::require(c, p, scope, creator, &principal)?;
            true
        }
        (Actor::Agent(_), Actor::Human(_)) => false,
    };
    if !permitted {
        return Err(scope_mismatch(
            "process fact actor differs from its admitted principal/owner",
        ));
    }
    let target = identity
        .session
        .as_ref()
        .map(|s| key(c, "session", s.as_str(), scope, false))
        .transpose()?;
    if let Some(target) = &target {
        let valid:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND session_id=? AND agent_id=?)",rusqlite::params![p,target,principal],|r|r.get(0)).map_err(sql)?;
        if !valid {
            return Err(scope_mismatch(
                "process session belongs to another principal or is absent",
            ));
        }
    }
    Ok((principal, target))
}
fn verify_transition(
    c: &Connection,
    h: &EventHeader,
    keys: (&[u8], &[u8], u64),
    states: (ProcessState, ProcessState),
    lease: &LeaseIdentity,
    identity: &ProcessIdentityRecord,
    outcome: Option<&str>,
) -> StoreResult<()> {
    let ((p, id, rev), (from, to)) = (keys, states);
    let (old_seq, old_state, released):(i64,String,bool)=c.query_row("SELECT last_seq,state,ownership_released FROM processes WHERE project_id=? AND process_id=?",rusqlite::params![p,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(sql)?;
    if released || state(&old_state)? != from {
        return Err(invalid_transition(
            "process source state or retained ownership differs",
        ));
    }
    let old = codec::process::identity(c, old_seq, p, id, rev - 1, &old_state, false)?;
    if from == ProcessState::StopUnproved && to == ProcessState::StopUnproved {
        release::apply(c, h, p, &old, identity, rev, lease)?;
    }
    let console = console::argv(c, old_seq, (from, to), &old, identity, outcome)?;
    let exec = from == ProcessState::Starting
        && to == ProcessState::Starting
        && outcome == Some("exec-observed")
        && matches!(
            codec::facts(c, old_seq)?
                .get("outcome")
                .and_then(serde_json::Value::as_str),
            Some("root-prepared" | "console-prepared")
        )
        && matches!((&old.instance, &identity.instance), (RecordedIdentity::Present(a), RecordedIdentity::Present(b)) if exec_image(from, to, a, b));
    if from == ProcessState::Starting
        && to == ProcessState::Starting
        && !(old.root_identity == RootIdentityState::Unpublished
            && matches!(old.instance, RecordedIdentity::Absent { .. })
            && identity.root_identity == RootIdentityState::Identified)
        && !console
        && !exec
    {
        return Err(invalid_transition(
            "Starting to Starting requires root publication, one console argv handoff, or the exact witnessed exec checkpoint",
        ));
    }
    if old.principal != identity.principal
        || old.session != identity.session
        || matches!((&old.instance, &identity.instance), (RecordedIdentity::Present(a), RecordedIdentity::Present(b)) if a != b && !exec_image(from, to, a, b) && !console)
        || matches!(
            (&old.instance, &identity.instance),
            (
                RecordedIdentity::Present(_),
                RecordedIdentity::Absent { .. } | RecordedIdentity::Unreadable { .. }
            )
        )
    {
        return Err(source_changed(
            "process principal/session/native birth identity cannot be replaced",
        ));
    }
    Ok(())
}
fn encode_containment(
    c: &Connection,
    p: &[u8],
    scope: &[u8],
    fact: &ContainmentFact,
) -> StoreResult<ContainmentCols> {
    match fact {
        ContainmentFact::NotLaunched => Ok(ContainmentCols {
            kind: "not-launched",
            ..Default::default()
        }),
        ContainmentFact::Unknown { reason } => Ok(ContainmentCols {
            kind: "unknown",
            unknown: Some(reason.clone()),
            ..Default::default()
        }),
        ContainmentFact::Contained {
            kind,
            observed_at_us,
        } => Ok(ContainmentCols {
            kind: match kind {
                ContainmentKind::Cgroup => "cgroup",
                ContainmentKind::Job => "job",
                ContainmentKind::ProcessGroup => "process-group",
            },
            observed: Some(*observed_at_us),
            ..Default::default()
        }),
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
                session::reference(c, p, scope, probe)?;
            }
            Ok(ContainmentCols {
                kind: "uncontained",
                cause: Some(cause),
                unknown: None,
                observed: Some(*observed_at_us),
                probe: probe
                    .as_ref()
                    .map(|e| key(c, "event", e.as_str(), scope, false))
                    .transpose()?,
            })
        }
    }
}
#[derive(Default)]
struct IdentityCols {
    state: &'static str,
    cause: Option<String>,
    machine: Option<i64>,
    boot: Option<i64>,
    pid: Option<u32>,
    birth: Option<Vec<u8>>,
    executable: Option<i64>,
    argv: Option<Vec<u8>>,
}
fn encode_identity(c: &Connection, instance: &RecordedIdentity) -> StoreResult<IdentityCols> {
    match instance {
        RecordedIdentity::Present(instance) => {
            let f = instance.fields();
            Ok(IdentityCols {
                state: "present",
                cause: None,
                machine: Some(symbol(c, f.machine.as_str().as_bytes())?),
                boot: Some(symbol(c, f.boot.as_str().as_bytes())?),
                pid: Some(f.pid.get()),
                birth: Some(codec::encode(&f.started)?.into_bytes()),
                executable: Some(symbol(c, codec::encode(&f.executable)?.as_bytes())?),
                argv: Some(f.argv_sha256.as_bytes().to_vec()),
            })
        }
        RecordedIdentity::Absent { reason } => Ok(IdentityCols {
            state: "absent",
            cause: Some(reason.clone()),
            ..Default::default()
        }),
        RecordedIdentity::Unreadable { cause } => Ok(IdentityCols {
            state: "unreadable",
            cause: Some(cause.clone()),
            ..Default::default()
        }),
    }
}
pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    rev: u64,
    authority: &ApplyAuthority<'_>,
) -> StoreResult<()> {
    let lease = authority.lease;
    if lease.mode != LeaseMode::Host {
        return Err(invalid_transition(
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
                return Err(invalid_transition(
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
                return Err(invalid_transition(
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
    let (principal, target) = verify_actor_and_session(c, h, (&p, &scope), &identity, authority)?;
    if let Some(from) = from {
        verify_transition(
            c,
            h,
            (&p, &id, rev),
            (from, to),
            lease,
            &identity,
            outcome.as_deref(),
        )?;
    }
    let cols = encode_identity(c, &identity.instance)?;
    let root = match identity.root_identity {
        RootIdentityState::NoChildCreated => "no-child-created",
        RootIdentityState::Unpublished => "unpublished",
        RootIdentityState::Identified => "identified",
        RootIdentityState::Unknown => "unknown",
    };
    let contain = encode_containment(c, &p, &scope, &identity.containment)?;
    let observation = observation
        .as_ref()
        .map(|e| key(c, "event", e.as_str(), &scope, false))
        .transpose()?;
    c.execute("INSERT INTO process_data(event_seq,process_id,principal_id,target_session_id,root_identity,identity_state,identity_cause,machine_id,boot_identity,pid,birth_identity,executable,argv_sha256,custody_version,custody,containment,containment_cause,containment_unknown_reason,containment_observed_at_us,containment_probe,state,expected_revision,observation_event) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",crate::sql_value::sql_params![seq,id,principal,target,root,cols.state,cols.cause,cols.machine,cols.boot,cols.pid,cols.birth,cols.executable,cols.argv,identity.custody.format_version,identity.custody.record,contain.kind,contain.cause,contain.unknown,contain.observed,contain.probe,name(to),expected_revision,observation]).map_err(sql)?;
    if let Some(from) = from {
        codec::aux(c, seq, serde_json::json!({"from":from,"outcome":outcome}))?;
        let released = from == ProcessState::StopUnproved && to == ProcessState::StopUnproved;
        let changed = c.execute("UPDATE processes SET revision=?,last_seq=?,state=?,ownership_released=? WHERE project_id=? AND process_id=? AND revision=? AND state=? AND ownership_released=0",crate::sql_value::sql_params![rev,seq,name(to),released,p,id,rev-1,name(from)]).map_err(sql)?;
        if changed != 1 {
            return Err(revision_conflict("process head changed"));
        }
    } else {
        c.execute("INSERT INTO processes(project_id,process_id,first_seq,revision,last_seq,state) VALUES(?,?,?,?,?,?)",crate::sql_value::sql_params![p,id,seq,rev,seq,name(to)]).map_err(sql)?;
    }
    Ok(())
}
