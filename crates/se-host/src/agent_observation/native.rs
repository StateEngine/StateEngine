//! Outside, exact-birth native readback. A stored activation is never liveness.
use super::*;
use se_core::ops::process_commit::ENDED_BY_REBOOT;
use se_proc::{CheckpointKind, CheckpointPrincipal, CheckpointSource, NativeState, ProcessRead};
use se_store::{Actor, RecordedIdentity};

fn probe_native_process(
    plan: &AgentObservationPlan,
    target: &crate::SessionIdentity,
    identity: &se_store::ProcessIdentityRecord,
    deadline: Instant,
) -> Result<Option<(se_proc::ProcessRecord, ProcessRead)>> {
    let checkpoint =
        se_proc::decode_checkpoint(identity.custody.format_version, &identity.custody.record)
            .map_err(|e| invalid(&format!("the native checkpoint must decode: {e}")))?;
    if checkpoint.lifecycle != identity.record
        || checkpoint.session.as_ref() != Some(&target.session)
        || !matches!(&checkpoint.principal, CheckpointPrincipal::Agent(agent) if agent == &target.agent)
        || identity.principal != Actor::Agent(target.agent.clone())
    {
        return Err(invalid(
            "matching native and recorded lifecycle/project/agent/session",
        ));
    }
    let RecordedIdentity::Present(instance) = &identity.instance else {
        return Err(invalid("the original recorded native process identity"));
    };
    if matches!(plan.recorded_exit, RecordedExit::Reboot) {
        bound(deadline)?;
        if !matches!(&checkpoint.checkpoint, CheckpointKind::Exit { witness, .. } if witness.ended_by_reboot())
        {
            return Err(invalid("a retained reboot exit witness for this lifecycle"));
        }
        let home = plan
            .command_home
            .as_ref()
            .ok_or_else(|| invalid("the local protected machine identity"))?;
        let files = crate::state_files::Files::open(home).map_err(|e| invalid(&e.to_string()))?;
        let machine = crate::state_files::machine_identity(&files)?;
        let current =
            se_proc::observe_reboot_boot(machine).map_err(|e| invalid(&format!("{e:?}")))?;
        let proof = se_proc::prove_reboot(&checkpoint, instance, &current);
        bound(deadline)?;
        return match proof {
            se_proc::RebootProof::Proven(_) => Ok(None),
            se_proc::RebootProof::NotProven => {
                Err(invalid("a proven reboot for the recorded root"))
            }
            se_proc::RebootProof::Unreadable(reason) => Err(invalid(&reason)),
        };
    }
    let record = match checkpoint.checkpoint {
        CheckpointKind::Process(record) => record,
        CheckpointKind::Exit { source, .. } => match *source {
            CheckpointSource::Process(record) => record,
            _ => {
                return Err(invalid(
                    "an identified process source in the exit checkpoint",
                ));
            }
        },
        _ => {
            return Err(invalid(
                "a published process or identified terminal cleanup checkpoint",
            ));
        }
    };
    se_proc::match_recorded_root(&record.root, Some(record.argv_sha256), instance)
        .map_err(|reason| invalid(&reason))?;
    bound(deadline)?;
    let observation = se_proc::read_process(record.root.machine.clone(), record.root.pid)
        .map_err(|e| invalid(&format!("readable native process identity: {e:?}")))?;
    Ok(Some((record, observation)))
}

fn classify_observation(
    plan: &mut AgentObservationPlan,
    record: &se_proc::ProcessRecord,
    observation: ProcessRead,
    deadline: Instant,
) -> Result<Option<(Read<String>, u128)>> {
    let result = match observation {
        // Birth is identity. The executable path is reported as the process now
        // reports it, so an in-place update or rename shows here, not as loss.
        ProcessRead::Present(actual) if actual.identity.same_birth(&record.root) => {
            match actual.state {
                NativeState::Running | NativeState::Stopped => {
                    match se_proc::observe_process_birth(&record.root, deadline) {
                        Ok(born) => {
                            plan.row.session.process = Some(se_core::ops::ProcessView {
                                pid: record.root.pid.0,
                                started_at: se_core::ops::receipt::timestamp(born.unix_micros())?,
                                exe: actual.identity.image.to_string_lossy().into_owned(),
                                machine_id: record.root.machine.to_string(),
                            })
                        }
                        Err(error) => {
                            plan.row.session.state = "unknown".into();
                            plan.row.session.liveness =
                                unreadable("pinned native process birth", format!("{error:?}"));
                            return Ok(None);
                        }
                    }
                    (
                        Read::Present {
                            value: "live".into(),
                        },
                        actual.observed_at_unix_ns,
                    )
                }
                NativeState::Exited | NativeState::ExitedAwaitingReap => (
                    Read::Present {
                        value: "exited".into(),
                    },
                    actual.observed_at_unix_ns,
                ),
            }
        }
        ProcessRead::Absent {
            observed_at_unix_ns,
            ..
        } => (
            Read::Absent {
                checked: "the exact recorded process PID is absent at this native observation"
                    .into(),
            },
            observed_at_unix_ns,
        ),
        ProcessRead::ExitedRecord {
            boot,
            start,
            observed_at_unix_ns,
            ..
        } if boot == record.root.boot && start == record.root.start => (
            Read::Present {
                value: "exited".into(),
            },
            observed_at_unix_ns,
        ),
        _ => {
            plan.row.session.state = "unknown".into();
            plan.row.session.liveness = unreadable(
                "native process identity",
                "PID now names a different birth or boot; no successor is attributed to this session",
            );
            return Ok(None);
        }
    };
    Ok(Some(result))
}

pub(super) fn observe(plan: &mut AgentObservationPlan, deadline: Instant) -> Result<()> {
    let target = plan
        .identity
        .as_ref()
        .ok_or_else(|| invalid("a launched session target"))?;
    plan.row.session.process = None;
    plan.row.session.end_reason = None;
    plan.row.session.observed_at = None;
    plan.row.session.state = if plan.row.session.recorded_state.as_deref() == Some("prepared") {
        "starting"
    } else {
        "unknown"
    }
    .into();
    let identity = match &plan.process {
        Read::Present { value } => value,
        other => {
            plan.row.session.liveness = other.clone().map(|_| String::new());
            return Ok(());
        }
    };
    let (record, observation) = match probe_native_process(plan, target, identity, deadline) {
        Ok(Some(value)) => value,
        Ok(None) => {
            plan.row.session.state = "stopped".into();
            plan.row.session.end_reason = Some(ENDED_BY_REBOOT.into());
            plan.row.session.liveness = Read::Present {
                value: "exited".into(),
            };
            return Ok(());
        }
        Err(error) => {
            plan.row.session.state = "unknown".into();
            plan.row.session.liveness = unreadable("native process identity", error);
            return Ok(());
        }
    };
    let Some((life, at)) = classify_observation(plan, &record, observation, deadline)? else {
        return Ok(());
    };
    plan.row.session.observed_at = Some(se_core::ops::receipt::timestamp(
        i64::try_from(at / 1000).map_err(|_| invalid("a representable native observation time"))?,
    )?);
    let live = matches!(&life, Read::Present { value } if value == "live");
    if live
        && matches!(&plan.row.session.process_state, Read::Present { value } if value == "exited")
    {
        plan.row.session.state = "unknown".into();
        plan.row.session.liveness = unreadable(
            "session process contradiction",
            "the exact original process is live despite its recorded exit; owner diagnosis is required",
        );
        return Ok(());
    }
    let recorded = plan.row.session.recorded_state.as_deref();
    plan.row.session.state = match (&plan.row.session.process_state, recorded, live) {
        (Read::Present { value }, _, _) if value == "stop-unproved" || value == "lost" => "lost",
        (Read::Present { value }, _, true) if value == "stop-requested" => "stopping",
        (_, Some("activated"), true) => "running",
        (_, _, false) => "stopped",
        _ => "unknown",
    }
    .into();
    plan.row.session.liveness = life;
    Ok(())
}
