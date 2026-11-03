//! Outside, exact-birth native readback. A stored activation is never liveness.
use super::*;
use se_proc::{CheckpointKind, CheckpointPrincipal, CheckpointSource, NativeState, ProcessRead};
use se_store::{Actor, RecordedIdentity};

pub(super) fn observe(plan: &mut AgentObservationPlan, deadline: Instant) -> Result<()> {
    let target = plan
        .identity
        .as_ref()
        .ok_or_else(|| invalid("a launched session target"))?;
    plan.row.session.process = None;
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
    let checked = (|| {
        let checkpoint =
            se_proc::decode_checkpoint(identity.custody.format_version, &identity.custody.record)
                .map_err(|e| invalid(&format!("the native checkpoint must decode: {e}")))?;
        if checkpoint.lifecycle != identity.record
            || checkpoint.session.as_ref() != Some(&target.session)
            || !matches!(&checkpoint.principal,CheckpointPrincipal::Agent(agent) if agent==&target.agent)
            || identity.principal != Actor::Agent(target.agent.clone())
        {
            return Err(invalid(
                "matching native and recorded lifecycle/project/agent/session",
            ));
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
        let RecordedIdentity::Present(instance) = &identity.instance else {
            return Err(invalid("the original recorded native process identity"));
        };
        let fields = instance.fields();
        let same_start = match (&record.root.start, &fields.started) {
            (
                se_proc::StartIdentity::Linux { start_ticks: a },
                se_types::StartIdentity::Linux { start_ticks: b },
            ) => a == b,
            (
                se_proc::StartIdentity::Windows {
                    creation_filetime: a,
                },
                se_types::StartIdentity::Windows {
                    creation_filetime: b,
                },
            ) => *a == b.get(),
            (
                se_proc::StartIdentity::MacOs {
                    seconds: a,
                    microseconds: b,
                },
                se_types::StartIdentity::Macos {
                    start_seconds: c,
                    start_micros: d,
                },
            ) => a == c && b == d,
            _ => false,
        };
        if !same_start
            || record.root.machine != fields.machine
            || record.root.pid.0 != fields.pid.get()
            || record.root.image != fields.executable.to_local()?
            || record.argv_sha256 != *fields.argv_sha256.as_bytes()
        {
            return Err(invalid(
                "the checkpoint's exact machine, PID, birth, image and recorded argv digest",
            ));
        }
        bound(deadline)?;
        let observation = se_proc::read_process(record.root.machine.clone(), record.root.pid)
            .map_err(|e| invalid(&format!("readable native process identity: {e:?}")))?;
        Ok((record, observation))
    })();
    let (record, observation) = match checked {
        Ok(value) => value,
        Err(error) => {
            plan.row.session.state = "unknown".into();
            plan.row.session.liveness = unreadable("native process identity", error);
            return Ok(());
        }
    };
    let (life, at) = match observation {
        ProcessRead::Present(actual) if actual.identity == record.root => match actual.state {
            NativeState::Running | NativeState::Stopped => {
                match se_proc::observe_process_birth(&record.root, deadline) {
                    Ok(born) => {
                        plan.row.session.process = Some(se_core::ops::ProcessView {
                            pid: record.root.pid.0,
                            started_at: se_core::ops::receipt::timestamp(born.unix_micros())?,
                            exe: record.root.image.to_string_lossy().into_owned(),
                            machine_id: record.root.machine.to_string(),
                        })
                    }
                    Err(error) => {
                        plan.row.session.state = "unknown".into();
                        plan.row.session.liveness =
                            unreadable("pinned native process birth", format!("{error:?}"));
                        return Ok(());
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
        },
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
                "PID now names a different birth, boot or image; no successor is attributed to this session",
            );
            return Ok(());
        }
    };
    plan.row.session.observed_at = Some(se_core::ops::receipt::timestamp(
        i64::try_from(at / 1000).map_err(|_| invalid("a representable native observation time"))?,
    )?);
    let live = matches!(&life,Read::Present {value} if value=="live");
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
