//! Display birth time never becomes process authority. The endpoint has already
//! passed protected file and store-owner checks; this read binds its native start.
use crate::{EndpointRecord, client::lease::Deadline};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use se_core::ops::receipt;
use se_core::{ops::ProcessView, scope};
use se_types::Result;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use se_types::SeError;

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub fn observe(endpoint: &EndpointRecord, bound: &Deadline) -> Result<ProcessView> {
    bound.remaining()?;
    let fields = endpoint.epoch.owner.fields();
    let boot = se_proc::current_runtime_identity(fields.machine.clone()).map_err(native)?;
    if boot.boot_relation(&fields.boot) != se_proc::RuntimeBootRelation::Same {
        return Err(scope::unreadable(
            "host birth identity",
            "the recorded host boot does not match or cannot be compared",
        ));
    }
    let live =
        match se_proc::read_process(fields.machine.clone(), se_proc::ProcessId(fields.pid.get()))
            .map_err(native)?
        {
            se_proc::ProcessRead::Present(value)
                if value.state != se_proc::NativeState::ExitedAwaitingReap =>
            {
                value
            }
            _ => {
                return Err(scope::unreadable(
                    "host birth identity",
                    "the exact host process is no longer executing",
                ));
            }
        };
    if same_start(&live.identity.start, &fields.started) != Some(true)
        || live.identity.image != fields.executable.to_local()?
    {
        return Err(scope::unreadable(
            "host birth identity",
            "native start or executable changed since protected endpoint publication",
        ));
    }
    from_identity(&live.identity, bound)
}

pub fn same_start(
    native: &se_proc::StartIdentity,
    recorded: &se_types::StartIdentity,
) -> Option<bool> {
    Some(match (native, recorded) {
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
                seconds,
                microseconds,
            },
            se_types::StartIdentity::Macos {
                start_seconds,
                start_micros,
            },
        ) => seconds == start_seconds && microseconds == start_micros,
        _ => return None,
    })
}

pub(crate) fn proc_start(start: &se_types::StartIdentity) -> se_proc::StartIdentity {
    match start {
        se_types::StartIdentity::Linux { start_ticks } => se_proc::StartIdentity::Linux {
            start_ticks: *start_ticks,
        },
        se_types::StartIdentity::Macos {
            start_seconds,
            start_micros,
        } => se_proc::StartIdentity::MacOs {
            seconds: *start_seconds,
            microseconds: *start_micros,
        },
        se_types::StartIdentity::Windows { creation_filetime } => se_proc::StartIdentity::Windows {
            creation_filetime: creation_filetime.get(),
        },
    }
}
/// A native committed startup supplies its exact retained identity directly.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub fn from_identity(identity: &se_proc::ProcessIdentity, bound: &Deadline) -> Result<ProcessView> {
    let born = se_proc::observe_process_birth(identity, bound.at()).map_err(native)?;
    bound.remaining()?;
    Ok(ProcessView {
        pid: identity.pid.0,
        started_at: receipt::timestamp(born.unix_micros())?,
        exe: identity.image.display().to_string(),
        machine_id: identity.machine.to_string(),
    })
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn observe(_endpoint: &EndpointRecord, _bound: &Deadline) -> Result<ProcessView> {
    Err(scope::unreadable(
        "host birth identity",
        "native birth-time observation is unavailable on this platform",
    ))
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn native(error: se_proc::ProcError) -> SeError {
    scope::unreadable("native host birth observation", &format!("{error:?}"))
        .with_cause(NativeObservationError(error))
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[derive(Debug)]
struct NativeObservationError(se_proc::ProcError);
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl std::fmt::Display for NativeObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl std::error::Error for NativeObservationError {}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
/// Waits until the recorded host process on `machine` has provably exited.
pub fn witness_exit(
    machine: &se_types::MachineId,
    instance: &se_types::ProcessInstance,
    bound: &Deadline,
) -> Result<()> {
    let expected = instance.fields();
    if *machine != expected.machine {
        return Err(scope::unreadable(
            "remove host exit",
            "the recorded host belongs to a different machine",
        ));
    }
    loop {
        bound.remaining()?;
        let native = se_proc::current_runtime_identity(expected.machine.clone())
            .map_err(|e| scope::unreadable("remove host exit", &format!("{e:?}")))?;
        match native.boot_relation(&expected.boot) {
            se_proc::RuntimeBootRelation::Same => {}
            se_proc::RuntimeBootRelation::Different => return Ok(()),
            se_proc::RuntimeBootRelation::Unverifiable => {
                return Err(scope::unreadable(
                    "remove host exit",
                    "the recorded boot cannot be compared to the current boot",
                ));
            }
        }
        let observed = se_proc::read_process_until(
            expected.machine.clone(),
            se_proc::ProcessId(expected.pid.get()),
            bound.at(),
        )
        .map_err(|e| scope::unreadable("remove host exit", &format!("{e:?}")))?;
        match observed {
            se_proc::ProcessRead::Absent { .. } | se_proc::ProcessRead::ExitedRecord { .. } => {
                return Ok(());
            }
            se_proc::ProcessRead::Present(live) => {
                let same_start =
                    same_start(&live.identity.start, &expected.started).ok_or_else(|| {
                        scope::unreadable(
                            "remove host exit",
                            "native start identity has an incompatible platform",
                        )
                    })?;
                if !same_start
                    || matches!(
                        live.state,
                        se_proc::NativeState::Exited | se_proc::NativeState::ExitedAwaitingReap
                    )
                {
                    return Ok(());
                }
                if live.identity.image != expected.executable.to_local()? {
                    return Err(scope::unreadable(
                        "remove host exit",
                        "the same process changed its executable; exit is not proven",
                    ));
                }
            }
        }
        std::thread::sleep(bound.remaining()?.min(std::time::Duration::from_millis(25)));
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn witness_exit(
    _machine: &se_types::MachineId,
    _instance: &se_types::ProcessInstance,
    _bound: &Deadline,
) -> Result<()> {
    Err(scope::unreadable(
        "remove host exit",
        "native host exit observation is unavailable on this platform",
    ))
}
