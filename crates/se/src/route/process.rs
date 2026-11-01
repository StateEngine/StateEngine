//! Display birth time never becomes process authority. The endpoint has already
//! passed native IPC authentication; this read binds its native start again.
#[cfg(any(target_os = "linux", windows))]
use se_core::ops::receipt;
use se_core::{ops::ProcessView, scope};
use se_host::{EndpointRecord, client::lease::Deadline};
use se_types::Result;
#[cfg(any(target_os = "linux", windows))]
use se_types::SeError;

#[cfg(any(target_os = "linux", windows))]
pub fn observe(endpoint: &EndpointRecord, bound: &Deadline) -> Result<ProcessView> {
    bound.remaining()?;
    let fields = endpoint.epoch.owner.fields();
    let boot = se_proc::current_runtime_identity(fields.machine.clone()).map_err(native)?;
    if boot.boot_id != fields.boot {
        return Err(scope::unreadable(
            "host birth identity",
            "the recorded host belongs to a different native boot",
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
    let matches = match (&live.identity.start, &fields.started) {
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
        _ => false,
    };
    if !matches || live.identity.image != fields.executable.to_local()? {
        return Err(scope::unreadable(
            "host birth identity",
            "native start or executable changed since authenticated endpoint verification",
        ));
    }
    from_identity(&live.identity, bound)
}
/// A native committed startup supplies its exact retained identity directly.
#[cfg(any(target_os = "linux", windows))]
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
#[cfg(not(any(target_os = "linux", windows)))]
pub fn observe(_endpoint: &EndpointRecord, _bound: &Deadline) -> Result<ProcessView> {
    Err(scope::unreadable(
        "host birth identity",
        "native birth-time observation is unavailable on this platform",
    ))
}
#[cfg(any(target_os = "linux", windows))]
fn native(error: se_proc::ProcError) -> SeError {
    scope::unreadable("native host birth observation", &format!("{error:?}"))
        .with_cause(NativeObservationError(error))
}
#[cfg(any(target_os = "linux", windows))]
#[derive(Debug)]
struct NativeObservationError(se_proc::ProcError);
#[cfg(any(target_os = "linux", windows))]
impl std::fmt::Display for NativeObservationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}
#[cfg(any(target_os = "linux", windows))]
impl std::error::Error for NativeObservationError {}
