//! Installed detached host entry. The inherited native bootstrap authenticates
//! private inputs; publication stays fenced until the parent commits this owner.
#[cfg(any(target_os = "linux", windows))]
#[path = "host/detachment.rs"]
mod detachment;
#[cfg(any(target_os = "linux", windows))]
pub use detachment::{DetachmentObservation, read_detachment};
#[cfg(any(target_os = "linux", windows))]
#[path = "host/child.rs"]
mod child;
#[cfg(any(target_os = "linux", windows))]
#[path = "host/environment.rs"]
mod environment;
#[cfg(any(target_os = "linux", windows))]
#[path = "host/interrupt.rs"]
mod interrupt;
#[cfg(any(target_os = "linux", windows))]
#[path = "host/launch.rs"]
mod launch;
#[cfg(any(target_os = "linux", windows))]
pub(crate) use child::foreground;
#[cfg(any(target_os = "linux", windows))]
pub use launch::{StartedHost, StartupFailure, start, start_with_origin};

use se_types::{Result, SeError};
use std::ffi::OsString;
/// Authenticated private-frame policy, never selected from an environment flag.
#[cfg(any(target_os = "linux", windows))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupOrigin {
    Explicit,
    Automatic,
}
#[cfg(any(target_os = "linux", windows))]
impl StartupOrigin {
    fn frame(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Automatic => "automatic",
        }
    }
}
#[cfg(any(target_os = "linux", windows))]
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

pub fn dispatch(args: &[OsString]) -> Option<Result<u8>> {
    if args
        .get(1)
        .is_none_or(|arg| arg != "--stateengine-private-runtime-bootstrap")
    {
        return None;
    }
    #[cfg(any(target_os = "linux", windows))]
    {
        let result = se_proc::RuntimeBootstrap::from_process_entry()
            .map_err(native_error)
            .and_then(|guard| {
                guard.ok_or_else(|| invalid("authenticated inherited native channels"))
            })
            .and_then(child::receive);
        #[cfg(windows)]
        eprintln!(
            "host shutdown pid={} stage=private-entry-return exit_code={}",
            std::process::id(),
            result.as_ref().copied().unwrap_or(1)
        );
        Some(result)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Some(Err(invalid(
            "a supported Linux or Windows detached runtime bootstrap",
        )))
    }
}
fn invalid(expected: &str) -> SeError {
    SeError::invalid("private runtime entry", expected)
}
#[cfg(any(target_os = "linux", windows))]
fn native_error(error: se_proc::ProcError) -> SeError {
    if error.code == se_proc::ProcErrorCode::BreakawayDenied {
        // The runtime must outlive its caller. Keep the native refusal instead
        // of retrying inside the job or misreporting a state-directory problem.
        return SeError::new(se_types::Detail::JobBreakawayRefused(
            se_types::details::JobBreakawayRefused {
                parent: format!("caller process PID {}", std::process::id()),
            },
        ));
    }
    if error.code == se_proc::ProcErrorCode::LaunchFailed
        && let se_proc::ProcErrorDetail::Executable { program } = error.detail.as_ref()
    {
        return SeError::new(se_types::Detail::LaunchFailed(
            se_types::details::LaunchFailed {
                subject: program.display().to_string(),
                reason: format!(
                    "runtime executable could not be pinned: {}",
                    error.native.as_ref().map(|native| native.reason.as_str())
                        .unwrap_or("the image does not meet native launch preconditions")
                ),
                next_step: "Reinstall StateEngine or copy this executable to a regular single-link file and run that copy, then retry se up".into(),
            },
        ));
    }
    se_core::scope::unreadable("native runtime bootstrap", &format!("{error:?}"))
}
#[cfg(any(target_os = "linux", windows))]
fn deadline(timeout: Duration) -> Result<se_host::client::lease::Deadline> {
    se_host::client::lease::Deadline::from_options(&se_host::client::ClientOptions {
        expected_generation: None,
        timeout,
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}
#[cfg(any(target_os = "linux", windows))]
fn decode_instance(value: &std::ffi::OsStr) -> Result<se_proc::HostInstanceId> {
    let text = value
        .to_str()
        .ok_or_else(|| invalid("a native host instance identifier"))?;
    if text.len() != 32 || !text.bytes().all(|v| v.is_ascii_hexdigit()) {
        return Err(invalid("a 16-byte hex host instance identifier"));
    }
    let mut id = [0; 16];
    for (index, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid("a hex host identifier"))?;
    }
    if id == [0; 16] {
        return Err(invalid("a nonzero host identifier"));
    }
    Ok(se_proc::HostInstanceId(id))
}

#[cfg(any(target_os = "linux", windows))]
fn machine(home: &std::path::Path) -> Result<se_types::MachineId> {
    let files = crate::route::files::Files::open(home)
        .map_err(|error| se_core::store_error::store_error(&error))?;
    crate::route::identity::require_machine(&files)
}
