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
#[path = "host/launch.rs"]
mod launch;
#[cfg(any(target_os = "linux", windows))]
pub use launch::{StartedHost, StartupFailure, start};

use se_types::{Result, SeError};
use std::{
    ffi::OsString,
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
        Some(
            se_proc::RuntimeBootstrap::from_process_entry()
                .map_err(native_error)
                .and_then(|guard| {
                    guard.ok_or_else(|| invalid("authenticated inherited native channels"))
                })
                .and_then(child::receive),
        )
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
    se_core::scope::unreadable("native runtime bootstrap", &format!("{error:?}"))
}
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
