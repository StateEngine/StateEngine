//! Core admits the finite uninstall plan; the native carrier receives only
//! inherited exact objects and output data.
use se_state_files::NativeStateFiles;
use std::{
    fs::File,
    io::{self, Read, Seek, Write},
    os::windows::io::{AsRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    time::Duration,
};
#[cfg(test)]
use windows_sys::Win32::System::Console::*;
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::Threading::*};
mod cleanup;
mod debt;
pub use debt::{HelperCleanupOutcome, UninstallHelperCleanup};
mod helper;
mod native;
mod worker;
pub use worker::entry as uninstall_carrier_entry;
pub const UNINSTALL_CARRIER_ENTRY: &str = "--stateengine-private-uninstall";
mod spawn;
mod staging;

#[derive(Debug)]
pub struct UninstallNativeError {
    pub operation: &'static str,
    pub source: io::Error,
    /// Exact protected artifacts whose cleanup remains unresolved after failure.
    pub pending_paths: Vec<PathBuf>,
    /// Cleanup attempts that failed after `source`, which is kept unchanged.
    pub cleanup_failures: Vec<UninstallNativeError>,
    /// Carrier diagnostic text captured after preparation failed, if any.
    pub diagnostic: Option<String>,
}
se_state_files::native_error::native_error!(UninstallNativeError, |error, out| {
    write!(out, "{}: {}", error.operation, error.source)?;
    if let Some(diagnostic) = &error.diagnostic {
        write!(out, "; {diagnostic}")?;
    }
    for path in &error.pending_paths {
        write!(out, "; preserve pending artifact {}", path.display())?;
    }
    for failure in &error.cleanup_failures {
        write!(out, "; cleanup failed: {failure}")?;
    }
    Ok(())
}; source Some(&error.source));
type Result<T> = std::result::Result<T, UninstallNativeError>;
fn error(operation: &'static str, source: io::Error) -> UninstallNativeError {
    UninstallNativeError {
        operation,
        source,
        pending_paths: Vec::new(),
        cleanup_failures: Vec::new(),
        diagnostic: None,
    }
}
fn refuse(operation: &'static str, reason: &'static str) -> UninstallNativeError {
    error(operation, io::Error::other(reason))
}
fn custody(e: se_state_files::StateFileError) -> UninstallNativeError {
    error("protect uninstall handoff files", io::Error::other(e))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileId {
    #[serde(with = "se_custody::checkpoint::decimal::u64")]
    volume: u64,
    index: [u8; 16],
}
fn clock() -> u64 {
    // SAFETY: shared machine-monotonic clock; no pointer arguments or mutation.
    unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() }
}
fn check_deadline(deadline: u64) -> Result<()> {
    if clock() >= deadline {
        Err(refuse(
            "observe uninstall handoff",
            "handoff deadline expired; cleanup remains pending",
        ))
    } else {
        Ok(())
    }
}
mod carrier;
pub use carrier::NativeUninstallCarrier;
