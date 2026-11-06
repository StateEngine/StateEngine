//! Core admits the finite uninstall plan; the system carrier receives only
//! inherited exact objects and output data, never a private executable entry.
use crate::NativeStateFiles;
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
mod native;
mod script;
mod spawn;
mod staging;

#[derive(Debug)]
pub struct UninstallNativeError {
    pub operation: &'static str,
    pub source: io::Error,
    /// Exact protected artifacts whose cleanup remains unresolved after failure.
    pub pending_paths: Vec<PathBuf>,
}
crate::native_error::native_error!(UninstallNativeError, |error, out| {
    write!(out, "{}: {}", error.operation, error.source)?;
    for path in &error.pending_paths {
        write!(out, "; preserve pending artifact {}", path.display())?;
    }
    Ok(())
}; source Some(&error.source));
type Result<T> = std::result::Result<T, UninstallNativeError>;
fn error(operation: &'static str, source: io::Error) -> UninstallNativeError {
    UninstallNativeError {
        operation,
        source,
        pending_paths: Vec::new(),
    }
}
fn refuse(operation: &'static str, reason: &'static str) -> UninstallNativeError {
    error(operation, io::Error::other(reason))
}
fn custody(e: crate::StateFileError) -> UninstallNativeError {
    error("protect uninstall handoff files", io::Error::other(e))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileId {
    #[serde(with = "crate::checkpoint::decimal::u64")]
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
