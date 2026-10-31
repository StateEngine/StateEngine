//! The CLI recognizes the exact private argv before normal parsing, then calls
//! from_process_entry. The marker grants no authority: the inherited native
//! envelope, actual creator, image identities and private channels must agree.
//! Core validates the opaque plan and owns every non-image uninstall effect.
use crate::NativeStateFiles;
use std::{
    fs::File,
    io::{self, Read, Seek, Write},
    os::windows::io::{AsRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::Cryptography::*,
    Storage::FileSystem::*,
    System::{Console::*, Threading::*},
};
mod frame;
mod native;
mod spawn;
use frame::Frame;

#[derive(Debug)]
pub struct UninstallNativeError {
    pub operation: &'static str,
    pub source: io::Error,
    /// Exact protected artifacts whose cleanup remains unresolved after failure.
    pub pending_paths: Vec<PathBuf>,
}
impl std::fmt::Display for UninstallNativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.operation, self.source)
    }
}
impl std::error::Error for UninstallNativeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UninstallProcessIdentity {
    pub pid: u32,
    pub creation_filetime: u64,
    pub image: PathBuf,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct FileId {
    volume: u64,
    index: [u8; 16],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UninstallReady {
    Pending,
    Ready,
}
#[derive(Debug)]
pub struct UninstallHandoffReceipt {
    pub parent: UninstallProcessIdentity,
    pub helper: UninstallProcessIdentity,
    /// Handoff is pending. This receipt never claims image deletion or success.
    pub pending_image: PathBuf,
}
#[derive(Debug)]
pub struct UninstallImageWitness {
    parent: UninstallProcessIdentity,
    helper: UninstallProcessIdentity,
}
impl UninstallImageWitness {
    pub fn parent(&self) -> &UninstallProcessIdentity {
        &self.parent
    }
    pub fn helper(&self) -> &UninstallProcessIdentity {
        &self.helper
    }
    pub fn removed_image(&self) -> &Path {
        &self.parent.image
    }
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
fn protected(file: &File, path: &Path) -> Result<()> {
    crate::state_files::windows::security::verify(file, path, true).map_err(custody)
}

mod handoff;
mod helper;
pub use handoff::NativeUninstallHandoff;
pub use helper::NativeUninstallHelper;
