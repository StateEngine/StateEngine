//! Execution custody for an already-qualified native file. Transcript pins
//! remain non-blocking; process creation takes its own short-lived custody.
use super::{
    Result,
    effects::changed,
    source::{NativeSourcePin, SourceChunk},
};
use crate::native_ipc::ExecutableStamp;
use std::{
    fs::File,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(windows)]
#[path = "executable/windows.rs"]
mod windows;

pub struct NativeExecutablePin(NativeSourcePin);

/// Retain this object until native process creation has completed. Linux names
/// the retained descriptor, not the package pathname. Windows excludes writes
/// and deletion through creation, without blocking updates between invocations.
/// Neither contract protects against deliberate same-account in-place rewriting
/// of the retained Unix file. macOS has pre/post checks, not descriptor execution.
pub struct NativeExecutableInvocation {
    original: PathBuf,
    executable: PathBuf,
    identity: [u8; 32],
    stamp: Option<ExecutableStamp>,
    _file: File,
}

/// Exclusion held only while the platform selects a process image. Dropping it
/// permits provider updates; it never terminates or claims to observe a process.
pub struct NativeExecutableCreation {
    _files: Vec<File>,
}

impl NativeExecutablePin {
    pub fn open(path: &Path) -> Result<Option<Self>> {
        NativeSourcePin::open(path).map(|pin| pin.map(Self))
    }
    pub fn path(&self) -> &Path {
        self.0.path()
    }
    pub fn validate_path(&self, claimed: &Path) -> Result<()> {
        self.0.validate_path(claimed)
    }
    pub fn read_at(&mut self, offset: u64, limit: usize) -> Result<SourceChunk> {
        self.0.read_at(offset, limit)
    }
    pub fn prepare(&self) -> Result<NativeExecutableInvocation> {
        let original = self.path().to_owned();
        let file = self.0.try_clone_file()?;
        self.0.validate_path(&original)?;
        #[cfg(target_os = "linux")]
        let executable = {
            use std::os::fd::AsRawFd;
            // The spawning process retains this descriptor while its child
            // closes unrelated inherited descriptors during launch preparation.
            PathBuf::from(format!(
                "/proc/{}/fd/{}",
                std::process::id(),
                file.as_raw_fd()
            ))
        };
        #[cfg(not(target_os = "linux"))]
        let executable = original.clone();
        let stamp = ExecutableStamp::observe(&original).map_err(|error| {
            super::io_error(
                "observe invocation image",
                &original,
                std::io::Error::other(error),
            )
        })?;
        Ok(NativeExecutableInvocation {
            original,
            executable,
            identity: self.0.identity(),
            stamp,
            _file: file,
        })
    }
}

impl NativeExecutableInvocation {
    pub fn path(&self) -> &Path {
        &self.executable
    }
    pub fn original_path(&self) -> &Path {
        &self.original
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn descriptor(&self) -> i32 {
        use std::os::fd::AsRawFd;
        self._file.as_raw_fd()
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn uses_interpreter(&self) -> bool {
        self.stamp.is_none()
    }

    pub(crate) fn creation_guard(&self) -> Result<NativeExecutableCreation> {
        #[cfg(windows)]
        let guard = NativeExecutableCreation {
            _files: windows::lock(&self.original)?,
        };
        #[cfg(not(windows))]
        let guard = NativeExecutableCreation { _files: Vec::new() };
        self.validate()?;
        Ok(guard)
    }
    pub fn command(&self) -> Result<(Command, NativeExecutableCreation)> {
        let guard = self.creation_guard()?;
        let command = Command::new(&self.executable);
        #[cfg(unix)]
        let command = {
            use std::os::unix::process::CommandExt;
            let mut command = command;
            command.arg0(&self.original);
            command
        };
        Ok((command, guard))
    }
    /// This readback detects drift. On macOS a pathname replacement can still
    /// execute before this check reports it; it is not an atomic execution proof.
    pub fn validate(&self) -> Result<()> {
        let named = NativeSourcePin::open(&self.original)?
            .ok_or_else(|| changed("invoked executable pathname is absent", &self.original))?;
        let stamp = ExecutableStamp::observe(&self.original).map_err(|error| {
            super::io_error(
                "reobserve invocation image",
                &self.original,
                std::io::Error::other(error),
            )
        })?;
        if named.identity() != self.identity || stamp != self.stamp {
            return Err(changed(
                "invoked executable changed during process creation",
                &self.original,
            ));
        }
        named.validate_path(&self.original)
    }
}
