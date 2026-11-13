//! Retained read-only provider transcript custody. A hook pathname never creates
//! a pin: the trusted host resolver owns open/bind and retains this object.
#[cfg(unix)]
use super::unix::effects::ReadPin;
#[cfg(windows)]
use super::windows::effects::ReadPin;
use super::{Result, StateFileErrorCode, effects::changed, failure, io_error};
use sha2::{Digest, Sha256};
use std::{
    io,
    path::{Path, PathBuf},
};

pub struct NativeSourcePin {
    path: PathBuf,
    pin: ReadPin,
    identity: [u8; 32],
    observed_len: u64,
}
pub struct SourceChunk {
    pub bytes: Vec<u8>,
    pub next_offset: u64,
    pub end_of_file: bool,
}
impl NativeSourcePin {
    pub(super) fn try_clone_file(&self) -> Result<std::fs::File> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            // SAFETY: retained read-only source; duplicate above stdio so the
            // child's stream setup cannot overwrite its execution descriptor.
            let fd = unsafe { libc::fcntl(self.pin.file().as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(io_error(
                    "duplicate executable source",
                    &self.path,
                    io::Error::last_os_error(),
                ));
            }
            // SAFETY: successful fcntl transferred one new owned descriptor.
            Ok(unsafe { std::fs::File::from_raw_fd(fd) })
        }
        #[cfg(not(target_os = "linux"))]
        self.pin
            .file()
            .try_clone()
            .map_err(|error| io_error("duplicate retained source", &self.path, error))
    }
    /// None means actual native absence. Permission, sharing, links, unsafe
    /// ownership and identity drift remain errors. No write/delete rights or
    /// mutation locks are taken on the provider's file.
    pub fn open(path: &Path) -> Result<Option<Self>> {
        let Some(pin) = ReadPin::open(path)? else {
            return Ok(None);
        };
        // Canonical stable tuple only; appends do not change file identity.
        let identity = Sha256::digest(pin.identity()).into();
        let observed_len = pin
            .file()
            .metadata()
            .map_err(|error| io_error("inspect pinned transcript length", path, error))?
            .len();
        Ok(Some(Self {
            path: path.into(),
            pin,
            identity,
            observed_len,
        }))
    }
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Validate a claimed name without reading its bytes. Reopening compares
    /// native identity against the retained pin before any capture read.
    pub fn validate_path(&self, claimed: &Path) -> Result<()> {
        self.pin.check()?;
        // check() already reopens this exact name and validates its current
        // parent, file identity and ownership against the retained handles.
        if claimed == self.path {
            return Ok(());
        }
        let Some(other) = ReadPin::open(claimed)? else {
            return Err(changed("claimed transcript is absent", claimed));
        };
        if <[u8; 32]>::from(Sha256::digest(other.identity())) != self.identity {
            return Err(changed(
                "claimed transcript differs from the retained source",
                claimed,
            ));
        }
        other.check()
    }
    /// At most one 256-KiB capture chunk. Bounds describe this actual read,
    /// never a whole-file snapshot; ordinary append remains available.
    pub fn read_at(&mut self, offset: u64, limit: usize) -> Result<SourceChunk> {
        if limit == 0 || limit > 256 * 1024 {
            return Err(failure(
                StateFileErrorCode::Unsupported,
                "transcript chunk requires 1..=256 KiB",
                &self.path,
            ));
        }
        self.pin.check()?;
        let length = self
            .pin
            .file()
            .metadata()
            .map_err(|error| io_error("inspect transcript before chunk read", &self.path, error))?
            .len();
        if length < self.observed_len || offset > length {
            return Err(changed(
                "retained transcript was truncated; captured offset must not reset",
                &self.path,
            ));
        }
        let wanted = (length - offset).min(limit as u64) as usize;
        let mut bytes = vec![0u8; wanted];
        let mut count = 0;
        while count < wanted {
            #[cfg(unix)]
            let read = {
                use std::os::unix::fs::FileExt;
                self.pin
                    .file()
                    .read_at(&mut bytes[count..], offset + count as u64)
            };
            #[cfg(windows)]
            let read = {
                use std::os::windows::fs::FileExt;
                self.pin
                    .file()
                    .seek_read(&mut bytes[count..], offset + count as u64)
            };
            match read {
                Ok(0) => {
                    return Err(changed(
                        "transcript shortened during bounded read",
                        &self.path,
                    ));
                }
                Ok(size) => count += size,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => {
                    return Err(io_error(
                        "read retained transcript chunk",
                        &self.path,
                        error,
                    ));
                }
            }
        }
        self.pin.check()?;
        let after = self
            .pin
            .file()
            .metadata()
            .map_err(|error| io_error("inspect transcript after chunk read", &self.path, error))?
            .len();
        if after < length {
            return Err(changed(
                "transcript truncated during bounded read",
                &self.path,
            ));
        }
        self.observed_len = after;
        let next_offset = offset + count as u64;
        Ok(SourceChunk {
            bytes,
            next_offset,
            end_of_file: next_offset == after,
        })
    }
}
