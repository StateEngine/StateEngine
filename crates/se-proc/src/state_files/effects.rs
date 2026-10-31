//! Exact, already-admitted installation effects outside the private store root.
//! This layer grants no owner/human authority and accepts no recursive deletion.
//! Native pins survive from observation through comparison, mutation and readback.
use super::{Result, StateFileErrorCode, failure, io_error};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

#[cfg(unix)]
use super::unix::effects as os;
#[cfg(windows)]
use super::windows::effects as os;

/// A single regular file owned by the current native user. The parent chain and
/// original object are pinned; symlinks, reparse points and hard links refuse.
/// It is not Clone and never exposes an unvalidated mutation handle.
pub struct OwnedFile(os::Pin);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryRemoval {
    Removed,
    AlreadyAbsent,
    NotEmpty,
}

impl OwnedFile {
    /// None means native ENOENT, including an actually absent ancestor. Permission,
    /// sharing, link and identity failures retain their distinct error.
    pub fn open(path: &Path) -> Result<Option<Self>> {
        os::Pin::open(path).map(|pin| pin.map(Self))
    }
    pub fn sha256(&mut self) -> Result<[u8; 32]> {
        self.0.check()?;
        let value = digest(self.0.file(), self.0.path())?;
        self.0.check()?;
        Ok(value)
    }
    /// Read bounded profile bytes without silently accepting a truncated prefix.
    pub fn read(&mut self, limit: usize) -> Result<Vec<u8>> {
        self.0.check()?;
        let path = self.0.path();
        let mut file = self.0.file();
        file.seek(SeekFrom::Start(0))
            .map_err(|e| io_error("seek owned file", path, e))?;
        let mut bytes = Vec::new();
        file.take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| io_error("read owned file", path, e))?;
        if bytes.len() > limit {
            return Err(failure(
                StateFileErrorCode::Unsupported,
                "owned file exceeds caller read bound",
                path,
            ));
        }
        self.0.check()?;
        Ok(bytes)
    }
    /// A digest mismatch or replaced path refuses before unlink. Successful
    /// completion includes an independent reopen witnessing native absence.
    pub fn remove(self, expected: [u8; 32]) -> Result<()> {
        self.0.remove(expected)
    }
    /// Restore a proved recovery object to an absent exact target in the same
    /// directory. Native no-replace publication preserves security/identity;
    /// callers must prove plan association independently of its filename.
    pub fn restore_to(self, destination: &Path, expected: [u8; 32]) -> Result<()> {
        self.0.restore_to(destination, expected)
    }
    /// Atomic replacement, preserving the original file's permissions/security.
    /// The old path and digest are rechecked after staging and before publication.
    /// This is a mistake/drift check, not isolation from a hostile same-user editor.
    pub fn replace(self, expected: [u8; 32], bytes: &[u8]) -> Result<()> {
        self.0.replace(expected, bytes)
    }
}

pub fn remove_empty_directory(path: &Path) -> Result<DirectoryRemoval> {
    os::remove_empty_directory(path)
}

pub(super) fn changed(operation: &'static str, path: &Path) -> super::StateFileError {
    failure(StateFileErrorCode::SourceChanged, operation, path)
}
pub(super) fn absent(error: &super::StateFileError) -> bool {
    error
        .source
        .as_ref()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
}
pub(super) fn digest(mut file: &File, path: &Path) -> Result<[u8; 32]> {
    let before = file
        .metadata()
        .map_err(|e| io_error("inspect owned file before hash", path, e))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| io_error("seek owned file for hash", path, e))?;
    let mut hash = Sha256::new();
    let mut block = [0; 65536];
    loop {
        let count = file
            .read(&mut block)
            .map_err(|e| io_error("hash owned file", path, e))?;
        if count == 0 {
            break;
        }
        hash.update(&block[..count]);
    }
    let after = file
        .metadata()
        .map_err(|e| io_error("inspect owned file after hash", path, e))?;
    if before.len() != after.len()
        || before
            .modified()
            .map_err(|e| io_error("read original file modification time", path, e))?
            != after
                .modified()
                .map_err(|e| io_error("read current file modification time", path, e))?
    {
        return Err(changed("owned file changed while hashing", path));
    }
    Ok(hash.finalize().into())
}
pub(super) fn verify(file: &File, path: &Path, expected: [u8; 32]) -> Result<()> {
    if digest(file, path)? != expected {
        return Err(changed("owned file digest changed before mutation", path));
    }
    Ok(())
}

/// Inventory at most 4096 entries and 256 recovery siblings without following
/// a leaf. Missing directories refuse; an empty complete scan returns [].
/// The prefix grants no removal/restoration authority.
pub fn scan_recovery(directory: &Path) -> Result<Vec<std::path::PathBuf>> {
    os::scan_recovery(directory)
}
