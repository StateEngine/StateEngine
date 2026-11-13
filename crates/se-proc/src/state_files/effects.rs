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
    /// Internal native handoff only: revalidate the original object and deny
    /// concurrent writes for the lifetime of the returned custody handle.
    #[cfg(windows)]
    pub(crate) fn uninstall_custody(&self) -> Result<File> {
        self.0.mutation_guard()
    }
    /// None means native ENOENT, including an actually absent ancestor. Permission,
    /// sharing, link and identity failures retain their distinct error.
    pub fn open(path: &Path) -> Result<Option<Self>> {
        os::Pin::open(path).map(|pin| pin.map(Self))
    }
    /// Acquire the admitted record-local installer hold before reading bytes.
    /// A separate account-wide claim is required for pattern-based temp cleanup.
    pub fn claim_installation_record(&mut self) -> Result<()> {
        self.0.claim_record()
    }
    pub fn sha256(&mut self) -> Result<[u8; 32]> {
        self.0.check()?;
        let value = digest(self.0.file(), self.0.path())?;
        self.0.check()?;
        Ok(value)
    }
    /// Observe permissions on the pinned object without exposing a write handle.
    pub fn permissions(&self) -> Result<std::fs::Permissions> {
        self.0.check()?;
        let permissions = self
            .0
            .file()
            .metadata()
            .map_err(|error| io_error("inspect owned file permissions", self.0.path(), error))?
            .permissions();
        self.0.check()?;
        Ok(permissions)
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
    /// Compare the complete observed file, then atomically publish exactly its
    /// retained prefix through the same security-preserving replacement path.
    /// Keeping the displaced object protects edits racing Unix publication;
    /// in-place truncation could irretrievably discard a concurrent append.
    pub fn truncate(self, expected: [u8; 32], length: u64) -> Result<()> {
        const MAX_PREFIX: u64 = 1024 * 1024;
        self.0.check()?;
        let path = self.0.path();
        let original = self
            .0
            .file()
            .metadata()
            .map_err(|error| io_error("inspect compare-and-truncate source", path, error))?;
        if length > original.len() || length > MAX_PREFIX {
            return Err(failure(
                StateFileErrorCode::Unsupported,
                "truncate requires an existing prefix within the one-MiB profile bound",
                path,
            ));
        }
        let mut source = self.0.file();
        source
            .seek(SeekFrom::Start(0))
            .map_err(|error| io_error("seek retained profile prefix", path, error))?;
        let mut prefix = Vec::new();
        let mut hash = Sha256::new();
        let mut block = [0u8; 65536];
        loop {
            let count = source
                .read(&mut block)
                .map_err(|error| io_error("read compare-and-truncate source", path, error))?;
            if count == 0 {
                break;
            }
            hash.update(&block[..count]);
            let retain = (length.saturating_sub(prefix.len() as u64) as usize).min(count);
            prefix.extend_from_slice(&block[..retain]);
        }
        if prefix.len() as u64 != length || <[u8; 32]>::from(hash.finalize()) != expected {
            return Err(changed(
                "profile changed while observing its retained prefix",
                path,
            ));
        }
        // The exact bytes retained came from the same stream as the expected
        // complete digest. Replacement verifies that digest again at publication.
        self.replace(expected, &prefix)
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
    let paths = os::scan_recovery(directory)?;
    if paths.iter().any(|path| path.to_str().is_none()) {
        return Err(failure(
            StateFileErrorCode::Unsupported,
            "recovery pathname is not lossless UTF-8; inventory is incomplete",
            directory,
        ));
    }
    Ok(paths)
}

/// The same finite held-parent inventory for installer staging names. Core
/// separately decides whether a returned name is recorded or has the exact
/// admitted suffix; this function never opens or removes a discovered leaf.
pub fn scan_temporary(directory: &Path) -> Result<Vec<std::path::PathBuf>> {
    let paths = os::scan_temporary(directory)?;
    if paths.iter().any(|path| path.to_str().is_none()) {
        return Err(failure(
            StateFileErrorCode::Unsupported,
            "temporary pathname is not lossless UTF-8; inventory is incomplete",
            directory,
        ));
    }
    Ok(paths)
}

/// One native-account-wide installer/uninstaller claim, independent of SE_HOME
/// or overridden HOME. The permanent owner-only lock file is never unlinked.
pub struct NativeInstallationClaim {
    _pin: os::Pin,
}
impl NativeInstallationClaim {
    #[cfg(windows)]
    pub(crate) fn uninstall_custody(&self) -> Result<File> {
        self._pin.check()?;
        self._pin
            .file()
            .try_clone()
            .map_err(|error| io_error("retain uninstall account claim", self._pin.path(), error))
    }
    pub fn acquire() -> Result<Self> {
        let path = os::installation_claim_path()?;
        let mut pin = os::Pin::create_claim(&path)?;
        pin.claim_record()?;
        Ok(Self { _pin: pin })
    }
}

#[cfg(unix)]
#[path = "effects/install_hold_unix.rs"]
mod install_hold;
#[cfg(windows)]
#[path = "effects/install_hold_windows.rs"]
mod install_hold;

impl NativeInstallationClaim {
    /// Recover the native creator's handoff only from an inherited, still-held
    /// account-wide claim; environment text alone never becomes directory custody.
    #[cfg(unix)]
    pub fn inherited_created_directories() -> Result<Vec<std::path::PathBuf>> {
        install_hold::inherited_created_directories()
    }

    /// Run an explicitly named installer command with inherited standard I/O.
    /// The child also retains the kernel claim, so killing its holder never
    /// permits another installer while that child can still change files.
    pub fn run_child(&self, command: &std::ffi::OsStr, args: &[std::ffi::OsString]) -> Result<i32> {
        if !Path::new(command).is_absolute() {
            return Err(failure(
                StateFileErrorCode::Unsupported,
                "installer command must be an absolute executable path",
                Path::new(command),
            ));
        }
        install_hold::run(self._pin.file(), command, args, None)
    }
}

#[derive(Clone, Copy)]
pub(in crate::state_files) enum InventoryKind {
    Recovery,
    Temporary,
    Owned,
}
impl InventoryKind {
    pub(in crate::state_files) fn includes(self, name: &std::ffi::OsStr) -> bool {
        let bytes = name.as_encoded_bytes();
        match self {
            Self::Recovery => bytes.starts_with(b".se-edit-backup-"),
            Self::Temporary => {
                bytes.starts_with(b".se-profile-") || bytes.starts_with(b".se-publish-")
            }
            Self::Owned => bytes != b"." && bytes != b"..",
        }
    }
}
#[path = "effects/listing.rs"]
mod listing;

#[path = "effects/created.rs"]
mod created;
pub use created::{CreatedDirectoryCleanup, NativeDirectoryCreation};

impl NativeInstallationClaim {
    /// Pass exactly the native creator's published directory custody to the
    /// installer body. No caller-supplied absence list becomes ownership.
    pub fn run_child_with_created_directories(
        &self,
        command: &std::ffi::OsStr,
        args: &[std::ffi::OsString],
        creation: &NativeDirectoryCreation,
    ) -> Result<i32> {
        if !Path::new(command).is_absolute() {
            return Err(failure(
                StateFileErrorCode::Unsupported,
                "installer command must be absolute",
                Path::new(command),
            ));
        }
        let mut value = String::new();
        for path in creation.paths() {
            let text = path.to_str().ok_or_else(|| {
                failure(
                    StateFileErrorCode::Unsupported,
                    "created directory path is not UTF-8",
                    &path,
                )
            })?;
            if text.bytes().any(|byte| byte.is_ascii_control()) {
                return Err(failure(
                    StateFileErrorCode::Unsupported,
                    "installer directory paths cannot contain control characters",
                    &path,
                ));
            }
            if !value.is_empty() {
                value.push('\n');
            }
            value.push_str(text);
        }
        if value.len() > 32768 {
            return Err(failure(
                StateFileErrorCode::Unsupported,
                "created-directory handoff exceeds 32 KiB",
                Path::new(command),
            ));
        }
        install_hold::run(
            self._pin.file(),
            command,
            args,
            Some(std::ffi::OsStr::new(&value)),
        )
    }
}
