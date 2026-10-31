//! CLI-local translation of native custody into the store's narrow file port.
use se_proc::{NativeStateFiles, StateFileError, StateFileErrorCode};
use se_store::{
    LeaseIdentity, RuntimeLease, StateFiles, StoreDetail, StoreError, StoreErrorCode, StoreResult,
};
use se_types::{Read, Remedy, Retry};
use std::{
    fs::File,
    io::Write,
    path::{Component, Path},
};

pub struct Files(pub NativeStateFiles);
impl Files {
    pub fn open(path: &Path) -> StoreResult<Self> {
        NativeStateFiles::open(path).map(Self).map_err(native_error)
    }
    pub fn create(path: &Path) -> StoreResult<Self> {
        NativeStateFiles::create(path)
            .map(Self)
            .map_err(native_error)
    }
    /// Complete bounded immediate-file inventory through retained native
    /// custody. A budget or unsafe entry refuses the whole list.
    pub fn list_owned(
        &self,
        directory: &Path,
        maximum: usize,
    ) -> StoreResult<Vec<std::path::PathBuf>> {
        if maximum == 0 {
            return Err(fail(
                StoreErrorCode::ReadBudgetTooSmall,
                "owned file inventory requires a positive maximum",
            ));
        }
        if directory == self.0.root() {
            self.check_root()?;
        } else {
            self.check_path(directory)?;
        }
        let paths = self.0.list_owned(directory).map_err(native_error)?;
        if paths.len() > maximum {
            return Err(fail(
                StoreErrorCode::ReadIncomplete,
                "owned file inventory exceeds its requested maximum; no partial list returned",
            ));
        }
        if paths.iter().any(|path| path.parent() != Some(directory)) {
            return Err(fail(
                StoreErrorCode::LocationUnsafe,
                "native inventory returned a path outside the requested immediate directory",
            ));
        }
        self.check_root()?;
        Ok(paths)
    }
}
impl Files {
    fn check_root(&self) -> StoreResult<()> {
        // The real database read revalidates the original retained root before
        // and after opening. A missing database is still a valid root observation.
        self.0
            .readback(&self.0.root().join("state.db"))
            .map_err(native_error)?;
        Ok(())
    }
    fn check_path(&self, path: &Path) -> StoreResult<()> {
        let relative = path.strip_prefix(self.0.root()).map_err(|_| {
            fail(
                StoreErrorCode::LocationUnsafe,
                "owned state effect is outside its retained root",
            )
        })?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(fail(
                StoreErrorCode::LocationUnsafe,
                "owned state effect requires a normalized descendant file",
            ));
        }
        self.check_root()
    }
}
impl StateFiles for Files {
    fn list_owned(&self, directory: &Path, maximum: usize) -> StoreResult<Vec<std::path::PathBuf>> {
        Files::list_owned(self, directory, maximum)
    }
    fn prepare_directory(&self, path: &Path) -> StoreResult<()> {
        if path != self.0.root().join("backups") && path != self.0.root().join("staging") {
            return Err(fail(
                StoreErrorCode::LocationUnsafe,
                "only the fixed state backups/staging directories may be prepared",
            ));
        }
        self.check_root()?;
        self.0.prepare_directory(path).map_err(native_error)?;
        self.check_root()
    }
    fn replace_owned(
        &self,
        path: &Path,
        expected: Option<[u8; 32]>,
        bytes: &[u8],
    ) -> StoreResult<()> {
        self.check_path(path)?;
        // Read through the private-root port before the common native mutation pin.
        // This preserves owner-only protection in addition to the effects pin's identity.
        self.0.readback(path).map_err(native_error)?;
        match (
            se_proc::OwnedFile::open(path).map_err(native_error)?,
            expected,
        ) {
            (Some(file), Some(digest)) => file.replace(digest, bytes).map_err(native_error)?,
            (None, None) => {
                let parent = path.parent().ok_or_else(|| {
                    fail(StoreErrorCode::LocationUnsafe, "manifest parent is absent")
                })?;
                let mut staged = self.0.create_staging(parent).map_err(native_error)?;
                staged.file.write_all(bytes).map_err(|error| {
                    fail(
                        StoreErrorCode::Unreadable,
                        &format!("write manifest staging: {error}"),
                    )
                })?;
                staged.file.sync_all().map_err(|error| {
                    fail(
                        StoreErrorCode::Unreadable,
                        &format!("sync manifest staging: {error}"),
                    )
                })?;
                drop(staged.file);
                self.0
                    .publish_no_replace(&staged.path, path)
                    .map_err(native_error)?;
            }
            _ => {
                return Err(fail(
                    StoreErrorCode::SourceChanged,
                    "owned manifest presence differs from its measured expectation",
                ));
            }
        }
        if self.0.readback(path).map_err(native_error)?.is_none() {
            return Err(fail(
                StoreErrorCode::SourceChanged,
                "published state manifest is absent on private-root readback",
            ));
        }
        self.check_root()
    }
    fn remove_owned(&self, path: &Path, expected: [u8; 32]) -> StoreResult<()> {
        self.check_path(path)?;
        self.0.readback(path).map_err(native_error)?;
        if let Some(file) = se_proc::OwnedFile::open(path).map_err(native_error)? {
            file.remove(expected).map_err(native_error)?;
        }
        if self.0.readback(path).map_err(native_error)?.is_some() {
            return Err(fail(
                StoreErrorCode::SourceChanged,
                "retired state generation remains present",
            ));
        }
        self.check_root()
    }

    fn create_staging(&self, directory: &Path) -> StoreResult<se_store::ProtectedStaging> {
        let staged = self.0.create_staging(directory).map_err(native_error)?;
        Ok(se_store::ProtectedStaging {
            path: staged.path,
            file: staged.file,
        })
    }
    fn readback(&self, path: &Path) -> StoreResult<Read<File>> {
        Ok(match self.0.readback(path).map_err(native_error)? {
            Some(value) => Read::Present { value },
            None => Read::Absent {
                checked: format!("native no-follow readback at {}", path.display()),
            },
        })
    }
    fn publish_no_replace(&self, staged: &Path, destination: &Path) -> StoreResult<()> {
        self.0
            .publish_no_replace(staged, destination)
            .map_err(native_error)
    }
}
pub fn native_error(error: StateFileError) -> Box<StoreError> {
    Box::new(StoreError {code:match error.code {
        StateFileErrorCode::AlreadyExists=>StoreErrorCode::AlreadyExists,
        StateFileErrorCode::Unreadable=>StoreErrorCode::Unreadable,
        StateFileErrorCode::LocationUnsafe|StateFileErrorCode::Unsupported=>StoreErrorCode::LocationUnsafe,
        StateFileErrorCode::SourceChanged=>StoreErrorCode::SourceChanged,
    },cause:error.to_string(),detail:StoreDetail::None,remedy:Remedy {text:"Preserve the existing file and restore native ownership/protection before retrying the same request identity.".into(),command:None},retry:Retry::Never})
}
/// The file handle holds the shared OS lock until the direct transaction and its
/// fresh continuation read have finished. A file's mere existence is no lease.
pub struct DirectLease {
    pub files: Files,
    pub identity: LeaseIdentity,
    _locked: File,
}
impl DirectLease {
    pub fn acquire(
        files: Files,
        lock_file: &Path,
        identity: LeaseIdentity,
    ) -> StoreResult<Option<Self>> {
        if identity.mode != se_store::LeaseMode::DirectClient {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "direct lease requires DirectClient mode",
            ));
        }
        let file = match files.readback(lock_file)? {
            Read::Present { value } => value,
            Read::Absent { .. } => {
                return Err(fail(
                    StoreErrorCode::Absent,
                    "runtime lock is absent; explicit init must create it",
                ));
            }
            Read::Unreadable { reason, .. } => {
                return Err(fail(StoreErrorCode::Unreadable, &reason));
            }
            Read::Unknown { what } => return Err(fail(StoreErrorCode::Unreadable, &what)),
        };
        match file.try_lock_shared() {
            Ok(()) => Ok(Some(Self {
                files,
                identity,
                _locked: file,
            })),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(error)) => Err(fail(
                StoreErrorCode::Unreadable,
                &format!("shared runtime lock failed: {error}"),
            )),
        }
    }
}
impl RuntimeLease for DirectLease {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        Ok(self.identity.clone())
    }
    fn files(&self) -> &dyn StateFiles {
        &self.files
    }
}
fn fail(code: StoreErrorCode, cause: &str) -> Box<StoreError> {
    Box::new(StoreError {code,cause:cause.into(),detail:StoreDetail::None,remedy:Remedy {text:"Use explicit init for missing state; otherwise restore access or use the authenticated live-host route.".into(),command:None},retry:Retry::AfterReread})
}
