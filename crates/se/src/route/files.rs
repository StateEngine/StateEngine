//! CLI-local translation of native custody into the store's narrow file port.
use se_proc::{NativeStateFiles, StateFileError, StateFileErrorCode};
use se_store::{
    LeaseIdentity, RuntimeLease, StateFiles, StoreDetail, StoreError, StoreErrorCode, StoreResult,
};
use se_types::{Read, Remedy, Retry};
use std::{fs::File, path::Path};

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
}
impl StateFiles for Files {
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
