//! Direct-client runtime lease. Native store file mechanics are shared with the host.
pub use se_host::state_files::Files;
use se_store::{
    LeaseIdentity, RuntimeLease, StateFiles, StoreDetail, StoreError, StoreErrorCode, StoreResult,
};
use se_types::{Read, Remedy, Retry};
use sha2::{Digest, Sha256};
use std::{borrow::Borrow, fs::File, path::Path};

/// Persistent home-local exclusion for setup and uninstall. Never replace a
/// published lock: every cooperating operation must retain the same inode.
pub fn setup_lock(files: &Files) -> StoreResult<Option<File>> {
    let path = files.0.root().join("runtime.lock");
    match files.readback(&path)? {
        Read::Present { .. } => (),
        Read::Unreadable { reason, .. } => return Err(fail(StoreErrorCode::Unreadable, &reason)),
        Read::Unknown { what } => return Err(fail(StoreErrorCode::Unreadable, &what)),
        Read::Absent { .. } => {
            let staged = files.create_staging(files.0.root())?;
            staged
                .file
                .sync_all()
                .map_err(|error| fail(StoreErrorCode::Unreadable, &error.to_string()))?;
            drop(staged.file);
            match files.publish_no_replace(&staged.path, &path) {
                Ok(()) => (),
                Err(error) if error.code == StoreErrorCode::AlreadyExists => {
                    files.retire_staging(&staged.path, Sha256::digest([]).into())?;
                }
                Err(error) => return Err(error),
            }
        }
    }
    let file = match files.readback(&path)? {
        Read::Present { value } => value,
        Read::Absent { .. } => {
            return Err(fail(
                StoreErrorCode::Absent,
                "setup runtime lock disappeared",
            ));
        }
        Read::Unreadable { reason, .. } => return Err(fail(StoreErrorCode::Unreadable, &reason)),
        Read::Unknown { what } => return Err(fail(StoreErrorCode::Unreadable, &what)),
    };
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => {
            Err(fail(StoreErrorCode::Unreadable, &error.to_string()))
        }
    }
}

/// Ordinary transactions share the OS lock; setup holds it exclusively before
/// credential mutation through registration and close. Existence is no lease.
/// Status borrows its existing protected root; writers retain owned custody.
pub struct DirectLease<F = Files> {
    pub files: F,
    pub identity: LeaseIdentity,
    _locked: File,
}
impl<F: Borrow<Files>> DirectLease<F> {
    pub fn acquire_setup(files: F, identity: LeaseIdentity) -> StoreResult<Option<Self>> {
        if identity.mode != se_store::LeaseMode::DirectClient {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "setup lease requires DirectClient mode",
            ));
        }
        let Some(file) = setup_lock(files.borrow())? else {
            return Ok(None);
        };
        Ok(Some(Self {
            files,
            identity,
            _locked: file,
        }))
    }
    pub fn acquire(
        files: F,
        lock_file: &Path,
        identity: LeaseIdentity,
    ) -> StoreResult<Option<Self>> {
        if identity.mode != se_store::LeaseMode::DirectClient {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "direct lease requires DirectClient mode",
            ));
        }
        let file = match files.borrow().readback(lock_file)? {
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
impl<F: Borrow<Files> + Send + Sync> RuntimeLease for DirectLease<F> {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        Ok(self.identity.clone())
    }
    fn files(&self) -> &dyn StateFiles {
        self.files.borrow()
    }
}
fn fail(code: StoreErrorCode, cause: &str) -> Box<StoreError> {
    Box::new(StoreError {code,cause:cause.into(),detail:StoreDetail::None,remedy:Remedy {text:"Use explicit init for missing state; otherwise restore access or use the authenticated live-host route.".into(),command:None},retry:Retry::AfterReread})
}
