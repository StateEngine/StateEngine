//! Direct-client runtime lease. Native store file mechanics are shared with the host.
pub use se_host::state_files::Files;
use se_store::{
    LeaseIdentity, RuntimeLease, StateFiles, StoreDetail, StoreError, StoreErrorCode, StoreResult,
};
use se_types::{Read, Remedy, Retry};
use std::{fs::File, path::Path};

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
