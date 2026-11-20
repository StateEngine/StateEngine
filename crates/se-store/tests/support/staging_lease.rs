//! A runtime lease over the native file port that records the last staging
//! file it created, shared by the staging regressions in and outside `src/`.
use super::fixture::{Fixture, Lease};
use se_store::*;
use se_store_contract::error::fail;
use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
};

fn invalid(cause: impl std::fmt::Display) -> Box<StoreError> {
    fail(StoreErrorCode::EventInvalid, cause.to_string())
}
pub struct StagingFiles {
    pub native: se_proc::NativeStateFiles,
    pub created: Mutex<Option<fs::Metadata>>,
}
fn file_error(e: se_proc::StateFileError) -> Box<StoreError> {
    fail(StoreErrorCode::Unreadable, e.to_string())
}
impl StateFiles for StagingFiles {
    fn prepare_directory(&self, path: &Path) -> StoreResult<()> {
        self.native.prepare_directory(path).map_err(file_error)
    }
    fn retire_empty_staging(&self, staged: ProtectedStaging) -> StoreResult<std::fs::File> {
        self.native
            .retire_empty_staging(se_proc::ProtectedStateStaging {
                path: staged.path,
                file: staged.file,
            })
            .map_err(file_error)
    }
    fn create_staging(&self, path: &Path) -> StoreResult<ProtectedStaging> {
        let staged = self.native.create_staging(path).map_err(file_error)?;
        *self.created.lock().map_err(|_| invalid("metadata lock"))? =
            Some(staged.file.metadata().map_err(|e| invalid(e.to_string()))?);
        Ok(ProtectedStaging {
            path: staged.path,
            file: staged.file,
        })
    }
    fn inspect_metadata(&self, path: &Path) -> StoreResult<se_types::Read<std::fs::Metadata>> {
        Ok(
            match self.native.inspect_metadata(path).map_err(file_error)? {
                Some(value) => se_types::Read::Present { value },
                None => se_types::Read::Absent {
                    checked: format!("native metadata absence at {}", path.display()),
                },
            },
        )
    }
    fn readback(&self, path: &Path) -> StoreResult<se_types::Read<fs::File>> {
        Ok(match self.native.readback(path).map_err(file_error)? {
            Some(value) => se_types::Read::Present { value },
            None => se_types::Read::Absent {
                checked: "native file absent".into(),
            },
        })
    }
    fn publish_no_replace(&self, from: &Path, to: &Path) -> StoreResult<()> {
        self.native.publish_no_replace(from, to).map_err(file_error)
    }
    fn remove_owned(&self, path: &Path, digest: [u8; 32]) -> StoreResult<()> {
        let owned = se_proc::OwnedFile::open(path)
            .map_err(file_error)?
            .ok_or_else(|| invalid("staging file absent before retirement"))?;
        owned.remove(digest).map_err(file_error)?;
        assert!(self.native.readback(path).map_err(file_error)?.is_none());
        Ok(())
    }
}
pub struct StagingLease {
    pub held: Arc<Lease>,
    pub files: StagingFiles,
}
impl StagingLease {
    pub fn new(f: &Fixture, held: Arc<Lease>) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            held,
            files: StagingFiles {
                native: se_proc::NativeStateFiles::open(&f.options.state_directory)?,
                created: Mutex::new(None),
            },
        })
    }
}
impl RuntimeLease for StagingLease {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        self.held.identity()
    }
    fn files(&self) -> &dyn StateFiles {
        &self.files
    }
}
