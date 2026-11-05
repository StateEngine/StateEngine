//! SQLite may report exhausted WAL shared-memory growth as generic I/O.
//! Refine that diagnosis only with a current native zero-space observation.
use se_store::{StoreDetail, StoreError, StoreErrorCode};
use se_types::{Detail, SeError, details};
use std::{error::Error, path::Path};
fn io_path(error: &SeError) -> Option<&str> {
    let mut cause = error.cause.as_deref().map(|value| value as &dyn Error);
    while let Some(value) = cause {
        if let Some(store) = value.downcast_ref::<StoreError>()
            && store.code == StoreErrorCode::Unreadable
            && let StoreDetail::Io {
                opened_path,
                sqlite_extended_code: Some(code),
                ..
            } = &store.detail
            && code & 0xff == 10
        {
            return Some(opened_path);
        }
        cause = value.source();
    }
    None
}
pub(super) fn diagnose(error: SeError, home: &Path) -> SeError {
    let Some(path) = io_path(&error).map(Path::new) else {
        return error;
    };
    if !path.starts_with(home) {
        return error;
    }
    let Some(parent) = path.parent() else {
        return error;
    };
    let available =
        se_proc::NativeStateFiles::open(parent).and_then(|files| files.available_bytes());
    if !matches!(available, Ok(0)) {
        return error;
    }
    SeError::new(Detail::StoreDiskFull(details::StoreDiskFull {
        path: path.display().to_string(),
        free_bytes: Some(0),
    }))
    .with_cause(error)
}
