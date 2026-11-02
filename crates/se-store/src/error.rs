use crate::*;
use se_types::{Remedy, Retry};
mod diagnostic;
pub(crate) use diagnostic::{context, io, sqlite_context};
pub(crate) fn fail(code: StoreErrorCode, cause: impl Into<String>) -> Box<StoreError> {
    let remedy = match code {
        StoreErrorCode::ReferenceMissing => {
            "Correct the named identifier or reread the referenced entity before retrying."
        }
        StoreErrorCode::Corrupt => {
            "Preserve the database and its WAL/SHM; diagnose corruption and use the owner's validated backup restore."
        }
        StoreErrorCode::Unreadable => {
            "Inspect the store and protected temp-directory access, sharing and filesystem support; retry the original request after restoring access. Unreadable state is not absent; do not initialize over it."
        }
        StoreErrorCode::ApplicationMismatch
        | StoreErrorCode::TooNew
        | StoreErrorCode::VersionUnsupported => {
            "Use the compatible application version or the correct state directory; preserve this source rather than initialize over it."
        }
        StoreErrorCode::ProjectRemoved => {
            "The project was removed and its history retained; `se init --repo <root>` re-adopts the repository as a new project."
        }
        StoreErrorCode::PragmaRefused => {
            "Restore the required SQLite/filesystem setting or use a compatible build before admitting writes."
        }
        _ => "Preserve the original request key; reread the named state before retrying.",
    };
    Box::new(StoreError {
        code,
        cause: cause.into(),
        detail: StoreDetail::None,
        remedy: Remedy {
            text: remedy.into(),
            command: None,
        },
        retry: match code {
            StoreErrorCode::Busy | StoreErrorCode::Backpressure => Retry::AfterReread,
            _ => Retry::Never,
        },
    })
}
pub(crate) fn sql(e: rusqlite::Error) -> Box<StoreError> {
    use rusqlite::ErrorCode;
    let code = match &e {
        rusqlite::Error::SqliteFailure(c, _) => match c.code {
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => StoreErrorCode::Busy,
            ErrorCode::DiskFull => StoreErrorCode::DiskFull,
            ErrorCode::ConstraintViolation => StoreErrorCode::EventInvalid,
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => StoreErrorCode::Corrupt,
            _ => StoreErrorCode::Unreadable,
        },
        _ => StoreErrorCode::Unreadable,
    };
    let mut error = fail(code, e.to_string());
    if let Some(extended_code) = e.sqlite_extended_error_code() {
        error.detail = StoreDetail::Sqlite {
            extended_code,
            native_os_code: None,
        };
    }
    error
}
pub(crate) fn invalid(e: impl std::fmt::Display) -> Box<StoreError> {
    fail(StoreErrorCode::EventInvalid, e.to_string())
}
pub(crate) fn later<T>(operation: &str) -> StoreResult<T> {
    Err(fail(
        StoreErrorCode::InvalidTransition,
        format!("{operation} is not implemented in the wave-1 store; no effect occurred"),
    ))
}
impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.cause)
    }
}
impl std::error::Error for StoreError {}
