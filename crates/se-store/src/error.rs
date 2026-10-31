use crate::*;
use se_types::{Remedy, Retry};
pub(crate) fn fail(code: StoreErrorCode, cause: impl Into<String>) -> Box<StoreError> {
    Box::new(StoreError { code, cause: cause.into(), detail: StoreDetail::None,
        remedy: Remedy { text: "Preserve the original request key; reread the named state before retrying. For unreadable state, use diagnosis and a validated automatic backup.".into(), command: None },
        retry: match code { StoreErrorCode::Busy | StoreErrorCode::Backpressure => Retry::AfterReread, _ => Retry::Never } })
}
pub(crate) fn sql(e: rusqlite::Error) -> Box<StoreError> {
    use rusqlite::ErrorCode;
    let code = match &e {
        rusqlite::Error::SqliteFailure(c, _) => match c.code {
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => StoreErrorCode::Busy,
            ErrorCode::DiskFull => StoreErrorCode::DiskFull,
            ErrorCode::ConstraintViolation => StoreErrorCode::EventInvalid,
            _ => StoreErrorCode::Unreadable,
        },
        _ => StoreErrorCode::Unreadable,
    };
    fail(code, e.to_string())
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
