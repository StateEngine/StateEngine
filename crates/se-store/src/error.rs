use crate::*;

use std::time::Duration;
mod diagnostic;
pub(crate) use diagnostic::{context, io, sqlite_context};
/// BUSY extended codes whose failure means the busy handler spent the
/// connection's configured timeout: BUSY (5) and BUSY_RECOVERY (261).
/// BUSY_SNAPSHOT (517) refuses a stale snapshot without consuming the retry
/// loop's timeout, and LOCKED (6) / LOCKED_SHAREDCACHE (262) ran no retry
/// loop at all.
pub(crate) fn busy_wait_extended(code: i32) -> bool {
    use rusqlite::ffi::{SQLITE_BUSY, SQLITE_BUSY_RECOVERY};
    matches!(code, SQLITE_BUSY | SQLITE_BUSY_RECOVERY)
}
/// Stamp the configured busy timeout a BUSY-family refusal fully consumed.
/// Idempotent; LOCKED and unmeasured refusals stay untouched, so a reported
/// 0 ms remains true.
pub(crate) fn stamp_busy_wait(error: &mut Box<StoreError>, bound: Duration) {
    if error.code != StoreErrorCode::Busy || matches!(error.detail, StoreDetail::BusyWait { .. }) {
        return;
    }
    let code = match &error.detail {
        StoreDetail::Sqlite { extended_code, .. } => Some(*extended_code),
        StoreDetail::Io {
            sqlite_extended_code,
            ..
        } => *sqlite_extended_code,
        _ => None,
    };
    if let Some(code) = code.filter(|code| busy_wait_extended(*code)) {
        error.detail = StoreDetail::BusyWait {
            waited_ms: bound.as_millis().min(u64::MAX as u128) as u64,
            extended_code: code,
        };
    }
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

pub(crate) use se_store_contract::error::fail;
