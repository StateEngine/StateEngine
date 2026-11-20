//! Deadline refusals shared by the cold worker and the parse family.
use crate::cold::failure;
use se_types::{Detail, SeError, details};
use std::time::Duration;

pub fn cpu_expired(limit: Duration) -> SeError {
    SeError::new(Detail::DeadlineExceeded(details::DeadlineExceeded {
        op: "Atlas parse CPU".into(),
        deadline_ms: limit.as_millis().min(u128::from(u64::MAX)) as u64,
    }))
}
pub fn cleanup_error(error: std::io::Error, limit: Duration) -> SeError {
    if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        stall(limit).with_cause(error)
    } else {
        failure(error)
    }
}
pub fn stall(limit: Duration) -> SeError {
    SeError::new(Detail::DeadlineExceeded(details::DeadlineExceeded {
        op: "Atlas scheduling stall".into(),
        deadline_ms: limit.as_millis().min(u128::from(u64::MAX)) as u64,
    }))
}
