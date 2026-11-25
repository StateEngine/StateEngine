//! Native state-file acquisition shared by host and adoption: a bounded retry
//! across contention that reopens pins on every attempt, and the public store
//! errors a failed acquisition becomes.
use se_proc::{StateFileError, StateFileErrorCode};
use se_store::{StoreDetail, StoreError, StoreErrorCode};
use se_types::{Remedy, Retry};
use std::time::{Duration, Instant};

pub struct AcquisitionError {
    error: StateFileError,
    waited: Duration,
}
impl AcquisitionError {
    pub fn into_store(self) -> Box<StoreError> {
        if !self.error.is_contended() {
            return native_error(self.error);
        }
        Box::new(StoreError {
            code: StoreErrorCode::Busy,
            cause: format!("Native file acquisition remains contended: {}", self.error),
            detail: StoreDetail::NativeContention {
                waited_ms: self.waited.as_millis().try_into().unwrap_or(u64::MAX),
            },
            remedy: Remedy {
                text: "Wait for the current file operation to finish, reread the protected state, then retry the same request; preserve the existing files.".into(),
                command: None,
            },
            retry: Retry::AfterReread,
        })
    }
    pub fn into_public(
        self,
        fallback: impl FnOnce(StateFileError) -> se_types::SeError,
    ) -> se_types::SeError {
        if self.error.is_contended() {
            se_core::store_error::store_error(&self.into_store())
        } else {
            fallback(self.error)
        }
    }
}

/// One retry policy for synchronous staging and asynchronous launch cleanup.
/// Every attempt reopens native pins; waiting does not retain a worker slot.
pub struct AcquisitionRetry {
    deadline: Instant,
    started: Instant,
    contended: Option<StateFileError>,
}
pub enum Acquisition<T> {
    Ready(T),
    Wait(Duration),
}
impl AcquisitionRetry {
    pub fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            started: Instant::now(),
            contended: None,
        }
    }
    pub fn acquire<T>(
        &mut self,
        acquire: impl FnOnce() -> Result<T, StateFileError>,
    ) -> Result<Acquisition<T>, AcquisitionError> {
        let failed = |error| AcquisitionError {
            error,
            waited: self.started.elapsed(),
        };
        if Instant::now() >= self.deadline
            && let Some(error) = self.contended.take()
        {
            return Err(failed(error));
        }
        match acquire() {
            Ok(value) => Ok(Acquisition::Ready(value)),
            Err(error) if error.is_contended() => {
                let remaining = self.deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(failed(error));
                }
                self.contended = Some(error);
                Ok(Acquisition::Wait(remaining.min(Duration::from_millis(10))))
            }
            Err(error) => Err(failed(error)),
        }
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
