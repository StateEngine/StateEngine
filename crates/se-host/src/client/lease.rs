//! Shared absolute time/cancellation bounds. Native lease/channel operations
//! receive the same deadline; reconnect never renews a request's clock.
use crate::client::ClientOptions;
use se_types::{Result, SeError};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Deadline {
    at: Instant,
    budget: Duration,
    cancelled: Arc<AtomicBool>,
}
impl Deadline {
    pub fn from_options(options: &ClientOptions) -> Result<Self> {
        let timeout = options.timeout.min(CALL_TIMEOUT);
        if timeout.is_zero() {
            return Err(SeError::invalid(
                "IPC timeout",
                "a positive bounded duration",
            ));
        }
        let at = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| SeError::invalid("IPC deadline", "a representable absolute deadline"))?;
        let deadline = Self {
            at,
            budget: timeout,
            cancelled: Arc::clone(&options.cancelled),
        };
        deadline.remaining()?;
        Ok(deadline)
    }
    pub fn at(&self) -> Instant {
        self.at
    }
    pub fn stage(&self, maximum: Duration) -> Result<Self> {
        let budget = maximum.min(self.remaining()?);
        let at = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| SeError::invalid("IPC stage", "a representable deadline"))?
            .min(self.at);
        Ok(Self {
            at,
            budget,
            cancelled: Arc::clone(&self.cancelled),
        })
    }
    pub fn remaining(&self) -> Result<Duration> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(SeError::new(se_types::Detail::Cancelled(
                se_types::details::Cancelled {
                    op: "local IPC".into(),
                },
            )));
        }
        self.at
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                SeError::new(se_types::Detail::DeadlineExceeded(
                    se_types::details::DeadlineExceeded {
                        op: "local IPC".into(),
                        deadline_ms: self.budget.as_millis() as u64,
                    },
                ))
            })
    }
}
