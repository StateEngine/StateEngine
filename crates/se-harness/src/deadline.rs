//! Shared absolute time/cancellation bounds for host and harness operations.
use se_types::{Generation, Result, SeError};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub struct ClientOptions {
    pub expected_generation: Option<Generation>,
    pub timeout: Duration,
    pub cancelled: Arc<AtomicBool>,
}

pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct Deadline {
    started: Instant,
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
        Self::new(timeout, Arc::clone(&options.cancelled))
    }
    pub fn new(timeout: Duration, cancelled: Arc<AtomicBool>) -> Result<Self> {
        let started = Instant::now();
        let at = started
            .checked_add(timeout)
            .ok_or_else(|| SeError::invalid("IPC deadline", "a representable absolute deadline"))?;
        let deadline = Self {
            started,
            at,
            budget: timeout,
            cancelled,
        };
        deadline.remaining()?;
        Ok(deadline)
    }
    #[cfg(feature = "listener")]
    pub fn idle() -> Result<Self> {
        Self::new(IDLE_TIMEOUT, Arc::new(AtomicBool::new(false)))
    }
    #[cfg(feature = "listener")]
    pub fn next_call(&self) -> Result<Self> {
        Self::new(CALL_TIMEOUT, Arc::clone(&self.cancelled))
    }
    #[cfg(feature = "listener")]
    pub fn retained(&self) -> Self {
        Self {
            started: self.started,
            at: self.at,
            budget: self.budget,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
    #[cfg(feature = "listener")]
    pub fn observed_since(mut self, observed_at: Instant) -> Self {
        self.started = self.started.min(observed_at);
        self
    }
    pub fn at(&self) -> Instant {
        self.at
    }
    pub fn started(&self) -> Instant {
        self.started
    }
    #[cfg(feature = "listener")]
    pub fn capped_by(&self, limit: &Self) -> Self {
        Self {
            started: self.started.min(limit.started),
            at: self.at.min(limit.at),
            budget: self.budget.min(limit.budget),
            cancelled: Arc::clone(&self.cancelled),
        }
    }
    pub fn stage(&self, maximum: Duration) -> Result<Self> {
        let budget = maximum.min(self.remaining()?);
        let at = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| SeError::invalid("IPC stage", "a representable deadline"))?
            .min(self.at);
        Ok(Self {
            started: self.started,
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
    pub fn from_parts(at: Instant, budget: Duration, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            started: Instant::now(),
            at,
            budget,
            cancelled,
        }
    }
    pub fn budget(&self) -> Duration {
        self.budget
    }
    pub fn cancelled(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }
    pub fn native_bound(&self) -> se_proc::native_ipc::IpcIoBound {
        se_proc::native_ipc::IpcIoBound {
            deadline: self.at,
            cancelled: Arc::clone(&self.cancelled),
        }
    }
}

#[cfg(feature = "channels")]
impl se_channels::AsChannelDeadline for Deadline {
    fn as_channel_deadline(&self) -> se_channels::ChannelDeadline {
        se_channels::ChannelDeadline::from_parts(self.at, self.budget, Arc::clone(&self.cancelled))
    }
}

#[cfg(feature = "listener")]
impl se_remote::broker::Budget for Deadline {
    fn remaining(&self) -> Result<Duration> {
        Deadline::remaining(self)
    }
    fn write_timeout(&self) -> Duration {
        WRITE_TIMEOUT
    }
}
