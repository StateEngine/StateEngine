//! Shared wall-clock observation for direct and hosted CLI routes.
use se_types::{Result, SeError};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_us() -> Result<i64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| se_core::scope::unreadable("system clock", &e.to_string()))?;
    i64::try_from(elapsed.as_micros())
        .map_err(|_| SeError::invalid("system clock", "representable Unix microseconds"))
}
