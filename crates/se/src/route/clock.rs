//! Shared wall-clock observation for direct and hosted CLI routes.
use se_types::{Result, SeError};

pub fn now_us() -> Result<i64> {
    se_core::clock::now_us().map_err(|error| match error {
        se_core::clock::ClockError::BeforeEpoch(error) => {
            se_core::scope::unreadable("system clock", &error.to_string())
        }
        se_core::clock::ClockError::OutOfRange => {
            SeError::invalid("system clock", "representable Unix microseconds")
        }
    })
}
