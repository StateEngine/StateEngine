//! Fallible wall-clock observation shared by local consumers.

#[derive(Debug)]
pub enum ClockError {
    BeforeEpoch(std::time::SystemTimeError),
    OutOfRange,
}

pub fn now_us() -> std::result::Result<i64, ClockError> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(ClockError::BeforeEpoch)?;
    i64::try_from(elapsed.as_micros()).map_err(|_| ClockError::OutOfRange)
}
