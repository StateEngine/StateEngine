//! Bounded display-time observation. Native birth identities remain the custody
//! keys; this conversion never reconstructs ownership from a wall-clock value.
use crate::{ProcError, ProcErrorCode, ProcErrorDetail, ProcResult, ProcessIdentity};
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as os;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as os;

/// OS wall-clock birth converted to the public Time's Unix microsecond unit.
/// Linux's boot epoch is whole seconds, so precision reports one
/// second even when start ticks have a finer quantum. Windows FILETIME is
/// rounded down to microseconds; its full 100ns identity remains unchanged.
/// Darwin reports its native timeval birth directly, with microsecond precision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessBirthTime {
    unix_micros: i64,
    precision: Duration,
}
impl ProcessBirthTime {
    pub fn unix_micros(&self) -> i64 {
        self.unix_micros
    }
    pub fn precision(&self) -> Duration {
        self.precision
    }
}
fn failure(code: ProcErrorCode, reason: &str) -> ProcError {
    ProcError {
        code,
        detail: Box::new(ProcErrorDetail::Input {
            field: "native process birth".into(),
            reason: reason.into(),
        }),
        native: None,
    }
}
fn bound(deadline: Instant) -> ProcResult<()> {
    if Instant::now() >= deadline {
        return Err(failure(
            ProcErrorCode::LaunchTimedOut,
            "original native observation deadline elapsed",
        ));
    }
    Ok(())
}
#[cfg(any(target_os = "linux", windows))]
fn exact(expected: &ProcessIdentity, deadline: Instant) -> ProcResult<()> {
    bound(deadline)?;
    crate::platform::verify_live_identity(expected)?;
    bound(deadline)
}
#[cfg(target_os = "macos")]
fn exact(expected: &ProcessIdentity, deadline: Instant) -> ProcResult<()> {
    crate::macos_process::exact(expected, deadline)
}
/// Pins the selected native process for this read and rechecks its exact
/// boot/start/image before and after conversion. No current wall-clock sample,
/// assumed tick rate, or fabricated zero is used. Missing/unreadable/replaced
/// processes and exhausted deadlines refuse; the pin grants no signal authority.
pub fn observe_process_birth(
    expected: &ProcessIdentity,
    deadline: Instant,
) -> ProcResult<ProcessBirthTime> {
    bound(deadline)?;
    if expected.pid.0 == 0 || expected.pid.0 > i32::MAX as u32 || !expected.image.is_absolute() {
        return Err(failure(
            ProcErrorCode::InvalidInput,
            "positive native PID and absolute verified image required",
        ));
    }
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        let pin = os::Pin::open(expected)?;
        bound(deadline)?;
        pin.live(expected)?;
        exact(expected, deadline)?;
        let value = pin.birth(expected, deadline)?;
        exact(expected, deadline)?;
        pin.live(expected)?;
        bound(deadline)?;
        Ok(value)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    Err(failure(
        ProcErrorCode::UnsupportedPlatform,
        "native pinned birth-time conversion is not implemented on this platform",
    ))
}
