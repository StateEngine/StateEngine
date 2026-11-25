//! A machine-wide monotonic timestamp for native host-to-client intervals.
use std::io;

/// Microseconds on the native machine's monotonic clock. Values are comparable
/// only within one machine and boot; they are never wall-clock timestamps.
#[cfg(unix)]
pub fn monotonic_micros() -> io::Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is writable storage for one initialized native timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let seconds = u64::try_from(value.tv_sec).map_err(|_| invalid())?;
    let nanos = u64::try_from(value.tv_nsec).map_err(|_| invalid())?;
    if nanos >= 1_000_000_000 {
        return Err(invalid());
    }
    seconds
        .checked_mul(1_000_000)
        .and_then(|seconds| seconds.checked_add(nanos / 1_000))
        .ok_or_else(invalid)
}

#[cfg(windows)]
pub fn monotonic_micros() -> io::Result<u64> {
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };
    let mut frequency = 0_i64;
    let mut ticks = 0_i64;
    // SAFETY: both calls receive writable storage for their native i64 result.
    let observed = unsafe {
        QueryPerformanceFrequency(&mut frequency) != 0 && QueryPerformanceCounter(&mut ticks) != 0
    };
    if !observed {
        return Err(io::Error::last_os_error());
    }
    let frequency = u128::try_from(frequency).map_err(|_| invalid())?;
    let ticks = u128::try_from(ticks).map_err(|_| invalid())?;
    let micros = ticks
        .checked_mul(1_000_000)
        .and_then(|ticks| ticks.checked_div(frequency))
        .ok_or_else(invalid)?;
    u64::try_from(micros).map_err(|_| invalid())
}

#[cfg(not(any(unix, windows)))]
pub fn monotonic_micros() -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native monotonic clock unavailable",
    ))
}

#[cfg(any(unix, windows))]
fn invalid() -> io::Error {
    io::Error::other("native monotonic clock is outside its representable interval")
}
