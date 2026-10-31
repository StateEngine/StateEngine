use super::*;
use crate::{StartIdentity, support::native};
use std::{
    fs::File,
    io::{self, Read},
    os::fd::{AsRawFd, FromRawFd},
};
pub(super) struct Pin(File);
impl Pin {
    pub(super) fn open(expected: &ProcessIdentity) -> ProcResult<Self> {
        // SAFETY: positive validated native selector; success returns a unique
        // CLOEXEC kernel process-instance reference, with no signal dispatched.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, expected.pid.0, 0u32) } as i32;
        if raw < 0 {
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "pin process birth with pidfd_open",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: successful native allocation transferred this unique descriptor.
        Ok(Self(unsafe { File::from_raw_fd(raw) }))
    }
    pub(super) fn live(&self, expected: &ProcessIdentity) -> ProcResult<()> {
        let mut event = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: exact retained process-instance pin, finite zero-timeout query.
        let rc = unsafe { libc::poll(&mut event, 1, 0) };
        if rc < 0 {
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "query birth-time process pin",
                io::Error::last_os_error(),
            ));
        }
        if rc != 0 {
            return Err(crate::support::changed(expected, None));
        }
        Ok(())
    }
    pub(super) fn birth(
        &self,
        expected: &ProcessIdentity,
        deadline: Instant,
    ) -> ProcResult<ProcessBirthTime> {
        let StartIdentity::Linux { start_ticks } = expected.start else {
            return Err(failure(
                ProcErrorCode::IdentityChanged,
                "Linux birth requires the verified Linux tick identity",
            ));
        };
        let boot = boot_seconds(deadline)?;
        // SAFETY: errno is writable thread-local native storage; clearing it
        // distinguishes a real sysconf error from an indeterminate native value.
        unsafe {
            *libc::__errno_location() = 0;
        }
        // SAFETY: immutable native clock-tick unit query, never a guessed HZ.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz <= 0 {
            let cause = io::Error::last_os_error();
            let cause = if cause.raw_os_error() == Some(0) {
                io::Error::other("native query did not supply a positive tick rate")
            } else {
                cause
            };
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "sysconf(_SC_CLK_TCK)",
                cause,
            ));
        }
        let micros = u128::from(boot)
            .checked_mul(1_000_000)
            .and_then(|base| {
                u128::from(start_ticks)
                    .checked_mul(1_000_000)
                    .map(|ticks| ticks / hz as u128)
                    .and_then(|elapsed| base.checked_add(elapsed))
            })
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| {
                failure(
                    ProcErrorCode::IdentityUnreadable,
                    "native birth exceeds the Unix microsecond range",
                )
            })?;
        // A privileged wall-clock adjustment can change the kernel's boot epoch.
        // Refuse mixed epochs rather than join two different observations.
        if boot_seconds(deadline)? != boot {
            return Err(failure(
                ProcErrorCode::IdentityChanged,
                "kernel boot epoch changed during the pinned birth read",
            ));
        }
        self.live(expected)?;
        Ok(ProcessBirthTime {
            unix_micros: micros,
            precision: Duration::from_secs(1),
        })
    }
}
fn boot_seconds(deadline: Instant) -> ProcResult<u64> {
    bound(deadline)?;
    const MAX: usize = 1024 * 1024;
    let mut data = Vec::new();
    File::open("/proc/stat")
        .and_then(|file| file.take(MAX as u64 + 1).read_to_end(&mut data))
        .map_err(|e| {
            native(
                ProcErrorCode::IdentityUnreadable,
                "read kernel boot epoch",
                e,
            )
        })?;
    bound(deadline)?;
    if data.len() > MAX {
        return Err(failure(
            ProcErrorCode::ResourceLimit,
            "kernel boot epoch read exceeds 1 MiB",
        ));
    }
    let mut values = data
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(b"btime "));
    let value = values.next().ok_or_else(|| {
        failure(
            ProcErrorCode::IdentityUnreadable,
            "kernel boot epoch is absent",
        )
    })?;
    if values.next().is_some() {
        return Err(failure(
            ProcErrorCode::IdentityUnreadable,
            "duplicate kernel boot epoch",
        ));
    }
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(failure(
            ProcErrorCode::IdentityUnreadable,
            "malformed kernel boot epoch",
        ));
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| {
            failure(
                ProcErrorCode::IdentityUnreadable,
                "kernel boot epoch exceeds its native range",
            )
        })
}
