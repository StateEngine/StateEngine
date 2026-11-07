use super::*;
use crate::{
    StartIdentity,
    support::{changed, native},
};
use std::{
    io,
    mem::zeroed,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    ptr,
};

/// An exit subscription to the selected process instance. It grants no right
/// to signal, and is not a transferable process handle or recovery capability.
pub(super) struct Pin(OwnedFd);
impl Pin {
    pub(super) fn open(expected: &ProcessIdentity) -> ProcResult<Self> {
        // SAFETY: creates a unique native event queue, with no process mutation.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "kqueue birth pin",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: successful kqueue allocation transfers this unique descriptor.
        let queue = unsafe { OwnedFd::from_raw_fd(raw) };
        // Darwin kqueues are close-on-exec by default; no inheritable capability
        // is introduced into a concurrently created provider process.
        let change = libc::kevent {
            ident: expected.pid.0 as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: ptr::null_mut(),
        };
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: exact initialized change; no event output or blocking wait.
        if unsafe { libc::kevent(queue.as_raw_fd(), &change, 1, ptr::null_mut(), 0, &timeout) } < 0
        {
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "register birth exit pin",
                io::Error::last_os_error(),
            ));
        }
        Ok(Self(queue))
    }
    pub(super) fn live(&self, expected: &ProcessIdentity) -> ProcResult<()> {
        // SAFETY: initialized event output, filled by the bounded native query.
        let mut event: libc::kevent = unsafe { zeroed() };
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: retained queue and exact output; zero timeout cannot wait.
        let count =
            unsafe { libc::kevent(self.0.as_raw_fd(), ptr::null(), 0, &mut event, 1, &timeout) };
        if count < 0 {
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "read birth exit pin",
                io::Error::last_os_error(),
            ));
        }
        if count != 0 {
            if event.flags & libc::EV_ERROR != 0 {
                return Err(native(
                    ProcErrorCode::IdentityUnreadable,
                    "read birth exit event",
                    io::Error::from_raw_os_error(event.data as i32),
                ));
            }
            return Err(changed(expected, None));
        }
        Ok(())
    }
    pub(super) fn birth(
        &self,
        expected: &ProcessIdentity,
        deadline: Instant,
    ) -> ProcResult<ProcessBirthTime> {
        bound(deadline)?;
        let StartIdentity::MacOs {
            seconds,
            microseconds,
        } = expected.start
        else {
            return Err(changed(expected, None));
        };
        if microseconds >= 1_000_000 {
            return Err(failure(
                ProcErrorCode::IdentityUnreadable,
                "invalid native start microseconds",
            ));
        }
        let unix_micros = seconds
            .checked_mul(1_000_000)
            .and_then(|value| value.checked_add(u64::from(microseconds)))
            .and_then(|value| i64::try_from(value).ok())
            .ok_or_else(|| {
                failure(
                    ProcErrorCode::IdentityUnreadable,
                    "native birth exceeds Unix microsecond range",
                )
            })?;
        self.live(expected)?;
        bound(deadline)?;
        Ok(ProcessBirthTime {
            unix_micros,
            precision: Duration::from_micros(1),
        })
    }
}
