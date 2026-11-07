//! One native event queue per scope, registered with the existing host reactor.
use crate::{support::*, *};
use std::{
    fs::File,
    io,
    mem::zeroed,
    os::fd::{AsRawFd, FromRawFd},
    ptr,
};

pub(super) struct Watch {
    pub file: File,
    limit: usize,
}
impl Watch {
    pub fn new(limit: usize) -> ProcResult<Self> {
        // SAFETY: native queue allocation; Darwin marks it close-on-exec/fork.
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "create process event queue",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: successful allocation returns exclusive descriptor ownership.
        let file = unsafe { File::from_raw_fd(raw) };
        Ok(Self { file, limit })
    }
    pub fn track(&self, expected: &ProcessIdentity) -> ProcResult<()> {
        let live = || -> ProcResult<bool> {
            match crate::read_process(expected.machine.clone(), expected.pid)? {
                ProcessRead::Present(value) if value.identity == *expected => Ok(true),
                ProcessRead::Present(value) => Err(changed(expected, Some(&value.identity))),
                ProcessRead::Absent { .. } | ProcessRead::ExitedRecord { .. } => Ok(false),
            }
        };
        if !live()? {
            return Ok(());
        }
        let change = libc::kevent {
            ident: expected.pid.0 as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR,
            fflags: libc::NOTE_EXIT | libc::NOTE_FORK | libc::NOTE_EXEC,
            data: 0,
            udata: ptr::null_mut(),
        };
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: retained queue and exact initialized change; no blocking wait.
        if unsafe {
            libc::kevent(
                self.file.as_raw_fd(),
                &change,
                1,
                ptr::null_mut(),
                0,
                &timeout,
            )
        } < 0
        {
            let cause = io::Error::last_os_error();
            if cause.raw_os_error() == Some(libc::ESRCH) && !live()? {
                return Ok(());
            }
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "register process exit/fork",
                cause,
            ));
        }
        // Registration is a nudge, never a substitute for instance observation.
        let _ = live()?;
        Ok(())
    }
    pub fn drain(&self) -> ProcResult<Vec<ProcessId>> {
        let mut executed = Vec::new();
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        for _ in 0..=self.limit {
            // SAFETY: initialized, aligned fixed native event output.
            let mut event: libc::kevent = unsafe { zeroed() };
            // SAFETY: retained queue and writable output, with zero timeout.
            let count = unsafe {
                libc::kevent(
                    self.file.as_raw_fd(),
                    ptr::null(),
                    0,
                    &mut event,
                    1,
                    &timeout,
                )
            };
            if count < 0 {
                return Err(native(
                    ProcErrorCode::IdentityUnreadable,
                    "read process notifications",
                    io::Error::last_os_error(),
                ));
            }
            if count == 0 {
                return Ok(executed);
            }
            if event.flags & libc::EV_ERROR != 0 {
                return Err(native(
                    ProcErrorCode::IdentityUnreadable,
                    "process notification error",
                    io::Error::from_raw_os_error(event.data as i32),
                ));
            }
            if event.fflags & libc::NOTE_EXEC != 0 {
                let pid = u32::try_from(event.ident)
                    .map_err(|_| input("process event", "native PID overflow"))?;
                if pid == 0 {
                    return Err(input("process event", "invalid native PID"));
                }
                executed.push(ProcessId(pid));
            }
        }
        Err(capacity(
            "process notifications per observation",
            self.limit as u64,
        ))
    }
}
