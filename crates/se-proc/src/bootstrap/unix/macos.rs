//! Native instance observation and guarded cleanup for the detached root.
pub(in crate::bootstrap) use super::launch::{receive, spawn};
use super::*;
pub(in crate::bootstrap) use super::{
    Child, clock, hello, initial_identity, read, read_diagnostics, release, revoke,
    settle_launcher, verify_image, write,
};
use std::mem::{size_of, zeroed};
use std::{ptr, sync::atomic::Ordering};

fn credentials(file: &File) -> ProcResult<(u32, ProcessId)> {
    use std::os::fd::AsFd;
    let (uid, pid) = crate::native_ipc::local_socket_credentials(file.as_fd())
        .map_err(|e| input("runtime peer", &e.to_string()))?;
    Ok((uid, ProcessId(pid)))
}
pub(in crate::bootstrap) fn single_threaded() -> ProcResult<()> {
    // SAFETY: exact initialized native task-info output.
    let mut info: libc::proc_taskinfo = unsafe { zeroed() };
    let size = size_of::<libc::proc_taskinfo>() as i32;
    // SAFETY: querying only this early executable's native thread population.
    let count = unsafe {
        libc::proc_pidinfo(
            std::process::id() as i32,
            libc::PROC_PIDTASKINFO,
            0,
            (&mut info as *mut libc::proc_taskinfo).cast(),
            size,
        )
    };
    if count != size || info.pti_threadnum != 1 {
        return Err(input(
            "runtime private entry",
            "native single-threaded bootstrap required",
        ));
    }
    Ok(())
}
pub(in crate::bootstrap) fn receive_hello(
    child: &mut Child,
    events: &mut File,
    deadline: Instant,
) -> ProcResult<ProcessId> {
    let mut byte = [0];
    read(events, &mut byte, deadline)?;
    // LOCAL_PEERPID observes the last native socket owner. The private final
    // child has just written hello and remains paused until our pin ACK.
    let (uid, pid) = credentials(events)?;
    // SAFETY: immutable native current-user query.
    if byte != *b"R"
        || uid != unsafe { libc::geteuid() }
        || Some(pid.0 as i32) == child.launcher
        || pid.0 == std::process::id()
    {
        return Err(input(
            "runtime hello",
            "final same-user kernel peer required",
        ));
    }
    child.pid = Some(pid);
    Ok(pid)
}
pub(in crate::bootstrap) fn pin(child: &mut Child, pid: ProcessId) -> ProcResult<()> {
    // SAFETY: a new owned native event queue; Darwin closes it on exec/fork.
    let queue = owned(unsafe { libc::kqueue() })?;
    let event = libc::kevent {
        ident: pid.0 as usize,
        filter: libc::EVFILT_PROC,
        flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR,
        fflags: libc::NOTE_EXIT,
        data: 0,
        udata: ptr::null_mut(),
    };
    // SAFETY: exact native event registration on the kernel-authenticated paused child.
    if unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            &event,
            1,
            ptr::null_mut(),
            0,
            ptr::null(),
        )
    } < 0
    {
        return Err(fail(
            "retain runtime exit observation",
            io::Error::last_os_error(),
        ));
    }
    child.pin = Some(queue);
    Ok(())
}
fn exited(child: &Child) -> ProcResult<bool> {
    if child.exited.load(Ordering::Acquire) {
        return Ok(true);
    }
    let queue = child
        .pin
        .as_ref()
        .ok_or_else(|| input("runtime custody", "native event registration absent"))?;
    // SAFETY: exact initialized native event output, queried without blocking.
    let mut event: libc::kevent = unsafe { zeroed() };
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: retained queue and one exact writable event with zero timeout.
    let count = unsafe { libc::kevent(queue.as_raw_fd(), ptr::null(), 0, &mut event, 1, &timeout) };
    if count < 0 {
        return Err(fail("observe runtime exit", io::Error::last_os_error()));
    }
    if count == 0 {
        return Ok(false);
    }
    if event.flags & libc::EV_ERROR != 0
        || event.filter != libc::EVFILT_PROC
        || child.pid.map(|p| p.0 as usize) != Some(event.ident)
        || event.fflags & libc::NOTE_EXIT == 0
    {
        return Err(input("runtime exit", "unexpected native process event"));
    }
    child.exited.store(true, Ordering::Release);
    Ok(true)
}
pub(in crate::bootstrap) fn alive(child: &Child, identity: &ProcessIdentity) -> ProcResult<()> {
    if child.pid != Some(identity.pid) || exited(child)? {
        return Err(changed(identity, None));
    }
    crate::macos_process::exact(identity, Instant::now() + Duration::from_secs(5))
}
pub(in crate::bootstrap) fn abort(
    child: &mut Child,
    identity: Option<&ProcessIdentity>,
) -> ProcResult<()> {
    let identity = identity.ok_or_else(|| {
        input(
            "runtime abort",
            "authorization revoked; retain unproved startup custody",
        )
    })?;
    if exited(child)? {
        return Ok(());
    }
    alive(child, identity)?;
    // SAFETY: exact same-user native birth was reobserved under retained exit
    // registration. Darwin retains its explicit non-atomic check/signal bound.
    if unsafe { libc::kill(identity.pid.0 as i32, libc::SIGKILL) } < 0 {
        return Err(fail(
            "abort uncommitted runtime",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}
pub(in crate::bootstrap) fn witness(
    child: &Child,
    identity: &ProcessIdentity,
) -> ProcResult<RuntimeExitObservation> {
    if child.pid != Some(identity.pid) {
        return Err(changed(identity, None));
    }
    if !exited(child)? {
        return Ok(RuntimeExitObservation::Pending {
            identity: identity.clone(),
        });
    }
    Ok(RuntimeExitObservation::Exited(Box::new(
        RuntimeExitWitness {
            identity: identity.clone(),
            evidence: ExitEvidence::KernelHandleSignalled,
            status: ExitStatus::Unavailable {
                reason: ExitStatusUnavailable::NotOurChild,
            },
            observed_at_unix_ns: now()?,
        },
    )))
}
pub(in crate::bootstrap) fn boot_id() -> ProcResult<se_types::BootId> {
    crate::observe_boot_id().map_err(|e| fail(e.operation, e.source))
}
pub(in crate::bootstrap) fn authenticate_creator(
    events: &File,
    expected: &ProcessIdentity,
) -> ProcResult<()> {
    // SAFETY: immutable current-user query for the inherited local socket.
    let user = unsafe { libc::geteuid() };
    let (uid, pid) = credentials(events)?;
    if pid != expected.pid || uid != user {
        return Err(input(
            "runtime creator",
            "inherited channel differs from the same-user parent",
        ));
    }
    Ok(())
}
