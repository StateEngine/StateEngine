pub(in crate::bootstrap) use super::launch::{receive, spawn};
use super::*;
pub(in crate::bootstrap) use super::{
    Child, clock, hello, initial_identity, read, read_diagnostics, release, revoke,
    settle_launcher, verify_image, write,
};
use std::ptr;
pub(in crate::bootstrap) fn receive_hello(
    child: &mut Child,
    events: &mut File,
    deadline: Instant,
) -> ProcResult<ProcessId> {
    wait(events, libc::POLLIN, deadline)?;
    let mut byte = [0u8; 1];
    let mut vector = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 16];
    // SAFETY: msghdr is native POD; all used output pointers and capacities follow.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&control);
    // SAFETY: exact retained socket and aligned writable message/control buffers.
    let count = unsafe {
        libc::recvmsg(
            events.as_raw_fd(),
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if count != 1 || byte != *b"R" || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
    {
        return Err(input(
            "runtime hello",
            "missing, unreadable or truncated kernel-authenticated hello",
        ));
    }
    // SAFETY: successful recvmsg initialized the bounded aligned control region.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null() {
        return Err(input("runtime hello", "kernel sender credentials absent"));
    }
    // SAFETY: header points inside the validated retained recvmsg control region.
    let expected = unsafe {
        (*header).cmsg_level == libc::SOL_SOCKET
            && (*header).cmsg_type == libc::SCM_CREDENTIALS
            && (*header).cmsg_len
                == libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32) as usize
    };
    if !expected {
        return Err(input("runtime hello", "unexpected native control record"));
    }
    // SAFETY: exact SCM_CREDENTIALS length checked; copy avoids alignment assumptions.
    let credentials = unsafe { ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>()) };
    // SAFETY: immutable native current-user query.
    if credentials.pid <= 0 || credentials.uid != unsafe { libc::geteuid() } {
        return Err(input("runtime hello", "different native sender owner"));
    }
    let pid = ProcessId(credentials.pid as u32);
    child.pid = Some(pid);
    Ok(pid)
}
pub(in crate::bootstrap) fn pin(child: &mut Child, pid: ProcessId) -> ProcResult<()> {
    // SAFETY: kernel-reported sender PID; pidfd_open returns an exact instance reference.
    child.pin = Some(owned(
        unsafe { libc::syscall(libc::SYS_pidfd_open, pid.0, 0) } as i32,
    )?);
    Ok(())
}
pub(in crate::bootstrap) fn alive(child: &Child, identity: &ProcessIdentity) -> ProcResult<()> {
    let pin = child
        .pin
        .as_ref()
        .ok_or_else(|| input("runtime custody", "native pidfd missing"))?;
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: immutable zero-timeout query on the exact retained native instance.
    let rc = unsafe { libc::poll(&mut poll, 1, 0) };
    if rc != 0 {
        return Err(input(
            "runtime custody",
            "exact child is exited or unreadable",
        ));
    }
    match crate::read_process(identity.machine.clone(), identity.pid)? {
        ProcessRead::Present(live) if &live.identity == identity => Ok(()),
        ProcessRead::Present(live) => Err(changed(identity, Some(&live.identity))),
        _ => Err(changed(identity, None)),
    }
}
pub(in crate::bootstrap) fn abort(
    child: &mut Child,
    _identity: Option<&ProcessIdentity>,
) -> ProcResult<()> {
    let Some(pin) = &child.pin else {
        // EOF revokes an uncommitted child even before its native hello arrives.
        return Err(input(
            "runtime abort",
            "startup authorization revoked; retain unproved child until its kernel hello/exit can be read",
        ));
    };
    // SAFETY: exact retained pidfd, literal signal, no numeric-PID mutation.
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pin.as_raw_fd(),
            libc::SIGKILL,
            ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    } < 0
    {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESRCH) {
            return Err(fail("abort uncommitted runtime", e));
        }
    }
    Ok(())
}
pub(in crate::bootstrap) fn witness(
    child: &Child,
    identity: &ProcessIdentity,
) -> ProcResult<RuntimeExitObservation> {
    let pin = child
        .pin
        .as_ref()
        .ok_or_else(|| input("runtime custody", "native pidfd missing"))?;
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: retained pidfd is queried without waiting or mutation.
    let rc = unsafe { libc::poll(&mut poll, 1, 0) };
    if rc < 0 {
        return Err(fail("observe runtime pidfd", io::Error::last_os_error()));
    }
    if rc == 0 {
        return Ok(RuntimeExitObservation::Pending {
            identity: identity.clone(),
        });
    }
    if poll.revents & libc::POLLIN == 0 {
        return Err(input("runtime exit", "unreadable pidfd readiness"));
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
    crate::platform::runtime_boot_id()
}

pub(in crate::bootstrap) fn enable_credentials(parent: &File) -> ProcResult<()> {
    let enable: i32 = 1;
    // SAFETY: retained receiving socket and exact native integer option value.
    if unsafe {
        libc::setsockopt(
            parent.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enable as *const i32).cast(),
            std::mem::size_of_val(&enable) as u32,
        )
    } < 0
    {
        return Err(fail(
            "enable kernel bootstrap credentials",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}
pub(in crate::bootstrap) fn authenticate_creator(
    events: &File,
    expected: &ProcessIdentity,
) -> ProcResult<()> {
    let mut credentials: libc::ucred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of_val(&credentials) as u32;
    // SAFETY: retained connected socket and correctly sized writable kernel credentials.
    if unsafe {
        libc::getsockopt(
            events.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(fail(
            "authenticate runtime creator",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: immutable current native user read.
    let user = unsafe { libc::geteuid() };
    if length as usize != std::mem::size_of_val(&credentials)
        || credentials.pid as u32 != expected.pid.0
        || credentials.uid != user
    {
        return Err(input(
            "runtime creator",
            "inherited channel does not belong to the exact same-user parent",
        ));
    }
    Ok(())
}
pub(in crate::bootstrap) fn single_threaded() -> ProcResult<()> {
    let count = std::fs::read_dir("/proc/self/task")
        .map_err(|e| fail("inspect bootstrap thread count", e))?
        .try_fold(0usize, |n, entry| entry.map(|_| n + 1))
        .map_err(|e| fail("read bootstrap thread count", e))?;
    if count != 1 {
        return Err(input(
            "runtime private entry",
            "bootstrap must precede every runtime thread",
        ));
    }
    Ok(())
}
