//! Creation and bounded custody of the finite helper tree.
use super::{
    clock::Expiry,
    identity::{ProcessPin, State},
    invalid,
};
use std::{
    io,
    os::{
        fd::{AsRawFd, RawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Child, Command},
    time::{Duration, Instant},
};
unsafe extern "C" {
    fn setiopolicy_np(kind: i32, scope: i32, policy: i32) -> i32;
}

pub(super) fn prepare(command: &mut Command, channel: &UnixStream, parent: u32) -> io::Result<()> {
    let descriptor = channel.as_raw_fd();
    // SAFETY: initialized native resource-limit output.
    let mut inherited: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: read-only resource query into exact initialized output.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut inherited) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let close_limit = i32::try_from(inherited.rlim_cur)
        .ok()
        .filter(|n| *n <= 65_536)
        .ok_or_else(|| invalid("Git descriptor inventory exceeds its qualified bound"))?;
    // SAFETY: only native async-signal-safe operations and scalar captures run after fork.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(descriptor, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            for (kind, cap) in [(libc::RLIMIT_CPU, 900), (libc::RLIMIT_NOFILE, 64)] {
                let mut old: libc::rlimit = std::mem::zeroed();
                if libc::getrlimit(kind, &mut old) < 0 {
                    return Err(io::Error::last_os_error());
                }
                let value = cap.min(old.rlim_cur).min(old.rlim_max);
                let limit = libc::rlimit {
                    rlim_cur: value,
                    rlim_max: value,
                };
                if libc::setrlimit(kind, &limit) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::setpriority(libc::PRIO_PROCESS, 0, 10) < 0 || setiopolicy_np(0, 0, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            for fd in 4..close_limit {
                // Preserve Command's exec-error pipe until successful exec.
                if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0
                    && io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
                {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::getppid() as u32 != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
    }
    Ok(())
}
pub(super) fn nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: caller retains the live descriptor throughout this flag update.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: retain every current flag and add only nonblocking I/O.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(super) fn ready(fd: RawFd, expiry: Expiry) -> io::Result<bool> {
    let mut event = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let millis = expiry.remaining()?.as_millis().clamp(1, 10) as i32;
    // SAFETY: one retained descriptor and finite original-clock wait.
    let result = unsafe { libc::poll(&mut event, 1, millis) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(error);
    }
    if event.revents & libc::POLLNVAL != 0 {
        return Err(invalid("Git private descriptor became invalid"));
    }
    Ok(result > 0)
}
/// None is an independently observed exited child, not an unreadable sample.
/// The supervisor still owns waitpid and must collect that exact child next.
pub(super) fn combined(
    supervisor: &ProcessPin,
    git: &ProcessPin,
    expiry: Expiry,
) -> io::Result<Option<u64>> {
    let deadline = expiry.native_bound()?.deadline;
    if supervisor.state(deadline)? != State::Alive {
        return Err(invalid("Git memory observation lost its live supervisor"));
    }
    match git.state(deadline)? {
        State::Exited => return Ok(None),
        State::Absent => return Err(invalid("unreaped Git child is unexpectedly absent")),
        State::Alive => (),
    }
    let owner_bytes = crate::atlas_worker::macos_peak(supervisor.pid)?;
    let git_bytes = match crate::atlas_worker::macos_peak(git.pid) {
        Ok(bytes) => bytes,
        Err(error) => {
            if git.state(deadline)? == State::Exited {
                return Ok(None);
            }
            return Err(error);
        }
    };
    let bytes = owner_bytes
        .checked_add(git_bytes)
        .ok_or_else(|| invalid("Git combined physical footprint overflow"))?;
    if bytes > crate::atlas_worker::MEMORY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            format!(
                "Git helper tree exceeds its {}-byte sampled physical footprint budget",
                crate::atlas_worker::MEMORY_BYTES
            ),
        ));
    }
    expiry.remaining()?;
    Ok(Some(bytes))
}
pub(super) fn before_release(
    supervisor: &ProcessPin,
    git: &ProcessPin,
    expiry: Expiry,
) -> io::Result<u64> {
    combined(supervisor, git, expiry)?
        .ok_or_else(|| invalid("Git bootstrap exited before its measured release barrier"))
}
/// Direct Child pins identity until waitpid. Never report exit without reap.
pub(super) fn reap(child: &mut Child) -> io::Result<()> {
    reap_until(child, Instant::now() + Duration::from_millis(200))
}
pub(super) fn reap_until(child: &mut Child, deadline: Instant) -> io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    if let Err(error) = child.kill() {
        if child.try_wait()?.is_none() {
            return Err(error);
        }
        return Ok(());
    }
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Git exact child termination is pending",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
