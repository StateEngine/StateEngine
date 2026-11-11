use super::*;
use std::{
    io::Read,
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, Stdio},
};
struct Owned(Child, bool, crate::atlas_worker::lease::Lease);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.1 {
            let _ = self.0.kill();
            let deadline = Instant::now() + std::time::Duration::from_millis(200);
            loop {
                match self.0.try_wait() {
                    Ok(Some(_)) => {
                        self.1 = true;
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(1))
                    }
                    _ => {
                        self.2.retain_on_failed_reap();
                        eprintln!(
                            "Git history termination pending for owned pid {}; cold phase allocation remains reserved",
                            self.0.id()
                        );
                        break;
                    }
                }
            }
        }
    }
}
fn nonblocking(fd: i32) -> io::Result<()> {
    // SAFETY: the borrowed pipe descriptor remains retained by its Child pipe.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: valid retained descriptor; add only the nonblocking status flag.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn drain(reader: &mut impl Read, bytes: &mut Vec<u8>, maximum: usize) -> io::Result<bool> {
    let mut block = [0; 4096];
    loop {
        match reader.read(&mut block) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if bytes.len() + n > maximum {
                    return Err(io::Error::new(
                        io::ErrorKind::OutOfMemory,
                        format!(
                            "Git history output exceeds {maximum} bytes; lower the history bound"
                        ),
                    ));
                }
                bytes.extend_from_slice(&block[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn read(
    image: &Path,
    control: &Path,
    objects: &Path,
    roots: [&crate::NativeSourceRoot; 2],
    args: Vec<String>,
    deadline: Instant,
) -> io::Result<GitOutput> {
    let lease = crate::atlas_worker::lease::Lease::acquire()?;
    let filesystem = super::filesystem::Filesystem::new(image, roots)?;
    let parent = std::process::id() as libc::pid_t;
    let mut command = Command::new(image);
    command
        .current_dir(control)
        .env_clear()
        .env("HOME", control)
        .env("XDG_CONFIG_HOME", control)
        .env("GIT_DIR", control)
        .env("GIT_OBJECT_DIRECTORY", objects)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("LC_ALL", "C")
        .env("GIT_PAGER", "cat")
        .args([
            "--no-optional-locks",
            "--no-replace-objects",
            "-c",
            "core.packedGitWindowSize=1048576",
            "-c",
            "core.packedGitLimit=8388608",
            "-c",
            "core.deltaBaseCacheLimit=1048576",
            "-c",
            "core.commitGraph=false",
            "-c",
            "core.multiPackIndex=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            "-c",
            "protocol.allow=never",
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the pre-exec callback performs only async-signal-safe native limit
    // calls, with initialized stack POD. It never raises an inherited bound.
    unsafe {
        command.pre_exec(move || {
            let mut inherited = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_AS, &mut inherited) < 0 {
                return Err(io::Error::last_os_error());
            }
            let cap = crate::atlas_worker::MEMORY_BYTES
                .min(inherited.rlim_cur)
                .min(inherited.rlim_max);
            let limit = libc::rlimit {
                rlim_cur: cap,
                rlim_max: cap,
            };
            let cpu = libc::rlimit {
                rlim_cur: 900,
                rlim_max: 900,
            };
            let descriptors = libc::rlimit {
                rlim_cur: 64,
                rlim_max: 64,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &limit) < 0
                || libc::setrlimit(libc::RLIMIT_CPU, &cpu) < 0
                || libc::setrlimit(libc::RLIMIT_NOFILE, &descriptors) < 0
                || libc::setpriority(libc::PRIO_PROCESS, 0, 10) < 0
                || libc::syscall(libc::SYS_ioprio_set, 1, 0, 3 << 13) < 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                || libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            filesystem.enter()?;
            contain()?;
            Ok(())
        });
    }
    let mut child = Owned(command.spawn()?, false, lease);
    let mut stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| invalid("Git stdout pipe missing"))?;
    let mut stderr = child
        .0
        .stderr
        .take()
        .ok_or_else(|| invalid("Git stderr pipe missing"))?;
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut closed = [false; 2];
    let mut status = None;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Git history deadline exceeded; original data preserved",
            ));
        }
        if !closed[0] {
            closed[0] = drain(&mut stdout, &mut out, OUTPUT_BYTES)?;
        }
        if !closed[1] {
            closed[1] = drain(&mut stderr, &mut err, STDERR_BYTES)?;
        }
        if status.is_none() {
            status = child.0.try_wait()?;
            if status.is_some() {
                child.1 = true;
            }
        }
        if closed.iter().all(|v| *v)
            && let Some(status) = status
        {
            return Ok(GitOutput {
                status,
                stdout: out,
                stderr: err,
            });
        }
        let mut fds = [
            libc::pollfd {
                fd: if closed[0] { -1 } else { stdout.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if closed[1] { -1 } else { stderr.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(50) as i32;
        // SAFETY: exactly two writable pollfd values refer to retained pipes.
        if unsafe { libc::poll(fds.as_mut_ptr(), 2, wait) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            return Err(io::Error::last_os_error());
        }
    }
}

/// The closed read verbs need neither network nor descendants. Exec remains
/// available for the one initial Git image; no verb/config can invoke a helper.
/// The filter uses stack POD only, including when installed after fork.
fn contain() -> io::Result<()> {
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Git history syscall containment is unavailable",
    ));
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const DENIED: [libc::c_long; 7] = [
            libc::SYS_socket,
            libc::SYS_connect,
            libc::SYS_socketpair,
            libc::SYS_clone,
            libc::SYS_clone3,
            libc::SYS_fork,
            libc::SYS_vfork,
        ];
        let mut filter = [libc::sock_filter {
            code: 0,
            jt: 0,
            jf: 0,
            k: 0,
        }; 21];
        filter[..6].copy_from_slice(&[
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 4,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: ARCH,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x80000000,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x35,
                jt: 0,
                jf: 1,
                k: 0x40000000,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050000 | libc::EPERM as u32,
            },
        ]);
        for (n, call) in DENIED.into_iter().enumerate() {
            filter[6 + 2 * n] = libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: call as u32,
            };
            filter[7 + 2 * n] = libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x00050000 | libc::EPERM as u32,
            };
        }
        filter[20] = libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        };
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: exact initialized stack filter remains live across both native calls.
        if unsafe{libc::prctl(libc::PR_SET_NO_NEW_PRIVS,1,0,0,0)}<0
            // SAFETY: immutable bounded program with 21 initialized instructions.
            || unsafe{libc::prctl(libc::PR_SET_SECCOMP,libc::SECCOMP_MODE_FILTER,&program)}<0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
