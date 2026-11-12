//! Native failures exercise the production worker, with this dedicated test
//! executable as its private entry. No provider, shell or engine session runs.
//! Bug: virtual image headroom was conflated with the resident ceiling.
//! Protects: 96 MB virtual admission still cancels and reaps a child above 64 MB resident.
#[cfg(target_os = "linux")]
mod linux {
    use se_proc::atlas_worker::{AtlasWorker, ENTRY, MEMORY_BYTES, WorkerChannel};
    use std::{
        error::Error,
        io::{self, Write},
        os::unix::process::ExitStatusExt,
        path::Path,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    type Check<T = ()> = Result<T, Box<dyn Error>>;
    fn until() -> Instant {
        Instant::now() + Duration::from_secs(3)
    }
    fn receive(worker: &mut AtlasWorker) -> Check<Vec<u8>> {
        let end = until();
        loop {
            worker.wait_ready(end)?;
            if let Some(bytes) = worker.receive()? {
                return Ok(bytes);
            }
            if worker.try_reap()?.is_some() || Instant::now() >= end {
                return Err("worker exited or deadline expired before its report".into());
            }
        }
    }
    fn spawn(mode: &str, deadline: Instant) -> Check<AtlasWorker> {
        Ok(AtlasWorker::spawn(
            &std::env::current_exe()?,
            &serde_json::to_vec(mode)?,
            deadline,
        )?)
    }
    fn reap(worker: &mut AtlasWorker) -> Check {
        let end = until();
        worker.acknowledge_completion()?;
        loop {
            if let Some(status) = worker.try_reap()? {
                assert!(status.success(), "{status}");
                break;
            }
            if Instant::now() >= end {
                return Err("worker did not exit after acknowledgment".into());
            }
            std::thread::yield_now();
        }
        assert!(
            !Path::new(&format!("/proc/{}", worker.pid())).exists(),
            "reaped worker remained present"
        );
        Ok(())
    }
    fn probe() -> Check {
        let (mut channel, bytes) = WorkerChannel::receive()?;
        let mode: String = serde_json::from_slice(&bytes)?;
        match mode.as_str() {
            "abort" => {
                // Zero RLIMIT_CORE so the SIGABRT does not stall on the
                // machine's core collector, then report the applied limit
                // as stderr witness before aborting.
                let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                // SAFETY: fixed native rlimit argument.
                if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) } < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                let mut core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
                // SAFETY: exact writable native rlimit output.
                if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) } < 0 {
                    return Err(io::Error::last_os_error().into());
                }
                io::stderr().write_all(
                    format!("native abort marker core-limit={}\n", core.rlim_cur)
                        .as_bytes(),
                )?;
                std::process::abort();
            }
            "noisy" => {
                // A full stderr pipe must return WouldBlock instead of
                // stalling the completion protocol.
                let _ = io::stderr().write_all(&[b'x'; 8192]);
                channel.send(b"ready")?;
            }
            "denials" => {
                // SAFETY: fixed syscall arguments, no borrowed output. Any
                // unexpected successful descriptor is closed in this test child.
                let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                let socket_error = io::Error::last_os_error().raw_os_error();
                if socket >= 0 {
                    // SAFETY: close only the descriptor returned by this probe.
                    unsafe { libc::close(socket) };
                }
                // SAFETY: clone3 with a null buffer cannot create a child; the
                // production filter must reject before the native EFAULT check.
                let clone =
                    unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<libc::c_void>(), 0) };
                let clone_error = io::Error::last_os_error().raw_os_error();
                let image = c"/bin/true";
                let args = [image.as_ptr(), std::ptr::null()];
                let env = [std::ptr::null::<libc::c_char>()];
                // SAFETY: retained NUL-terminated executable and pointer arrays;
                // unexpected success exits this probe instead of reporting PASS.
                let exec = unsafe { libc::execve(image.as_ptr(), args.as_ptr(), env.as_ptr()) };
                let exec_error = io::Error::last_os_error().raw_os_error();
                channel.send(&serde_json::to_vec(&(
                    socket,
                    socket_error,
                    clone,
                    clone_error,
                    exec,
                    exec_error,
                ))?)?;
            }
            "limits" => {
                let mut limits = Vec::new();
                for resource in [libc::RLIMIT_AS, libc::RLIMIT_CPU, libc::RLIMIT_NOFILE] {
                    let mut limit = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    // SAFETY: exact writable native rlimit output.
                    if unsafe { libc::getrlimit(resource, &mut limit) } < 0 {
                        return Err(io::Error::last_os_error().into());
                    }
                    limits.push((limit.rlim_cur, limit.rlim_max));
                }
                // SAFETY: anonymous allocation requests no existing address or
                // file. An unexpectedly admitted mapping is immediately released.
                let mapping = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        128_000_000,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                let denied = mapping == libc::MAP_FAILED;
                let error = io::Error::last_os_error().raw_os_error();
                if !denied {
                    // SAFETY: release exactly this probe's successful mapping.
                    unsafe { libc::munmap(mapping, 128_000_000) };
                }
                // SAFETY: read only priority of this exact current process.
                let priority = unsafe { libc::syscall(libc::SYS_ioprio_get, 1, 0) };
                channel.send(&serde_json::to_vec(&(limits, denied, error, priority))?)?;
            }
            "resident" => {
                let bytes = 72_000_000;
                // SAFETY: this dedicated child owns the anonymous mapping and
                // touches only offsets inside it. The parent must cancel it.
                let mapping = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        bytes,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                if mapping == libc::MAP_FAILED {
                    return Err(io::Error::last_os_error().into());
                }
                for offset in (0..bytes).step_by(4096) {
                    // SAFETY: each offset is within this child-owned mapping.
                    unsafe { mapping.cast::<u8>().add(offset).write_volatile(1) };
                }
                channel.send(b"resident")?;
            }
            "sleep" => {
                channel.send(b"ready")?;
                // SAFETY: this dedicated child waits for an exact parent kill.
                loop {
                    // SAFETY: this dedicated child waits for its exact parent.
                    unsafe { libc::pause() };
                }
            }
            _ => return Err("unknown probe mode".into()),
        }
        channel.await_reap()?;
        Ok(())
    }
    fn orphan_owner(path: &Path) -> Check {
        let mut worker = spawn("sleep", until())?;
        assert_eq!(receive(&mut worker)?, b"ready");
        std::fs::write(path, worker.pid().to_string())?;
        // SAFETY: kill only this dedicated test owner, after the production
        // child has validated the channel and installed all restrictions.
        unsafe { libc::raise(libc::SIGKILL) };
        Err("SIGKILL returned".into())
    }
    fn parent_death() -> Check {
        // SAFETY: this dedicated test process adopts only its own orphan probe,
        // permitting an exact wait witness rather than mistaking a zombie for live.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        let path = std::env::temp_dir().join(format!("atlas-parent-death-{}", std::process::id()));
        assert!(!path.exists(), "private test output already exists");
        let mut owner = Command::new(std::env::current_exe()?)
            .arg("--orphan-owner")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        assert!(!owner.wait()?.success());
        let pid: u32 = std::fs::read_to_string(&path)?.parse()?;
        std::fs::remove_file(&path)?;
        let end = until();
        let mut status = 0;
        loop {
            // SAFETY: exact adopted child PID from the owner probe; an
            // unreaped child cannot be recycled to another process instance.
            let result = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
            if result == pid as i32 {
                assert!(libc::WIFSIGNALED(status));
                assert_eq!(libc::WTERMSIG(status), libc::SIGKILL);
                break;
            }
            if result < 0 {
                return Err(io::Error::last_os_error().into());
            }
            if Instant::now() >= end {
                // SAFETY: retain custody and clean up only the exact unreaped
                // adopted child before failing the missing-guard assertion.
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                    libc::waitpid(pid as i32, &mut status, 0);
                }
                return Err("parent death left its contained child alive".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }
    #[expect(
        clippy::cognitive_complexity,
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) fn run() -> Check {
        let args: Vec<_> = std::env::args_os().collect();
        if args.get(1).is_some_and(|arg| arg == ENTRY) {
            return probe();
        }
        if args.get(1).is_some_and(|arg| arg == "--orphan-owner") {
            return orphan_owner(Path::new(args.get(2).ok_or("missing orphan output")?));
        }
        {
            use se_proc::atlas_git::{GitRead, read};
            let id = "1".repeat(40);
            let blocked = || {
                read(
                    Path::new("/usr/bin/git"),
                    Path::new("/"),
                    Path::new("/"),
                    GitRead::RootTree { commit: &id },
                    until(),
                )
            };
            let mut first = spawn("noisy", until())?;
            assert_eq!(receive(&mut first)?, b"ready");
            assert_eq!(
                blocked()
                    .err()
                    .ok_or("Git overlapped the live parser")?
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            reap(&mut first)?;
            let mut second = spawn("noisy", until())?;
            assert_eq!(receive(&mut second)?, b"ready");
            drop(first);
            assert_eq!(
                blocked()
                    .err()
                    .ok_or("dropping an old reaped parser released its successor's allocation")?
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            reap(&mut second)?;
            // A non-repository refusal is still a real, exactly reaped Git
            // process, admitted only after both parser phases have closed.
            assert!(!blocked()?.status.success());
        }
        println!(
            "PASS Git shares the parser allocation and exact reap releases only its own reservation"
        );
        {
            let mut worker = spawn("denials", until())?;
            let data = receive(&mut worker)?;
            let (socket, se, clone, ce, exec, ee): (
                i32,
                Option<i32>,
                i64,
                Option<i32>,
                i32,
                Option<i32>,
            ) = serde_json::from_slice(&data)?;
            assert_eq!((socket, se), (-1, Some(libc::EPERM)));
            assert_eq!((clone, ce), (-1, Some(libc::EPERM)));
            assert_eq!((exec, ee), (-1, Some(libc::EPERM)));
            reap(&mut worker)?;
        }
        println!(
            "PASS seccomp denies network, clone and exec through the production private entry"
        );
        {
            let mut worker = spawn("limits", until())?;
            let (limits, denied, error, priority): (Vec<(u64, u64)>, bool, Option<i32>, i64) =
                serde_json::from_slice(&receive(&mut worker)?)?;
            assert!(denied, "allocation above 96 MB virtual ceiling succeeded");
            assert_eq!(limits, vec![(96_000_000, 96_000_000), (900, 900), (64, 64)]);
            assert_eq!(error, Some(libc::ENOMEM));
            assert_eq!(priority >> 13, 3);
            reap(&mut worker)?;
        }
        println!("PASS 96 MB virtual ceiling, CPU/descriptors and idle I/O limits");
        {
            assert_eq!(MEMORY_BYTES, 64_000_000);
            let mut worker = spawn("resident", until())?;
            assert_eq!(receive(&mut worker)?, b"resident");
            let error = worker
                .observe_memory()
                .err()
                .ok_or("resident ceiling did not cancel the child")?;
            assert!(
                error.to_string().contains("Atlas child exceeded 64 MB"),
                "{error}"
            );
            assert!(worker.peak_observed_bytes() > 64_000_000);
            assert!(
                worker.try_reap()?.is_some(),
                "resident breach did not reap its exact child"
            );
            assert!(!Path::new(&format!("/proc/{}", worker.pid())).exists());
        }
        println!("PASS unchanged 64 MB resident ceiling cancels and reaps its exact child");
        {
            let mut worker = spawn("sleep", Instant::now() + Duration::from_millis(200))?;
            assert_eq!(receive(&mut worker)?, b"ready");
            std::thread::sleep(Duration::from_millis(220));
            let error = worker
                .receive()
                .err()
                .ok_or("deadline guard did not refuse")?;
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(
                worker.try_reap()?.is_some(),
                "deadline did not reap the exact child"
            );
        }
        println!("PASS deadline kills and reaps its exact contained child");
        parent_death()?;
        println!("PASS parent death kills the contained child; exact adopted wait completed");
        {
            // The aborting child zeroes RLIMIT_CORE so the SIGABRT reaps
            // without waiting for the machine's core collector under
            // workspace load. Keep the exact signal/stderr/reap assertions,
            // with a separate allowance for that OS exit work rather than
            // the three-second probe clock.
            let end = Instant::now() + Duration::from_secs(15);
            let mut worker = spawn("abort", end)?;
            loop {
                worker.wait_ready(end)?;
                if let Some(status) = worker.try_reap()? {
                    assert_eq!(status.signal(), Some(libc::SIGABRT));
                    assert!(
                        worker.stderr_report().contains("native abort marker core-limit=0"),
                        "aborting child did not zero RLIMIT_CORE"
                    );
                    break;
                }
                if Instant::now() >= end {
                    return Err("abort was not reaped".into());
                }
            }
        }
        println!("PASS abnormal native exit retains its signal and stderr");
        {
            let mut worker = spawn("noisy", until())?;
            assert_eq!(receive(&mut worker)?, b"ready");
            reap(&mut worker)?;
            let report = worker.stderr_report();
            assert!(
                report.len() < 4400,
                "stderr capture exceeded its owner bound"
            );
            assert!(
                report.contains("stderr_at_capacity=true"),
                "stderr bound not reported"
            );
        }
        println!("PASS full stderr pipe cannot stall completion or grow owner capture");
        println!("8 passed; 0 failed");
        Ok(())
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|v| v == "--list") {
        if !std::env::args().any(|v| v == "--ignored") {
            println!("atlas_worker_failure: test");
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    linux::run()?;
    #[cfg(not(target_os = "linux"))]
    println!("native Linux Atlas worker failure checks are unsupported on this platform");
    Ok(())
}
