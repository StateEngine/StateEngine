//! Native Darwin worker consumers; Linux seccomp and virtual-address limits stay separate.
use se_proc::atlas_worker::{AtlasWorker, ENTRY, WorkerChannel};
use std::{
    io::{self, Write},
    os::unix::{ffi::OsStrExt, process::ExitStatusExt},
    process::ExitStatus,
    time::{Duration, Instant},
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn end() -> Instant {
    Instant::now() + Duration::from_secs(15)
}
fn spawn(mode: &str, deadline: Instant) -> Check<AtlasWorker> {
    Ok(AtlasWorker::spawn(
        &std::env::current_exe()?,
        &serde_json::to_vec(mode)?,
        deadline,
    )?)
}
fn gone(pid: u32) -> Check {
    let mut status = 0;
    // SAFETY: read-only wait for this fixture's exact already-reaped child; never signal a PID.
    let result = unsafe { libc::waitpid(i32::try_from(pid)?, &mut status, libc::WNOHANG) };
    assert_eq!(result, -1, "worker did not reap its exact child");
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    Ok(())
}
fn receive(worker: &mut AtlasWorker) -> Check<Vec<u8>> {
    let deadline = end();
    loop {
        worker.wait_ready(deadline)?;
        if let Some(bytes) = worker.receive()? {
            return Ok(bytes);
        }
        if let Some(status) = worker.try_reap()? {
            return Err(format!(
                "worker exited before reply: {status}; {}",
                worker.failure_diagnostic()?
            )
            .into());
        }
        if Instant::now() >= deadline {
            return Err("native worker reply deadline".into());
        }
    }
}
fn exited(worker: &mut AtlasWorker) -> Check<ExitStatus> {
    let deadline = end();
    loop {
        worker.wait_ready(deadline)?;
        if let Some(status) = worker.try_reap()? {
            gone(worker.pid())?;
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("native worker exit deadline".into());
        }
    }
}
fn finish(worker: &mut AtlasWorker) -> Check {
    worker.acknowledge_completion()?;
    assert!(exited(worker)?.success());
    Ok(())
}
fn probe_limits(channel: &mut WorkerChannel) -> Check {
    let mut values = Vec::new();
    for resource in [libc::RLIMIT_CPU, libc::RLIMIT_NOFILE, libc::RLIMIT_RSS] {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: fixed native resource selector and exact initialized writable output.
        if unsafe { libc::getrlimit(resource, &mut limit) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        values.push((limit.rlim_cur, limit.rlim_max));
    }
    // SAFETY: read-only priority observation of this exact current process.
    let priority = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
    channel.send(&serde_json::to_vec(&(values, priority))?)?;
    Ok(())
}
fn probe_denials(channel: &mut WorkerChannel, port: u16) -> Check {
    // Socket allocation alone need not perform a sandboxed network operation.
    // The parent holds a reachable listener, so refusal is not an absent peer.
    let (connect, connect_error) =
        match std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)) {
            Ok(stream) => {
                drop(stream);
                (0, None)
            }
            Err(error) => (-1, error.raw_os_error()),
        };
    // SAFETY: the unexpected child executes only _exit; no allocation, lock or unwind after fork.
    let fork = unsafe { libc::fork() };
    let fork_error = io::Error::last_os_error().raw_os_error();
    if fork == 0 {
        // SAFETY: immediately exits only the unexpectedly created child.
        unsafe { libc::_exit(0) };
    }
    if fork > 0 {
        let mut status = 0;
        // SAFETY: exact positive child returned by this probe's fork, joined once.
        if unsafe { libc::waitpid(fork, &mut status, 0) } != fork {
            return Err(io::Error::last_os_error().into());
        }
    }
    let image = std::ffi::CString::new(std::env::current_exe()?.as_os_str().as_bytes())?;
    let argv = [
        image.as_ptr(),
        c"--unexpected-exec".as_ptr(),
        std::ptr::null(),
    ];
    let env = [std::ptr::null::<libc::c_char>()];
    // SAFETY: retained terminated path and pointer arrays; unexpected success cannot report a pass.
    let exec = unsafe { libc::execve(image.as_ptr(), argv.as_ptr(), env.as_ptr()) };
    let exec_error = io::Error::last_os_error().raw_os_error();
    channel.send(&serde_json::to_vec(&(
        connect,
        connect_error,
        fork,
        fork_error,
        exec,
        exec_error,
    ))?)?;
    Ok(())
}
fn probe() -> Check {
    let (mut channel, bytes) = WorkerChannel::receive()?;
    let mode: String = serde_json::from_slice(&bytes)?;
    match mode.as_str() {
        "limits" => probe_limits(&mut channel)?,
        value if value.starts_with("denials:") => probe_denials(
            &mut channel,
            value
                .strip_prefix("denials:")
                .ok_or("denial port missing")?
                .parse()?,
        )?,
        "abort" => {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: sets the core-file limit of this dedicated child only.
            if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } < 0 {
                return Err(io::Error::last_os_error().into());
            }
            eprintln!("native Darwin abort marker");
            std::process::abort();
        }
        "resident" => {
            let bytes = 72_000_000;
            // SAFETY: private anonymous mapping; each touched offset is inside this child's allocation.
            let mapping = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    bytes,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            if mapping == libc::MAP_FAILED {
                return Err(io::Error::last_os_error().into());
            }
            for offset in (0..bytes).step_by(4096) {
                // SAFETY: every offset lies within the owned mapping.
                unsafe { mapping.cast::<u8>().add(offset).write_volatile(1) };
            }
            loop {
                std::thread::park();
            }
        }
        "noisy" => {
            io::stderr().write_all(&[b'x'; 9000])?;
            channel.send(b"ready")?;
        }
        "sleep" => {
            channel.send(b"ready")?;
            loop {
                std::thread::park();
            }
        }
        "echo" => channel.send(b"ready")?,
        _ => return Err("unknown native worker fixture mode".into()),
    }
    channel.await_reap()?;
    Ok(())
}
fn one_child() -> Check {
    let mut first = spawn("echo", end())?;
    assert_eq!(receive(&mut first)?, b"ready");
    let error = spawn("echo", end())
        .err()
        .ok_or("overlapping cold child admitted")?;
    let error = error
        .downcast_ref::<io::Error>()
        .ok_or("overlap returned a non-native refusal")?;
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        error
            .to_string()
            .contains("previous Atlas child has not been reaped")
    );
    finish(&mut first)?;
    drop(first);
    let mut next = spawn("echo", end())?;
    assert_eq!(receive(&mut next)?, b"ready");
    finish(&mut next)?;
    Ok(())
}
fn limits() -> Check {
    let mut inherited = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // Darwin's RSS selector aliases address space. The worker inherits this
    // policy; the separate resident-footprint control enforces its memory cap.
    // SAFETY: fixed native selector and exact initialized writable output.
    if unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut inherited) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut worker = spawn("limits", end())?;
    let (limits, priority): (Vec<(u64, u64)>, i32) =
        serde_json::from_slice(&receive(&mut worker)?)?;
    assert_eq!(
        limits,
        [
            (900, 900),
            (64, 64),
            (inherited.rlim_cur, inherited.rlim_max)
        ]
    );
    assert!(priority >= 10);
    finish(&mut worker)?;
    Ok(())
}
fn denials() -> Check {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    // First witness that the exact loopback listener accepts outside the worker.
    let connected = std::net::TcpStream::connect(listener.local_addr()?)?;
    drop(listener.accept()?);
    drop(connected);
    let mut worker = spawn(&format!("denials:{}", listener.local_addr()?.port()), end())?;
    let facts: (i32, Option<i32>, i32, Option<i32>, i32, Option<i32>) =
        serde_json::from_slice(&receive(&mut worker)?)?;
    assert_eq!(
        facts,
        (
            -1,
            Some(libc::EPERM),
            -1,
            Some(libc::EPERM),
            -1,
            Some(libc::EPERM)
        )
    );
    finish(&mut worker)?;
    Ok(())
}
fn deadline() -> Check {
    let mut worker = spawn("sleep", Instant::now() + Duration::from_secs(2))?;
    assert_eq!(receive(&mut worker)?, b"ready");
    let deadline = end();
    loop {
        match worker.receive() {
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                break;
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => return Err("worker deadline was not observed".into()),
        }
    }
    gone(worker.pid())?;
    Ok(())
}
fn abnormal_exit() -> Check {
    let mut worker = spawn("abort", end())?;
    assert_eq!(exited(&mut worker)?.signal(), Some(libc::SIGABRT));
    assert!(
        worker
            .failure_diagnostic()?
            .contains("native Darwin abort marker")
    );
    Ok(())
}
fn noisy_stderr() -> Check {
    let mut worker = spawn("noisy", end())?;
    assert_eq!(receive(&mut worker)?, b"ready");
    finish(&mut worker)?;
    let report = worker.failure_diagnostic()?;
    assert!(report.len() < 8400);
    assert!(report.contains("808 earlier bytes omitted"));
    Ok(())
}
fn footprint() -> Check {
    let mut worker = spawn("resident", end())?;
    assert_eq!(exited(&mut worker)?.code(), Some(122));
    assert!(
        worker
            .failure_diagnostic()?
            .contains("64 MB footprint limit exceeded")
    );
    Ok(())
}
pub(super) fn run() -> Check {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|v| v == "--unexpected-exec")
    {
        return Err("native sandbox admitted executable replacement".into());
    }
    if std::env::args_os().nth(1).is_some_and(|v| v == ENTRY) {
        return probe();
    }
    one_child()?;
    println!(
        "PASS native worker admits one child and releases custody after exact completion/reap"
    );
    limits()?;
    println!(
        "PASS native CPU/descriptor limits, inherited address-space policy and background priority"
    );
    denials()?;
    println!("PASS native sandbox denies network, fork and executable replacement");
    deadline()?;
    println!("PASS native deadline cancels and exactly reaps the held worker");
    abnormal_exit()?;
    println!("PASS native abnormal exit retains its signal and stderr");
    noisy_stderr()?;
    println!("PASS bounded native stderr retains its tail and reports the discarded bytes");
    footprint()?;
    println!("PASS native footprint guard exits a worker above its resident budget");
    println!(
        "atlas_worker_failure macOS: 7 passed, 0 failed; Linux address-space/seccomp and orphan-reaper probes NOT GRADED"
    );
    Ok(())
}
