//! Real Linux process, owner and IPC readers agree on one native birth even
//! when comm contains final-delimiter lookalikes, whitespace and non-UTF8.
#[cfg(target_os = "linux")]
mod linux {
    use se_proc::{
        MachineId, NativeState, OwnerTarget, ProcessId, ProcessRead, observe_owner, read_process,
    };
    use std::{
        error::Error,
        io::{BufRead, Write},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;
    const NAME: &[u8] = b"odd) name\n) \xff\0";
    fn live(pid: ProcessId) -> Result<se_proc::LiveObservation> {
        match read_process(MachineId::new("linux-facts-judge")?, pid)
            .map_err(|e| format!("{e:?}"))?
        {
            ProcessRead::Present(value) => Ok(value),
            other => Err(format!("expected live process: {other:?}").into()),
        }
    }
    fn child() -> Result {
        // SAFETY: PR_SET_NAME copies at most 16 bytes from this retained,
        // NUL-terminated name into this dedicated child process's thread name.
        if unsafe { libc::prctl(libc::PR_SET_NAME, NAME.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let pid = ProcessId(std::process::id());
        let process = live(pid)?;
        let peer = se_proc::native_ipc::observe_ipc_self()?;
        let (
            se_types::StartIdentity::Linux {
                start_ticks: ipc_ticks,
            },
            se_proc::StartIdentity::Linux {
                start_ticks: process_ticks,
            },
        ) = (peer.started(), &process.identity.start)
        else {
            return Err("Linux readers returned a non-Linux birth".into());
        };
        assert_eq!(ipc_ticks, process_ticks);
        let owner = observe_owner(OwnerTarget::Current, &[])?;
        assert_eq!(owner.start(), &process.identity.start);
        println!("LINUX-FACTS-READY");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(())
    }
    // This wrapper is the sole owner and reaper of its exact spawned child.
    struct Held(Child);
    impl Drop for Held {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            if let Err(error) = self.0.wait() {
                eprintln!("owned facts child wait: {error}");
            }
        }
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub fn run() -> Result {
        if std::env::args().nth(1).as_deref() == Some("--facts-child") {
            return child();
        }
        let mut child = Held(
            Command::new(std::env::current_exe()?)
                .arg("--facts-child")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let mut reader =
            std::io::BufReader::new(child.0.stdout.take().ok_or("child stdout missing")?);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        assert_eq!(line.trim(), "LINUX-FACTS-READY");
        let pid = ProcessId(child.0.id());
        let bytes = std::fs::read(format!("/proc/{}/stat", pid.0))?;
        assert!(
            bytes
                .windows(NAME.len() - 1)
                .any(|part| part == &NAME[..NAME.len() - 1]),
            "native comm fixture not installed"
        );
        let process = live(pid)?;
        let owner = observe_owner(
            OwnerTarget::Process {
                pid,
                start: &process.identity.start,
            },
            &[],
        )?;
        assert_eq!(owner.pid(), pid);
        assert_eq!(owner.start(), &process.identity.start);
        let se_proc::StartIdentity::Linux { start_ticks } = process.identity.start else {
            return Err("not Linux birth".into());
        };
        let wrong = se_proc::StartIdentity::Linux {
            start_ticks: start_ticks + 1,
        };
        let error = observe_owner(OwnerTarget::Process { pid, start: &wrong }, &[])
            .err()
            .ok_or("wrong birth admitted")?;
        assert_eq!(error.operation, "bind observed owner");
        assert!(
            error
                .source
                .to_string()
                .contains("target process start changed")
        );
        drop(child.0.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: zeroed siginfo_t is the documented WNOHANG no-event state.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: this exact unreaped child is retained by Held. WNOWAIT
            // observes exit without stealing the Child object's eventual reap.
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid.0,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: successful waitid initialized this SIGCHLD-layout output.
            if unsafe { info.si_pid() } == pid.0 as i32 {
                break;
            }
            if Instant::now() >= deadline {
                return Err("owned child did not reach native exit witness".into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        match read_process(process.identity.machine.clone(), pid).map_err(|e| format!("{e:?}"))? {
            ProcessRead::ExitedRecord {
                state: NativeState::ExitedAwaitingReap,
                start,
                ..
            } => assert_eq!(start, process.identity.start),
            other => {
                return Err(format!(
                    "native-exited unreaped child lost its exited record: {other:?}"
                )
                .into());
            }
        }
        let error = observe_owner(
            OwnerTarget::Process {
                pid,
                start: &process.identity.start,
            },
            &[],
        )
        .err()
        .ok_or("zombie admitted as an owner")?;
        assert_eq!(error.operation, "read owner ancestry");
        assert!(error.source.to_string().contains("process has exited"));
        assert!(child.0.wait()?.success());
        println!(
            "linux_process_facts: 4 passed, 0 failed; real comm bytes, cross-reader birth, wrong-birth refusal and unreaped exit distinctions"
        );
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run()
}
#[cfg(not(target_os = "linux"))]
fn main() {
    println!("linux_process_facts: 0 cases; Linux native consumer only");
}
