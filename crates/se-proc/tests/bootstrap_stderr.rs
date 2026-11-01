//! Cold real bootstrap consumers; no host, endpoint or public stdio substitute.
#[cfg(any(target_os = "linux", windows))]
mod judge {
    use se_proc::*;
    use std::time::{Duration, Instant};
    type Result<T = ()> = std::result::Result<T, String>;
    const SECRET_SENTINEL: &str = "fixture-not-a-real-secret-never-dump-frame";
    const REASON: &str = "cold child refused: fixture storage is unavailable";
    fn error(value: impl std::fmt::Debug) -> String {
        format!("{value:?}")
    }
    fn require(ok: bool, reason: &str) -> Result {
        if ok { Ok(()) } else { Err(reason.into()) }
    }
    fn child(mut guard: RuntimeBootstrap) -> Result {
        let arguments: Vec<_> = guard.arguments().map(std::ffi::OsString::from).collect();
        let mode = arguments
            .first()
            .ok_or("missing child mode")?
            .to_string_lossy();
        if mode == "await-commit" {
            let _ = guard.await_commit(HostInstanceId([31; 16]));
            return Err("uncommitted guard unexpectedly returned to its caller".into());
        }
        if mode == "retained-await" {
            let root = std::path::PathBuf::from(arguments.get(2).ok_or("missing fixture root")?);
            let publication = root.join("endpoint.fixture");
            std::fs::write(&publication, b"published before ownership commit").map_err(error)?;
            let failure = guard.await_commit_retained(HostInstanceId([31; 16]));
            require(
                failure.is_err(),
                "uncommitted retained bootstrap returned admission",
            )?;
            // This must happen while the uncommitted guard is still alive.
            std::fs::remove_file(&publication).map_err(error)?;
            let mut marker = std::fs::File::create(root.join("cleanup.witness")).map_err(error)?;
            std::io::Write::write_all(&mut marker, b"cleanup completed before guard drop")
                .map_err(error)?;
            marker.sync_all().map_err(error)?;
            drop(guard);
            return Err("retained uncommitted guard drop returned".into());
        }
        if mode == "flood" {
            for _ in 0..12 {
                guard
                    .report_startup_failure("bounded-overflow", &"x".repeat(8192))
                    .map_err(error)?;
            }
        }
        guard
            .report_startup_failure("cold-fixture", REASON)
            .map_err(error)?;
        if mode == "live-read" {
            std::thread::sleep(Duration::from_secs(2));
        }
        drop(guard); // uncommitted native guard exits only this exact child
        Err("uncommitted guard drop returned".into())
    }
    struct Custody(Option<RuntimeChild>);
    impl Custody {
        fn child(&self) -> Result<&RuntimeChild> {
            self.0.as_ref().ok_or("missing exact child custody".into())
        }
        fn wait_exit(&self) -> Result<RuntimeExitWitness> {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match NativeProcessRuntime::witness_runtime(self.child()?).map_err(error)? {
                    RuntimeExitObservation::Exited(witness) => return Ok(*witness),
                    RuntimeExitObservation::Pending { .. } if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    _ => return Err("exact cold child failed to exit".into()),
                }
            }
        }
        fn release(&mut self, witness: &RuntimeExitWitness) -> Result {
            NativeProcessRuntime::release_runtime(
                self.0.as_mut().ok_or("missing custody")?,
                witness,
            )
            .map_err(error)?;
            self.0 = None;
            Ok(())
        }
    }
    impl Drop for Custody {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = NativeProcessRuntime::abort_runtime(child);
            }
            if self.0.is_some() {
                match self.wait_exit() {
                    Ok(witness) => {
                        if let Err(e) = self.release(&witness) {
                            eprintln!("exact fixture cleanup failed: {e}");
                        }
                    }
                    Err(e) => eprintln!("exact fixture exit remains unproved: {e}"),
                }
            }
        }
    }
    fn trial(mode: &str) -> Result {
        let root = std::env::temp_dir().join(format!(
            "se-retained-bootstrap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(error)?
                .as_nanos()
        ));
        if mode == "retained-await" {
            std::fs::create_dir(&root).map_err(error)?;
        }
        let machine = MachineId::new("persisted-cold-bootstrap-judge").map_err(error)?;
        let spec = RuntimeLaunchSpec {
            machine: machine.clone(),
            startup_nonce: [61; 16],
            executable: std::env::current_exe().map_err(error)?,
            arguments: vec![
                mode.into(),
                SECRET_SENTINEL.into(),
                root.as_os_str().to_owned(),
            ],
            environment: Environment {
                entries: vec![("JUDGE_NOT_A_CREDENTIAL".into(), SECRET_SENTINEL.into())],
            },
            deadline: Instant::now() + Duration::from_secs(3),
        };
        let mut custody = match NativeProcessRuntime::spawn_runtime(spec) {
            Ok(launch) => Custody(Some(launch.child)),
            Err(failure) => {
                let custody = Custody(failure.remaining);
                if custody.0.is_none() {
                    return Err(format!("native child was not created: {:?}", failure.error));
                }
                custody
            }
        };
        if mode == "live-read" {
            require(
                matches!(
                    NativeProcessRuntime::witness_runtime(custody.child()?).map_err(error)?,
                    RuntimeExitObservation::Pending { .. }
                ),
                "live-read child already exited",
            )?;
            let start = Instant::now();
            let partial = custody
                .child()?
                .startup_stderr(start + Duration::from_millis(100))
                .map_err(error)?;
            require(
                !partial.complete,
                "live child's stderr was falsely labeled EOF",
            )?;
            require(
                start.elapsed() < Duration::from_secs(1),
                "incomplete stderr read ignored its deadline",
            )?;
            require(
                partial.bytes.len() <= 16384,
                "incomplete capture exceeded its cap",
            )?;
        }
        let witness = custody.wait_exit()?;
        require(
            !matches!(witness.status, ExitStatus::Code(0)),
            "refused cold child exited successfully",
        )?;
        let retained = custody
            .child()?
            .startup_stderr(Instant::now() + Duration::from_secs(2))
            .map_err(error)?;
        require(
            retained.complete,
            "stderr readback did not witness actual EOF",
        )?;
        require(
            retained.failure.is_none(),
            "stderr readback retained an unexplained native read failure",
        )?;
        require(
            retained.bytes.len() <= 16384,
            "retained stderr exceeded the 16 KiB cap",
        )?;
        let text = String::from_utf8_lossy(&retained.bytes);
        require(
            !text.contains(SECRET_SENTINEL),
            "startup diagnostic dumped private frame or environment values",
        )?;
        if mode == "await-commit" || mode == "retained-await" {
            require(
                text.contains("runtime")
                    && (text.contains("deadline") || text.contains("LaunchTimedOut")),
                "await_commit lost its refusal before guard drop",
            )?;
        } else {
            require(
                text.contains("cold-fixture") && text.contains(REASON),
                "parent lost the exact cold child's public refusal",
            )?;
            require(
                retained.truncated == (mode == "flood"),
                "stderr truncation fact differs from actual bounded tail",
            )?;
        }
        require(
            !matches!(read_process(machine,witness.identity.pid).map_err(error)?, ProcessRead::Present(live) if live.identity==witness.identity && live.state!=NativeState::ExitedAwaitingReap),
            "refused cold child still executing",
        )?;
        custody.release(&witness)?;
        if mode == "retained-await" {
            require(
                !root.join("endpoint.fixture").try_exists().map_err(error)?,
                "failed bootstrap publication survived cleanup",
            )?;
            require(
                std::fs::read(root.join("cleanup.witness")).map_err(error)?
                    == b"cleanup completed before guard drop",
                "parent did not witness cleanup before guard drop",
            )?;
            std::fs::remove_file(root.join("cleanup.witness")).map_err(error)?;
            std::fs::remove_dir(root).map_err(error)?;
        }
        println!("PASS {mode}: exact exited child, bounded EOF stderr and public refusal");
        Ok(())
    }
    pub fn run() -> Result {
        if let Some(guard) = RuntimeBootstrap::from_process_entry().map_err(error)? {
            return child(guard);
        }
        if std::env::args_os().any(|arg| arg == "--retained-only") {
            trial("retained-await")?;
            println!("bootstrap_stderr retained: 1 passed, 0 failed");
            return Ok(());
        }
        for mode in [
            "refuse",
            "flood",
            "await-commit",
            "retained-await",
            "live-read",
            "refuse",
        ] {
            trial(mode)?;
        }
        println!("bootstrap_stderr: 6 passed, 0 failed");
        Ok(())
    }
}
#[cfg(any(target_os = "linux", windows))]
fn main() {
    if let Err(e) = judge::run() {
        eprintln!("FAIL bootstrap_stderr: {e}");
        std::process::exit(1);
    }
}
#[cfg(not(any(target_os = "linux", windows)))]
fn main() {
    println!("bootstrap_stderr: NOT GRADED on this platform");
}
