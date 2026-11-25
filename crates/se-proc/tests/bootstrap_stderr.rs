//! Cold real bootstrap consumers; no host, endpoint or public stdio substitute.
#[path = "support/detachment_venue.rs"]
mod detachment_venue;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod judge {
    use se_proc::*;
    use std::{
        path::Path,
        time::{Duration, Instant},
    };
    type Result<T = ()> = std::result::Result<T, String>;
    const SECRET_SENTINEL: &str = "fixture-not-a-real-secret-never-dump-frame";
    const REASON: &str = "cold child refused: fixture storage is unavailable";
    const FLOOD_CHUNKS: usize = 5;
    const FLOOD_CHUNK_BYTES: usize = 4 * 1024;

    fn flood_marker(chunk: usize) -> String {
        format!("fixture flood chunk {chunk}\n")
    }

    fn flood(guard: &mut RuntimeBootstrap, root: &Path) -> Result {
        let deadline = Instant::now() + Duration::from_secs(3);
        for chunk in 1..=FLOOD_CHUNKS {
            let filler = format!("{}\n{}", "x".repeat(FLOOD_CHUNK_BYTES), flood_marker(chunk));
            guard
                .report_startup_failure("bounded-overflow", filler.trim_end())
                .map_err(error)?;
            let ack = root.join(chunk.to_string());
            // The parent acknowledges only bytes it has read from this child.
            // This fills the retained tail while keeping the native channel drained.
            while !ack.try_exists().map_err(error)? {
                require(
                    Instant::now() < deadline,
                    "parent did not acknowledge flood bytes",
                )?;
                std::thread::sleep(Duration::from_millis(5));
            }
            std::fs::remove_file(ack).map_err(error)?;
        }
        Ok(())
    }

    fn acknowledge_flood(child: &RuntimeChild, root: &Path, deadline: Instant) -> Result {
        for chunk in 1..=FLOOD_CHUNKS {
            let marker = flood_marker(chunk);
            loop {
                let snapshot = child
                    .startup_stderr(deadline.min(Instant::now() + Duration::from_millis(25)))
                    .map_err(error)?;
                if snapshot.bytes.ends_with(marker.as_bytes()) {
                    std::fs::File::create_new(root.join(chunk.to_string())).map_err(error)?;
                    break;
                }
                if let Some(failure) = snapshot.failure {
                    return Err(format!(
                        "read stderr while awaiting flood chunk {chunk}: {failure:?}"
                    ));
                }
                if snapshot.complete || Instant::now() >= deadline {
                    return Err(format!(
                        "flood chunk {chunk} never arrived, retained {} bytes, EOF {}",
                        snapshot.bytes.len(),
                        snapshot.complete
                    ));
                }
            }
        }
        Ok(())
    }

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
        #[cfg(windows)]
        if mode == "inheritance" {
            let raw = arguments
                .get(3)
                .ok_or("missing excluded event")?
                .to_string_lossy()
                .parse::<usize>()
                .map_err(error)?;
            // from_process_entry already consumed the explicit input and auth
            // channels and validated the inherited parent. The normal refusal
            // below positively witnesses the child's explicit diagnostic handle.
            // SAFETY: SetEvent validates a possibly absent native handle.
            unsafe {
                windows_sys::Win32::System::Threading::SetEvent(raw as _);
            }
        }
        #[cfg(windows)]
        if mode == "broker" {
            use windows_sys::Win32::System::{
                JobObjects::IsProcessInJob, Threading::GetCurrentProcess,
            };
            let mut member = 1;
            // SAFETY: current-process query and writable BOOL; null tests every job.
            require(
                // SAFETY: retained process reference and writable native membership output.
                unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut member) }
                    != 0
                    && member == 0,
                "broker child still belongs to a Windows job",
            )?;
            std::thread::sleep(Duration::from_millis(500));
        }
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
            let root = arguments.get(2).ok_or("missing flood fixture root")?;
            flood(&mut guard, Path::new(root))?;
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
    /// Returns true only when the trial actually ran. A venue that cannot
    /// launch the detached child returns false, so no caller can report a pass
    /// that did not happen.
    fn trial(mode: &str) -> Result<bool> {
        // Every trial launches a detached native child, so a venue that forbids
        // breakaway cannot run any of them. Name the exact case instead of
        // failing on its precondition; the caller counts what actually ran.
        #[cfg(windows)]
        if crate::detachment_venue::hosted_runner_without_breakaway() {
            println!(
                "NOT RUN bootstrap_stderr::{mode}: {}",
                crate::detachment_venue::HOSTED_REASON
            );
            return Ok(false);
        }
        let root = fixture_root(mode)?;
        let machine = MachineId::new("persisted-cold-bootstrap-judge").map_err(error)?;
        #[cfg(windows)]
        let excluded = inheritable_event(mode)?;
        #[allow(unused_mut)]
        let mut arguments = vec![
            mode.into(),
            SECRET_SENTINEL.into(),
            root.as_os_str().to_owned(),
        ];
        #[cfg(windows)]
        if let Some(event) = &excluded {
            use std::os::windows::io::AsRawHandle;
            arguments.push((event.as_raw_handle() as usize).to_string().into());
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        let spec = RuntimeLaunchSpec {
            machine: machine.clone(),
            startup_nonce: [61; 16],
            executable: std::env::current_exe().map_err(error)?,
            arguments,
            environment: Environment {
                entries: vec![("JUDGE_NOT_A_CREDENTIAL".into(), SECRET_SENTINEL.into())],
            },
            deadline,
        };
        #[cfg(windows)]
        let mut observed_detachment = None;
        let mut custody = match NativeProcessRuntime::spawn_runtime(spec) {
            Ok(launch) => {
                #[cfg(windows)]
                {
                    observed_detachment = Some(launch.detachment);
                }
                Custody(Some(launch.child))
            }
            Err(failure) => {
                let custody = Custody(failure.remaining);
                if custody.0.is_none() {
                    return Err(format!("native child was not created: {:?}", failure.error));
                }
                custody
            }
        };
        #[cfg(windows)]
        if mode == "broker" {
            broker_child_is_outside_any_job(&custody, observed_detachment)?;
        }
        if mode == "live-read" {
            live_read_is_bounded(&custody)?;
        }
        if mode == "flood" {
            acknowledge_flood(custody.child()?, &root, deadline)?;
        }
        let witness = custody.wait_exit()?;
        require(
            !matches!(witness.status, ExitStatus::Code(0)),
            "refused cold child exited successfully",
        )?;
        retained_stderr_is_honest(mode, &custody, machine, &witness)?;
        custody.release(&witness)?;
        #[cfg(windows)]
        if let Some(event) = excluded {
            event_was_not_inherited(&event)?;
        }
        if mode == "retained-await" {
            retained_cleanup_was_witnessed(&root)?;
        }
        if matches!(mode, "retained-await" | "flood") {
            std::fs::remove_dir(root).map_err(error)?;
        }
        println!("PASS {mode}: exact exited child, bounded EOF stderr and public refusal");
        Ok(true)
    }

    fn fixture_root(mode: &str) -> Result<std::path::PathBuf> {
        let root = std::env::temp_dir().join(format!(
            "se-retained-bootstrap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(error)?
                .as_nanos()
        ));
        if matches!(mode, "retained-await" | "flood") {
            std::fs::create_dir(&root).map_err(error)?;
            eprintln!(
                "bootstrap fixture retained on failed or interrupted closure: {}",
                root.display()
            );
        }
        Ok(root)
    }

    #[cfg(windows)]
    fn inheritable_event(mode: &str) -> Result<Option<std::os::windows::io::OwnedHandle>> {
        let excluded = if mode == "inheritance" {
            use std::{mem::size_of, os::windows::io::FromRawHandle};
            use windows_sys::Win32::{
                Security::SECURITY_ATTRIBUTES, System::Threading::CreateEventW,
            };
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: std::ptr::null_mut(),
                bInheritHandle: 1,
            };
            // SAFETY: creates an unnamed owned event with inheritance explicitly enabled.
            let raw = unsafe { CreateEventW(&attributes, 1, 0, std::ptr::null()) };
            if raw.is_null() {
                return Err(error(std::io::Error::last_os_error()));
            }
            // SAFETY: successful event creation transferred unique ownership.
            Some(unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) })
        } else {
            None
        };
        Ok(excluded)
    }

    #[cfg(windows)]
    fn broker_child_is_outside_any_job(
        custody: &Custody,
        observed_detachment: Option<RuntimeDetachment>,
    ) -> Result {
        require(
            observed_detachment == Some(RuntimeDetachment::WindowsBroker),
            "strict job did not use the broker path",
        )?;
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::System::{JobObjects::IsProcessInJob, Threading::*};
        let identity = custody
            .child()?
            .identity()
            .ok_or("broker child identity missing")?;
        // SAFETY: read-only open of the exact child PID; retained custody pins that birth.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, identity.pid.0) };
        require(!raw.is_null(), "outside broker child observation failed")?;
        // SAFETY: successful native open transfers one owned reference.
        let observed = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut member = 1;
        // SAFETY: retained exact child reference and writable BOOL.
        require(
            // SAFETY: retained process reference and writable native membership output.
            unsafe { IsProcessInJob(observed.as_raw_handle(), std::ptr::null_mut(), &mut member) }
                != 0
                && member == 0,
            "outside observer found the detached child in a job",
        )?;
        Ok(())
    }

    fn live_read_is_bounded(custody: &Custody) -> Result {
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
        Ok(())
    }

    fn retained_stderr_is_honest(
        mode: &str,
        custody: &Custody,
        machine: MachineId,
        witness: &RuntimeExitWitness,
    ) -> Result {
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
        Ok(())
    }

    #[cfg(windows)]
    fn event_was_not_inherited(event: &std::os::windows::io::OwnedHandle) -> Result {
        use std::os::windows::io::AsRawHandle;
        // Observe the original object, not whether its raw number happens to
        // name another child handle. No child report can substitute for this.
        // SAFETY: retained parent event and zero-time native observation.
        let state = unsafe {
            windows_sys::Win32::System::Threading::WaitForSingleObject(event.as_raw_handle(), 0)
        };
        require(
            state == windows_sys::Win32::Foundation::WAIT_TIMEOUT,
            "bootstrap leaked an unlisted inheritable event",
        )?;
        Ok(())
    }

    fn retained_cleanup_was_witnessed(root: &Path) -> Result {
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
        Ok(())
    }
    #[cfg(windows)]
    fn strict_job() -> Result {
        use std::{
            mem::{size_of, zeroed},
            os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        };
        use windows_sys::Win32::System::{JobObjects::*, Threading::GetCurrentProcess};
        // SAFETY: creates a new unnamed noninheritable job owned only by this fixture.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        require(!raw.is_null(), "strict fixture job creation failed")?;
        // SAFETY: successful native creation transfers one owned reference.
        let job = unsafe { OwnedHandle::from_raw_handle(raw) };
        // SAFETY: native POD job information with no limits or breakaway flags enabled.
        let limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        // SAFETY: retained private job and exact read-only native structure size.
        require(
            // SAFETY: retained private job and exact native limit structure.
            unsafe {
                SetInformationJobObject(
                    job.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } != 0,
            "strict fixture job configuration failed",
        )?;
        // SAFETY: assign only this dedicated fixture caller, never the test driver or another process.
        require(
            // SAFETY: assigns only this dedicated fixture caller to its owned job.
            unsafe { AssignProcessToJobObject(job.as_raw_handle(), GetCurrentProcess()) } != 0,
            "strict fixture job admission failed",
        )?;
        let mut member = 0;
        // SAFETY: exact private job and current-process query.
        require(
            // SAFETY: retained private job and current-process query with writable BOOL.
            unsafe { IsProcessInJob(GetCurrentProcess(), job.as_raw_handle(), &mut member) } != 0
                && member != 0,
            "strict fixture caller was not in its job",
        )?;
        // The caller's own job membership is checked either way; only the
        // detached child is venue-dependent.
        let ran_broker = if crate::detachment_venue::hosted_runner_without_breakaway() {
            // Keep the check compiled and say plainly that this venue could not
            // supply its precondition; never report a pass it did not achieve.
            println!(
                "bootstrap_stderr: NOT RUN broker detached-launch case: {}",
                crate::detachment_venue::HOSTED_REASON
            );
            false
        } else {
            trial("broker")?
        };
        // SAFETY: same retained caller/job after the detached child has exited.
        require(
            // SAFETY: retained private job and current-process query with writable BOOL.
            unsafe { IsProcessInJob(GetCurrentProcess(), job.as_raw_handle(), &mut member) } != 0
                && member != 0,
            "launch changed the caller's job membership",
        )?;
        // Only the executed subset is claimed; a skipped case is not a pass.
        if ran_broker {
            println!(
                "bootstrap broker: 1 passed, 0 failed; caller remains in strict job; child outside all jobs and exited"
            );
        } else {
            println!(
                "bootstrap broker: 0 passed, 0 failed, 1 not run on this venue; caller remains in strict job"
            );
        }
        Ok(())
    }
    pub fn run() -> Result {
        if let Some(guard) = RuntimeBootstrap::from_process_entry().map_err(error)? {
            return child(guard);
        }
        #[cfg(windows)]
        if std::env::args_os().any(|arg| arg == "--strict-job") {
            return strict_job();
        }
        #[cfg(windows)]
        {
            let output = std::process::Command::new(std::env::current_exe().map_err(error)?)
                .arg("--strict-job")
                .output()
                .map_err(error)?;
            require(
                output.status.success(),
                &format!(
                    "strict-job consumer failed: {}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ),
            )?;
            print!("{}", String::from_utf8_lossy(&output.stdout));
        }
        if std::env::args_os().any(|arg| arg == "--retained-only") {
            let ran = trial("retained-await")?;
            if ran {
                println!("bootstrap_stderr retained: 1 passed, 0 failed");
            } else {
                println!("bootstrap_stderr retained: 0 passed, 0 failed, 1 not run on this venue");
            }
            return Ok(());
        }
        let mut ordinary = 0;
        for mode in [
            "refuse",
            "flood",
            "await-commit",
            "retained-await",
            "live-read",
            "refuse",
        ] {
            if trial(mode)? {
                ordinary += 1;
            }
        }
        #[cfg(windows)]
        {
            let inheritance = trial("inheritance")?;
            let ran = ordinary + usize::from(inheritance);
            // Count only what this venue executed; a skipped trial is not a pass.
            if ran == 7 {
                println!("bootstrap_stderr: 7 passed, 0 failed");
            } else {
                println!(
                    "bootstrap_stderr: {ran} passed, 0 failed, {} not run on this venue",
                    7 - ran
                );
            }
        }
        #[cfg(not(windows))]
        {
            // Six ordinary trials on this platform; a venue that skips one says
            // so rather than reporting a pass it did not achieve.
            let expected = 6;
            if ordinary == expected {
                println!("bootstrap_stderr: {ordinary} passed, 0 failed");
            } else {
                println!(
                    "bootstrap_stderr: {ordinary} passed, 0 failed, {} not run on this venue",
                    expected - ordinary
                );
            }
        }
        Ok(())
    }
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn main() {
    if std::env::args().any(|v| v == "--list") {
        if !std::env::args().any(|v| v == "--ignored") {
            println!("bootstrap_stderr: test");
        }
        return;
    }
    if let Err(e) = judge::run() {
        eprintln!("FAIL bootstrap_stderr: {e}");
        std::process::exit(1);
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn main() {
    if std::env::args().any(|v| v == "--list") {
        if !std::env::args().any(|v| v == "--ignored") {
            println!("bootstrap_stderr: test");
        }
        return;
    }
    println!("bootstrap_stderr: NOT GRADED on this platform");
}
