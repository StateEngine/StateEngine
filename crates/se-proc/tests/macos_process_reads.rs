//! Darwin observations checked against native facts outside the product reader.
//! This fixture grants no launch or signal authority and needs no provider account.
#[cfg(target_os = "macos")]
mod macos {
    use se_proc::{
        BootIdentity, MachineId, NativeProcessRuntime, NativeState, ProcErrorCode, ProcessId,
        ProcessIdentity, ProcessRead, StartIdentity, observe_process_birth, read_process,
        read_process_until,
    };
    use std::{
        ffi::OsString,
        io::{BufRead, Write},
        mem::{size_of, zeroed},
        os::unix::ffi::OsStringExt,
        process::{Child, Command, Stdio},
        time::{Duration, Instant, SystemTime},
    };
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    fn machine() -> MachineId {
        MachineId::new("darwin-reader-fixture").unwrap_or_else(|e| panic!("fixture machine: {e}"))
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn bsd(pid: u32) -> Result<libc::proc_bsdinfo> {
        // SAFETY: the native POD output is aligned and its full size is supplied.
        let mut value: libc::proc_bsdinfo = unsafe { zeroed() };
        let size = i32::try_from(size_of::<libc::proc_bsdinfo>())?;
        // SAFETY: only our retained positive child PID is selected, with writable output.
        let count = unsafe {
            libc::proc_pidinfo(
                i32::try_from(pid)?,
                libc::PROC_PIDTBSDINFO,
                // Darwin searches the zombie table only when this argument is nonzero.
                1,
                (&mut value as *mut libc::proc_bsdinfo).cast(),
                size,
            )
        };
        if count != size {
            return Err(format!(
                "outside BSD read: {count}/{size}: {}",
                std::io::Error::last_os_error()
            )
            .into());
        }
        assert_eq!(value.pbi_pid, pid);
        Ok(value)
    }
    fn outside(pid: u32) -> Result<ProcessIdentity> {
        let before = bsd(pid)?;
        let mut bytes = vec![0_u8; 4096];
        // SAFETY: retained native PID and bounded writable path storage.
        let count = unsafe {
            libc::proc_pidpath(
                i32::try_from(pid)?,
                bytes.as_mut_ptr().cast(),
                bytes.len() as u32,
            )
        };
        assert!(count > 0 && (count as usize) < bytes.len());
        bytes.truncate(
            bytes
                .iter()
                .position(|b| *b == 0)
                .ok_or("outside path lacks terminator")?,
        );
        let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
        // SAFETY: native POD output; sysctl fills the exact writable timeval size.
        let mut boot: libc::timeval = unsafe { zeroed() };
        let mut length = size_of::<libc::timeval>();
        assert_eq!(
            // SAFETY: read-only kernel MIB, correctly sized aligned output, no input buffer.
            unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    2,
                    (&mut boot as *mut libc::timeval).cast(),
                    &mut length,
                    std::ptr::null_mut(),
                    0,
                )
            },
            0
        );
        assert_eq!(length, size_of::<libc::timeval>());
        let after = bsd(pid)?;
        assert_eq!(
            (before.pbi_start_tvsec, before.pbi_start_tvusec),
            (after.pbi_start_tvsec, after.pbi_start_tvusec)
        );
        Ok(ProcessIdentity {
            machine: machine(),
            boot: BootIdentity::MacOs {
                seconds: boot.tv_sec,
                microseconds: boot.tv_usec,
            },
            pid: ProcessId(pid),
            start: StartIdentity::MacOs {
                seconds: before.pbi_start_tvsec,
                microseconds: u32::try_from(before.pbi_start_tvusec)?,
            },
            image: OsString::from_vec(bytes).into(),
        })
    }
    struct Held(Child);
    impl Held {
        fn start() -> Result<Self> {
            let mut child = Self(
                Command::new(std::env::current_exe()?)
                    .args([
                        "--exact",
                        "macos::owned_reader_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()?,
            );
            let mut output =
                std::io::BufReader::new(child.0.stdout.take().ok_or("child output missing")?);
            let mut line = String::new();
            loop {
                if output.read_line(&mut line)? == 0 {
                    return Err("child exited before readiness".into());
                }
                if line.contains("DARWIN-READER-READY") {
                    break;
                }
                line.clear();
            }
            // Retain the reader until reap: libtest writes its final report
            // after readiness, and a closed pipe would manufacture an exit failure.
            child.0.stdout = Some(output.into_inner());
            Ok(child)
        }
        fn pid(&self) -> ProcessId {
            ProcessId(self.0.id())
        }
        fn release(&mut self) {
            drop(self.0.stdin.take());
        }
    }
    impl Drop for Held {
        fn drop(&mut self) {
            self.release();
            if let Err(error) = self.0.wait() {
                eprintln!("join exact owned reader child: {error}");
            }
        }
    }
    #[test]
    #[ignore = "private pipe-held child, invoked only by the independent reader tests"]
    fn owned_reader_child() -> Result {
        println!("DARWIN-READER-READY");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        Ok(())
    }
    #[test]
    fn live_process_matches_native_birth_boot_image_parent_and_state() -> Result {
        let child = Held::start()?;
        let expected = outside(child.pid().0)?;
        let before = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos();
        let ProcessRead::Present(actual) =
            read_process(machine(), child.pid()).map_err(|e| format!("{e:?}"))?
        else {
            return Err("held child reported non-live".into());
        };
        let after = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)?
            .as_nanos();
        assert_eq!(actual.identity, expected);
        assert_eq!(actual.parent, Some(ProcessId(std::process::id())));
        assert_eq!(actual.state, NativeState::Running);
        assert!((before..=after).contains(&actual.observed_at_unix_ns));
        assert!(actual.identity.image.is_absolute());
        Ok(())
    }
    #[test]
    fn bounded_and_runtime_entrypoints_read_the_same_native_instance() -> Result {
        let child = Held::start()?;
        let expected = outside(child.pid().0)?;
        for value in [
            read_process_until(machine(), child.pid(), deadline()),
            NativeProcessRuntime::read_process(machine(), child.pid()),
            NativeProcessRuntime::read_process_until(machine(), child.pid(), deadline()),
        ] {
            let ProcessRead::Present(actual) = value.map_err(|e| format!("{e:?}"))? else {
                return Err("reader mirror lost live child".into());
            };
            assert_eq!(actual.identity, expected);
        }
        Ok(())
    }
    #[test]
    fn zero_and_overflow_pids_refuse_instead_of_selecting_self_or_absence() {
        for pid in [ProcessId(0), ProcessId(u32::MAX)] {
            for reply in [
                read_process(machine(), pid),
                read_process_until(machine(), pid, deadline()),
            ] {
                assert_eq!(
                    reply.err().map(|e| e.code),
                    Some(ProcErrorCode::InvalidInput)
                );
            }
        }
    }
    #[test]
    fn elapsed_original_deadline_refuses_even_for_a_readable_process() -> Result {
        let child = Held::start()?;
        for reply in [
            read_process_until(machine(), child.pid(), Instant::now()),
            NativeProcessRuntime::read_process_until(machine(), child.pid(), Instant::now()),
        ] {
            assert!(reply.is_err(), "expired bound was silently renewed");
        }
        Ok(())
    }
    #[test]
    fn unreaped_native_zombie_keeps_birth_and_is_not_absent_or_running() -> Result {
        let mut child = Held::start()?;
        let expected = outside(child.pid().0)?;
        child.release();
        let bound = deadline();
        while bsd(child.pid().0)?.pbi_status != libc::SZOMB {
            assert!(
                Instant::now() < bound,
                "owned child did not reach native zombie"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        for reply in [
            read_process(machine(), child.pid()),
            read_process_until(machine(), child.pid(), deadline()),
        ] {
            match reply.map_err(|e| format!("{e:?}"))? {
                ProcessRead::ExitedRecord {
                    pid,
                    boot,
                    start,
                    state: NativeState::ExitedAwaitingReap,
                    ..
                } => {
                    assert_eq!(pid, expected.pid);
                    assert_eq!(boot, expected.boot);
                    assert_eq!(start, expected.start);
                }
                other => return Err(format!("native zombie was misclassified: {other:?}").into()),
            }
        }
        assert!(child.0.wait()?.success());
        Ok(())
    }
    #[test]
    fn reaped_child_is_absent_without_inventing_a_zero_identity() -> Result {
        let mut child = Held::start()?;
        child.release();
        assert!(child.0.wait()?.success());
        for reply in [
            read_process(machine(), child.pid()),
            read_process_until(machine(), child.pid(), deadline()),
        ] {
            match reply.map_err(|e| format!("{e:?}"))? {
                ProcessRead::Absent {
                    pid,
                    observed_at_unix_ns,
                } => {
                    assert_eq!(pid, child.pid());
                    assert!(observed_at_unix_ns > 0);
                }
                other => return Err(format!("reaped child was not absent: {other:?}").into()),
            }
        }
        Ok(())
    }
    #[test]
    fn birth_conversion_matches_native_time_and_rejects_changed_identity() -> Result {
        let child = Held::start()?;
        let expected = outside(child.pid().0)?;
        let StartIdentity::MacOs {
            seconds,
            microseconds,
        } = expected.start
        else {
            return Err("outside birth is not Darwin".into());
        };
        let birth = observe_process_birth(&expected, deadline()).map_err(|e| format!("{e:?}"))?;
        assert_eq!(
            birth.unix_micros(),
            i64::try_from(seconds)? * 1_000_000 + i64::from(microseconds)
        );
        assert_eq!(birth.precision(), Duration::from_micros(1));
        let mut wrong = expected.clone();
        wrong.start = StartIdentity::MacOs {
            seconds: seconds + 1,
            microseconds,
        };
        let mut wrong_image = expected.clone();
        wrong_image.image.set_file_name("unowned-reader-image");
        let mut wrong_boot = expected.clone();
        wrong_boot.boot = BootIdentity::Linux { boot_id: [0; 16] };
        for identity in [wrong, wrong_image, wrong_boot] {
            assert_eq!(
                observe_process_birth(&identity, deadline())
                    .err()
                    .map(|e| e.code),
                Some(ProcErrorCode::IdentityChanged)
            );
        }
        assert!(observe_process_birth(&expected, Instant::now()).is_err());
        Ok(())
    }
}
