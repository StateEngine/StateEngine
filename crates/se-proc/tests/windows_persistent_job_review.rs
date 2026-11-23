//! Protects: a persistent Windows job outlives the host that created it, a
//! successor host re-adopts the exact live root cold, and a vanished persistent
//! job name is unproved rather than an empty scope.
//! Native Windows execution is required; a cross-check supplies no runtime grade.
#![cfg(windows)]
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
use se_proc::*;
use std::{
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ROOT_ENV: &str = "PERSISTENT_JOB_JUDGE_ROOT";
const MACHINE: &str = "windows-persistent-job-judge";

fn proc_error(error: ProcError) -> String {
    format!("{error:?}")
}
struct Notices;
impl ExitSink for Notices {
    fn notify(&self, _: ExitNotice) {}
}
struct Home(cleanup_directory::PrivateDirectory);
impl Home {
    fn new() -> Check<Self> {
        se_proc::initialize_file_creation_owner()?;
        let path = cleanup_directory::private_case_directory()?;
        drop(NativeStateFiles::create(&path)?);
        Ok(Self(path.cleanup_on_drop()))
    }
}
fn instance() -> Check<HostInstanceId> {
    Ok(HostInstanceId(random_secret()?.expose()[..16].try_into()?))
}
fn runtime(instance: HostInstanceId) -> Check<NativeProcessRuntime> {
    Ok(NativeProcessRuntime::open(HostConfig {
        machine: MachineId::new(MACHINE)?,
        instance,
        helper_executable: std::env::current_exe()?,
        linux_delegation: LinuxDelegation::CurrentScope,
        limits: ResourceLimits {
            max_lifecycles: 1,
            max_diagnostic_members: 4,
            max_observation_bytes: 65536,
            max_stdio_buffer_bytes: 4096,
        },
    })
    .map_err(proc_error)?)
}
fn ignored_test(name: &str) -> Vec<std::ffi::OsString> {
    [
        "--exact",
        name,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]
    .into_iter()
    .map(Into::into)
    .collect()
}

/// Releases the surviving root even when an assertion fails first.
struct Release(PathBuf);
impl Drop for Release {
    fn drop(&mut self) {
        let _ = fs::write(&self.0, b"release");
    }
}

/// An adopted scope this test must finish: witness its exit and release it,
/// or stop it through the successor's own job authority.
struct Adopted<'a> {
    runtime: &'a NativeProcessRuntime,
    process: OwnedProcess,
    generation: GenerationId,
    released: bool,
}
impl Adopted<'_> {
    fn wait_exit(&mut self) -> Check<StopWitness> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self
                .runtime
                .witness_exit(&self.process)
                .map_err(proc_error)?
            {
                StopObservation::Complete(witness) => {
                    self.runtime
                        .release(&self.process, &witness)
                        .map_err(proc_error)?;
                    self.released = true;
                    return Ok(*witness);
                }
                _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                _ => return Err("re-adopted persistent root did not exit".into()),
            }
        }
    }
}
impl Drop for Adopted<'_> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let cleanup = (|| -> Check {
            let stop = self
                .runtime
                .prepare_stop(
                    &self.process,
                    self.generation,
                    Instant::now() + Duration::from_secs(5),
                )
                .map_err(proc_error)?;
            self.runtime
                .request_stop(stop)
                .map_err(proc_error)?
                .dispatch
                .map_err(proc_error)?;
            self.wait_exit()?;
            Ok(())
        })();
        if let Err(error) = cleanup {
            eprintln!("re-adopted persistent scope cleanup failed: {error}");
        }
    }
}

/// The host side: launch one persistent root, publish its record, then leave
/// without stopping it, as a crashed or upgraded host would.
#[test]
#[ignore = "Explicitly spawned as the departing host by the persistent re-adoption judge"]
fn persistent_job_departing_host() -> Check {
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).ok_or("judge root absent")?);
    let executable = std::env::current_exe()?;
    let host = instance()?;
    let runtime = runtime(host)?;
    let owner = current_process_identity(MachineId::new(MACHINE)?).map_err(proc_error)?;
    let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
    let generation = GenerationId::new(1)?;
    let spec = LaunchSpec {
        executable_custody: None,
        lifecycle: lifecycle.clone(),
        generation,
        executable,
        arguments: ignored_test("persistent_job_surviving_root"),
        cwd: root.clone(),
        environment: Environment {
            entries: vec![(ROOT_ENV.into(), root.as_os_str().to_owned())],
        },
        stdio: StandardIo {
            stdin: Some(File::open(root.join("stdin"))?),
            stdout: Some(File::create(root.join("root-stdout"))?),
            stderr: Some(File::create(root.join("root-stderr"))?),
        },
        mode: LaunchMode::HeadlessPersistent,
        window: None,
        policy: LaunchPolicy {
            containment: ContainmentRequirement::KernelScope,
            writes: WritePolicy::Workspace {
                roots: vec![root.clone()],
                scratch: root.clone(),
            },
            network: NetworkPolicy::Allow,
            hardening: OptionalHardening::Off,
        },
        deadline: Instant::now() + Duration::from_secs(15),
        notifications: Arc::new(Notices),
    };
    let prepared = runtime
        .prepare_launch(
            LaunchReservation {
                format_version: 1,
                lifecycle,
                host,
                owner,
                generation,
                scope_nonce: nonce,
                parent: ReservationParent::Windows,
                created_at_unix_ns: 1,
            },
            spec,
        )
        .map_err(proc_error)?;
    let ticket = match runtime.begin_launch(prepared.prepared) {
        LaunchStart::Pending { ticket, .. } => ticket,
        LaunchStart::Failed(failure) => {
            return Err(format!("native creation failed: {:?}", failure.error).into());
        }
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    let record = loop {
        match runtime.poll_launch(&ticket).map_err(proc_error)? {
            LaunchProgress::Started(success) => break success.record,
            LaunchProgress::Pending if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5))
            }
            LaunchProgress::Failed(failure) => {
                return Err(format!("native launch failed: {:?}", failure.error).into());
            }
            _ => return Err("persistent launch did not publish its record".into()),
        }
    };
    let staged = root.join("record.staged");
    fs::write(&staged, serde_json::to_vec(&record)?)?;
    fs::rename(&staged, root.join("record.json"))?;
    // Leave without destructors: no stop, release or orderly handle teardown.
    std::process::exit(0)
}

/// The persistent root: stay alive until the judge releases it.
#[test]
#[ignore = "Explicitly launched inside the persistent job by the departing host"]
fn persistent_job_surviving_root() -> Check {
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).ok_or("judge root absent")?);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !root.join("release").exists() {
        if Instant::now() >= deadline {
            return Err("persistent root was never released".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

fn departing_host(home: &Path) -> Check<ProcessRecord> {
    fs::write(home.join("stdin"), b"")?;
    let output = Command::new(std::env::current_exe()?)
        .args(ignored_test("persistent_job_departing_host"))
        .env(ROOT_ENV, home)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "departing host failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&fs::read(
        home.join("record.json"),
    )?)?)
}

#[test]
fn a_persistent_root_survives_its_host_and_is_readopted_cold() -> Check {
    let home = Home::new()?;
    let _release = Release(home.0.join("release"));
    let record = departing_host(&home.0)?;
    let ScopeIdentity::WindowsJob {
        host: first_host,
        name,
        persistent: true,
    } = record.scope.clone()
    else {
        return Err(format!(
            "Codex-style launch lost its persistent job: {:?}",
            record.scope
        )
        .into());
    };
    assert_eq!(first_host, record.host);

    let successor = instance()?;
    let runtime = runtime(successor)?;
    let plan = runtime
        .plan_recovery(RecoverySource::Record(Box::new(record.clone())))
        .map_err(proc_error)?;
    assert_eq!(plan.disposition, RecoveryDisposition::ReattachWindowsJob);
    let generation = GenerationId::new(2)?;
    let (process, adopted) = match runtime.recover(plan, generation).map_err(proc_error)? {
        RecoveryOutcome::Recovered { process, record } => (process, *record),
        RecoveryOutcome::Exited(witness) => {
            return Err(format!("live persistent root reported exited: {witness:?}").into());
        }
        RecoveryOutcome::Unproved { error, .. } => {
            return Err(format!("live persistent root was not re-adopted: {error:?}").into());
        }
        _ => return Err("unexpected persistent recovery outcome".into()),
    };
    let mut adopted_scope = Adopted {
        runtime: &runtime,
        process,
        generation,
        released: false,
    };
    assert_eq!(adopted.root, record.root, "a different root was adopted");
    assert_eq!(adopted.host, successor);
    assert_eq!(
        adopted.scope,
        ScopeIdentity::WindowsJob {
            host: successor,
            name,
            persistent: true,
        },
        "scope must move to the successor host and keep its persistent name"
    );
    assert_eq!(adopted.owner.pid, ProcessId(std::process::id()));
    assert_eq!(adopted.generation, generation);
    assert_eq!(adopted.lifecycle, record.lifecycle);

    fs::write(home.0.join("release"), b"release")?;
    let witness = adopted_scope.wait_exit()?;
    assert!(
        matches!(
            witness.root,
            RootWitness::Identified {
                status: ExitStatus::Code(0),
                ..
            }
        ),
        "re-adopted root exit was not witnessed: {:?}\n{}",
        witness.root,
        fs::read_to_string(home.0.join("root-stderr")).unwrap_or_default()
    );
    assert_eq!(witness.scope_exit.remaining.population, Population::Empty);
    Ok(())
}

/// An absent pid and a never-created job name: the old host and root are
/// provably gone and the name resolves to nothing.
fn vanished(persistent: bool) -> Check<ProcessRecord> {
    let host = instance()?;
    let gone = ProcessIdentity {
        machine: MachineId::new(MACHINE)?,
        boot: BootIdentity::WindowsAbsoluteCreationClock,
        start: StartIdentity::Windows {
            creation_filetime: 1,
        },
        pid: ProcessId(u32::MAX - 3),
        image: std::env::current_exe()?,
    };
    let suffix: String = host.0.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(ProcessRecord {
        macos_boot_session: None,
        format_version: 1,
        lifecycle: LifecycleId::from_parts(1_700_000_000_000, host.0[..10].try_into()?)?,
        host,
        owner: gone.clone(),
        generation: GenerationId::new(1)?,
        root: gone,
        scope: ScopeIdentity::WindowsJob {
            host,
            name: format!(r"Local\SE-vanished-judge-{suffix}"),
            persistent,
        },
        tracked_obligations: None,
        guarantee: ContainmentGuarantee::KernelScope {
            explicit_breakaway: true,
        },
        entry: EntryMethod::WindowsJobList,
        state: LifecycleState::Running,
        ownership_release: None,
        exit_status: None,
        observed_at_unix_ns: 2,
        argv_sha256: [4; 32],
    })
}

/// Without kill-on-close the name disappears with its last handle while an
/// unanchored descendant may still run, so absence cannot prove empty. A
/// kill-on-close job keeps its query-only exit proof.
#[test]
fn a_vanished_persistent_job_name_is_unproved_not_empty() -> Check {
    let runtime = runtime(instance()?)?;
    let generation = GenerationId::new(2)?;

    let plan = runtime
        .plan_recovery(RecoverySource::Record(Box::new(vanished(true)?)))
        .map_err(proc_error)?;
    assert_eq!(plan.disposition, RecoveryDisposition::ReattachWindowsJob);
    match runtime.recover(plan, generation).map_err(proc_error)? {
        RecoveryOutcome::Unproved { error, .. } => {
            assert_eq!(error.code, ProcErrorCode::RecoveryUnproved, "{error:?}");
            let ProcErrorDetail::Input { reason, .. } = error.detail.as_ref() else {
                return Err(format!("refusal lost its reason: {error:?}").into());
            };
            assert!(
                reason.contains("absent") && reason.contains("before retrying"),
                "refusal must name the cause and a working step: {reason}"
            );
        }
        RecoveryOutcome::Exited(witness) => {
            return Err(format!("vanished persistent job reported empty: {witness:?}").into());
        }
        _ => return Err("unexpected outcome for a vanished persistent job".into()),
    }

    let plan = runtime
        .plan_recovery(RecoverySource::Record(Box::new(vanished(false)?)))
        .map_err(proc_error)?;
    assert_eq!(
        plan.disposition,
        RecoveryDisposition::VerifyExitedThenResume
    );
    match runtime.recover(plan, generation).map_err(proc_error)? {
        RecoveryOutcome::Exited(witness) => {
            assert_eq!(witness.scope_exit.remaining.population, Population::Empty);
        }
        RecoveryOutcome::Unproved { error, .. } => {
            return Err(format!("kill-on-close exit proof regressed: {error:?}").into());
        }
        _ => return Err("unexpected outcome for a vanished kill-on-close job".into()),
    }
    assert!(
        runtime
            .arena_snapshot()
            .map_err(proc_error)?
            .entries
            .is_empty(),
        "an unproved recovery retained an arena entry"
    );
    Ok(())
}
