//! Retained-owned-process policy controls, not the free-PID reader.
//! The private hook injects only observation results; real owned children,
//! original references, native exit witnesses and cleanup remain in use.
use super::*;
use crate::windows_policy_fixture::{Check, ChildPlan, Home, child_args};
use std::{
    cell::RefCell,
    fs::{self, File},
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

type Sampler = dyn FnMut(&NativeProcessRuntime, &OwnedProcess) -> ProcResult<OwnedObservation>;
thread_local! {
    static SAMPLE: RefCell<Option<Box<Sampler>>> = RefCell::new(None);
}
pub(super) fn sample(
    runtime: &NativeProcessRuntime,
    process: &OwnedProcess,
) -> ProcResult<OwnedObservation> {
    SAMPLE.with(|slot| match slot.borrow_mut().as_mut() {
        Some(sample) => sample(runtime, process),
        None => runtime.observe(process),
    })
}
struct Hook;
impl Hook {
    fn install(
        sample: impl FnMut(&NativeProcessRuntime, &OwnedProcess) -> ProcResult<OwnedObservation>
        + 'static,
    ) -> Self {
        SAMPLE.with(|slot| assert!(slot.borrow_mut().replace(Box::new(sample)).is_none()));
        Self
    }
}
impl Drop for Hook {
    fn drop(&mut self) {
        SAMPLE.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}
fn denied(api: &str, code: i64) -> ProcError {
    ProcError {
        code: ProcErrorCode::IdentityUnreadable,
        detail: Box::new(ProcErrorDetail::Input {
            field: "native operation".into(),
            reason: api.into(),
        }),
        native: Some(NativeFailure {
            api: api.into(),
            code: Some(code),
            reason: "synthetic native refusal".into(),
        }),
    }
}
fn cause(error: ProcError) -> String {
    format!("{error:?}")
}
struct Notices;
impl ExitSink for Notices {
    fn notify(&self, _: ExitNotice) {}
}
struct Fixture {
    runtime: NativeProcessRuntime,
    process: OwnedProcess,
    record: Option<ProcessRecord>,
    generation: GenerationId,
    home: Home,
    released: bool,
}
impl Fixture {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    fn new() -> Check<Self> {
        let home = Home::new()?;
        let machine = MachineId::new("owned-observation-fixture")?;
        let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
        let instance = HostInstanceId(nonce);
        let generation = GenerationId::new(1)?;
        let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
        let executable = std::env::current_exe()?;
        let runtime = NativeProcessRuntime::open(HostConfig {
            machine: machine.clone(),
            instance,
            helper_executable: executable.clone(),
            linux_delegation: LinuxDelegation::CurrentScope,
            limits: ResourceLimits {
                max_lifecycles: 1,
                max_diagnostic_members: 4,
                max_observation_bytes: 65536,
                max_stdio_buffer_bytes: 4096,
            },
        })
        .map_err(cause)?;
        let owner = runtime.inner.owner.clone();
        let plan = ChildPlan {
            report: home.0.join("ready"),
            excluded: 0,
            allowed: None,
            input: None,
            claim: None,
        };
        let mut arguments = child_args(&plan)?;
        arguments[1] = "runtime::owned_observation_tests::held_child".into();
        fs::write(home.0.join("stdin"), b"")?;
        let prepared = runtime
            .prepare_launch(
                LaunchReservation {
                    format_version: 1,
                    lifecycle: lifecycle.clone(),
                    host: instance,
                    owner,
                    generation,
                    scope_nonce: nonce,
                    parent: ReservationParent::Windows,
                    created_at_unix_ns: 1,
                },
                LaunchSpec {
                    lifecycle,
                    generation,
                    executable,
                    arguments,
                    cwd: home.0.clone(),
                    environment: Environment {
                        entries: Vec::new(),
                    },
                    stdio: StandardIo {
                        stdin: Some(File::open(home.0.join("stdin"))?),
                        stdout: Some(File::create(home.0.join("stdout"))?),
                        stderr: Some(File::create(home.0.join("stderr"))?),
                    },
                    mode: LaunchMode::Headless,
                    window: None,
                    policy: LaunchPolicy {
                        containment: ContainmentRequirement::KernelScope,
                        writes: WritePolicy::Workspace {
                            roots: vec![home.0.clone()],
                            scratch: home.0.clone(),
                        },
                        network: NetworkPolicy::Allow,
                        hardening: OptionalHardening::Off,
                    },
                    deadline: Instant::now() + Duration::from_secs(10),
                    notifications: Arc::new(Notices),
                },
            )
            .map_err(cause)?;
        let mut fixture = Self {
            runtime,
            process: prepared.process,
            record: None,
            generation,
            home,
            released: false,
        };
        let ticket = match fixture.runtime.begin_launch(prepared.prepared) {
            LaunchStart::Pending { ticket, .. } => ticket,
            LaunchStart::Failed(failure) => return Err(cause(failure.error).into()),
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let record = loop {
            match fixture.runtime.poll_launch(&ticket).map_err(cause)? {
                LaunchProgress::Started(success) => break success.record,
                LaunchProgress::Pending if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                LaunchProgress::Failed(failure) => return Err(cause(failure.error).into()),
                _ => return Err("owned fixture did not publish a native process record".into()),
            }
        };
        fixture.record = Some(record);
        while !fixture.home.0.join("ready").exists() {
            if Instant::now() >= deadline {
                fixture.finish()?;
                return Err("owned fixture barrier not reached".into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(fixture)
    }
    fn record(&self) -> Check<&ProcessRecord> {
        self.record
            .as_ref()
            .ok_or_else(|| "native fixture record absent".into())
    }
    fn finish(&mut self) -> Check {
        if self.released {
            return Ok(());
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        if !matches!(
            self.runtime.witness_exit(&self.process).map_err(cause)?,
            StopObservation::Complete(_)
        ) {
            let prepared = self
                .runtime
                .prepare_stop(&self.process, self.generation, deadline)
                .map_err(cause)?;
            self.runtime
                .request_stop(prepared)
                .map_err(cause)?
                .dispatch
                .map_err(cause)?;
        }
        loop {
            match self.runtime.witness_exit(&self.process).map_err(cause)? {
                StopObservation::Complete(witness) => {
                    self.runtime
                        .release(&self.process, &witness)
                        .map_err(cause)?;
                    self.released = true;
                    assert!(
                        self.runtime
                            .arena_snapshot()
                            .map_err(cause)?
                            .entries
                            .is_empty()
                    );
                    return Ok(());
                }
                _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
                _ => return Err("original owned child cleanup not witnessed".into()),
            }
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!("owned observation fixture cleanup failed: {error}");
        }
    }
}
fn live(
    runtime: &NativeProcessRuntime,
    process: &OwnedProcess,
    expected: &ProcessIdentity,
) -> ProcResult<OwnedObservation> {
    let actual = runtime.observe(process)?;
    assert_eq!(
        &actual.record.root, expected,
        "a retry replaced the retained identity"
    );
    assert!(
        matches!(actual.root, ProcessObservation::Live(_)),
        "fixture ceased to be live"
    );
    Ok(actual)
}

#[test]
fn owned_failed_startup_denial_reaches_original_native_exit() -> Check {
    let mut f = Fixture::new()?;
    let expected = f.record()?.root.clone();
    let release = f.home.0.join("release");
    let calls = Rc::new(RefCell::new(0));
    let observed_calls = Rc::clone(&calls);
    let hook = Hook::install(move |runtime, process| {
        *observed_calls.borrow_mut() += 1;
        let actual = runtime.observe(process)?;
        assert_eq!(actual.record.root, expected);
        if matches!(actual.root, ProcessObservation::Live(_)) {
            fs::write(&release, b"exit original child")
                .map_err(|error| crate::support::input("fixture release", &error.to_string()))?;
            Err(denied("QueryFullProcessImageNameW", 5))
        } else {
            Ok(actual)
        }
    });
    let observed = f
        .runtime
        .observe_until(&f.process, Instant::now() + Duration::from_secs(2));
    drop(hook);
    let observed = observed.map_err(cause)?;
    assert!(matches!(
        observed.root,
        ProcessObservation::Exited {
            evidence: ExitEvidence::KernelHandleSignalled,
            status: ExitStatus::Code(17),
            ..
        }
    ));
    assert!(*calls.borrow() >= 2, "the teardown refusal was not retried");
    f.finish()
}

#[test]
fn owned_live_inaccessible_identity_stays_unreadable_at_original_deadline() -> Check {
    let mut f = Fixture::new()?;
    let expected = f.record()?.root.clone();
    let hook = Hook::install(move |runtime, process| {
        live(runtime, process, &expected)?;
        Err(denied("QueryFullProcessImageNameW", 5))
    });
    let started = Instant::now();
    let deadline = started + Duration::from_millis(60);
    let observed = f.runtime.observe_until(&f.process, deadline);
    drop(hook);
    assert_eq!(
        observed.err().ok_or("denial became success or exit")?,
        denied("QueryFullProcessImageNameW", 5)
    );
    assert!(
        Instant::now() >= deadline,
        "persistent denial returned before its original bound"
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "original deadline was renewed"
    );
    live(&f.runtime, &f.process, &f.record()?.root).map_err(cause)?;
    f.finish()
}

#[test]
fn owned_changed_identity_is_not_retried_as_teardown() -> Check {
    let mut f = Fixture::new()?;
    let expected = f.record()?.root.clone();
    let mut changed = denied("QueryFullProcessImageNameW", 5);
    changed.code = ProcErrorCode::IdentityChanged;
    let original = changed.clone();
    let calls = Rc::new(RefCell::new(0));
    let seen = Rc::clone(&calls);
    let hook = Hook::install(move |runtime, process| {
        live(runtime, process, &expected)?;
        *seen.borrow_mut() += 1;
        Err(changed.clone())
    });
    let observed = f
        .runtime
        .observe_until(&f.process, Instant::now() + Duration::from_secs(1));
    drop(hook);
    assert_eq!(
        observed.err().ok_or("changed identity was accepted")?,
        original
    );
    assert_eq!(*calls.borrow(), 1);
    f.finish()
}

#[test]
fn owned_other_native_refusals_are_not_retried() -> Check {
    let mut f = Fixture::new()?;
    for error in [
        denied("OpenProcess", 5),
        denied("QueryFullProcessImageNameW", 87),
    ] {
        let expected = f.record()?.root.clone();
        let original = error.clone();
        let calls = Rc::new(RefCell::new(0));
        let seen = Rc::clone(&calls);
        let hook = Hook::install(move |runtime, process| {
            live(runtime, process, &expected)?;
            *seen.borrow_mut() += 1;
            Err(error.clone())
        });
        let observed = f
            .runtime
            .observe_until(&f.process, Instant::now() + Duration::from_secs(1));
        drop(hook);
        assert_eq!(
            observed.err().ok_or("unrelated native refusal accepted")?,
            original
        );
        assert_eq!(*calls.borrow(), 1);
    }
    f.finish()
}

#[test]
fn owned_elapsed_deadline_does_not_observe_or_renew() -> Check {
    let mut f = Fixture::new()?;
    let hook = Hook::install(|_, _| panic!("expired deadline began another native observation"));
    let observed = f
        .runtime
        .observe_until(&f.process, Instant::now() - Duration::from_millis(1));
    drop(hook);
    assert_eq!(
        observed.err().ok_or("expired observation accepted")?.code,
        ProcErrorCode::InvalidInput
    );
    f.finish()
}

#[test]
fn owned_no_fresh_observation_may_succeed_after_original_deadline() -> Check {
    let mut f = Fixture::new()?;
    let expected = f.record()?.root.clone();
    let deadline = Instant::now() + Duration::from_millis(60);
    let late = Rc::new(RefCell::new(0));
    let late_calls = Rc::clone(&late);
    let hook = Hook::install(move |runtime, process| {
        let began_after_expiry = Instant::now() >= deadline;
        let actual = live(runtime, process, &expected)?;
        if began_after_expiry {
            *late_calls.borrow_mut() += 1;
            Ok(actual)
        } else {
            Err(denied("QueryFullProcessImageNameW", 5))
        }
    });
    let observed = f.runtime.observe_until(&f.process, deadline);
    drop(hook);
    assert!(
        observed.is_err(),
        "a post-deadline native observation became success"
    );
    assert_eq!(
        *late.borrow(),
        0,
        "a new native observation began after original expiry"
    );
    f.finish()
}

#[test]
#[ignore = "spawned only through the exact owned native runtime fixture"]
fn held_child() -> Check {
    let args: Vec<_> = std::env::args().collect();
    let at = args
        .iter()
        .position(|v| v == "--skip")
        .ok_or("child plan absent")?;
    let plan: ChildPlan = serde_json::from_str(args.get(at + 1).ok_or("child plan bytes absent")?)?;
    fs::write(&plan.report, b"owned child ready")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !plan.report.with_file_name("release").exists() {
        if Instant::now() >= deadline {
            return Err("owned child release bound elapsed".into());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    std::process::exit(17)
}
