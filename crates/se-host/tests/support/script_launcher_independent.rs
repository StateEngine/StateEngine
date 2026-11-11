//! Independent Linux scope controls; the stock-provider journey is separate.
use super::launch_util::{script_launcher, stabilize_alias};
use crate::ProviderInvocation;
use se_proc::*;
use se_types::NativePath;
use std::{
    fs::{self, File},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const WORD: &str = "literal ' $HOME ; `false` λ";
fn native(e: ProcError) -> String {
    format!("{e:?}")
}
struct Home(PathBuf);
impl Home {
    fn new() -> Check<Self> {
        let root = std::env::temp_dir().join(format!(
            "script-launch-{}",
            se_types::hex_lower(&random_secret()?.expose()[..16])
        ));
        fs::create_dir(&root)?;
        let root = fs::canonicalize(root)?;
        let image = root.join("native child ; literal");
        let output = Command::new("cc")
            .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/support/script_launcher_child.c"
            ))
            .arg("-o")
            .arg(&image)
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::copy(&image, root.join("second-native"))?;
        let script = root.join("script launcher ' $ literal");
        fs::write(&script, b"#!/usr/bin/env sh\nexec \"$@\"\n")?;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;
        Ok(Self(root))
    }
    fn image(&self) -> PathBuf {
        self.0.join("native child ; literal")
    }
    fn script(&self) -> PathBuf {
        self.0.join("script launcher ' $ literal")
    }
    fn invocation(&self, script: bool, swap: bool) -> Check<ProviderInvocation> {
        let selected = if script { self.script() } else { self.image() };
        let mut arguments = vec![];
        if script {
            arguments.push(self.image().into_os_string());
        }
        arguments.extend([self.0.clone().into_os_string(), WORD.into()]);
        if swap {
            arguments.push(self.0.join("second-native").into_os_string());
        }
        let required = script_launcher(&selected)?;
        assert_eq!(required, script, "classify actual selected image");
        let invocation = stabilize_alias(
            ProviderInvocation {
                executable: NativePath::from_local(selected.clone())?,
                arguments,
                environment: Environment {
                    entries: vec![("PATH".into(), "/usr/bin:/bin".into())],
                },
            },
            required,
        )?;
        if script {
            assert_ne!(invocation.executable.to_local()?, selected);
        } else {
            assert_eq!(
                invocation.executable.to_local()?,
                selected,
                "native path remains direct"
            );
        }
        Ok(invocation)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let cleanup = (|| -> Check {
            for entry in fs::read_dir(&self.0)? {
                let entry = entry?;
                assert!(
                    entry.file_type()?.is_file(),
                    "retain unexpected fixture entry"
                );
                fs::remove_file(entry.path())?;
            }
            fs::remove_dir(&self.0)?;
            Ok(())
        })();
        if let Err(error) = cleanup {
            eprintln!("retained fixture {}: {error}", self.0.display());
        }
    }
}
struct Notices;
impl ExitSink for Notices {
    fn notify(&self, _: ExitNotice) {}
}
struct Scope {
    runtime: NativeProcessRuntime,
    process: OwnedProcess,
    root: PathBuf,
    record: Option<ProcessRecord>,
    released: bool,
    _executor: tokio::runtime::Runtime,
}
impl Scope {
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    fn launch(home: &Home, invocation: ProviderInvocation) -> Check<Self> {
        let executor = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .max_blocking_threads(2)
            .build()?;
        let machine = MachineId::new("script-launch-control")?;
        let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
        let host = HostInstanceId(nonce);
        let generation = GenerationId::new(1)?;
        let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
        let runtime = NativeProcessRuntime::open(HostConfig {
            machine: machine.clone(),
            instance: host,
            helper_executable: std::env::current_exe()?,
            linux_delegation: LinuxDelegation::CurrentScope,
            limits: ResourceLimits {
                max_lifecycles: 2,
                max_diagnostic_members: 8,
                max_observation_bytes: 65536,
                max_stdio_buffer_bytes: 4096,
            },
            reactor: Arc::new(super::reactor::Reactor {
                runtime: executor.handle().clone(),
                fault: Arc::new(crate::runtime::tasks::OwnershipFault::default()),
                fence: Arc::new(AtomicBool::new(false)),
            }),
        })
        .map_err(native)?;
        let until = Instant::now() + Duration::from_secs(12);
        let prepared = runtime
            .prepare_launch(
                LaunchReservation {
                    format_version: 1,
                    lifecycle: lifecycle.clone(),
                    host,
                    owner: current_process_identity(machine).map_err(native)?,
                    generation,
                    scope_nonce: nonce,
                    parent: ReservationParent::LinuxTracked,
                    created_at_unix_ns: 1,
                },
                LaunchSpec {
                    lifecycle,
                    generation,
                    executable: invocation.executable.to_local()?,
                    arguments: invocation.arguments,
                    cwd: home.0.clone(),
                    environment: invocation.environment,
                    stdio: StandardIo {
                        stdin: None,
                        stdout: None,
                        stderr: None,
                    },
                    mode: LaunchMode::Headless,
                    window: None,
                    policy: LaunchPolicy {
                        containment: ContainmentRequirement::TrackedTree,
                        writes: WritePolicy::Workspace {
                            roots: vec![home.0.clone()],
                            scratch: home.0.clone(),
                        },
                        network: NetworkPolicy::Allow,
                        hardening: OptionalHardening::Off,
                    },
                    deadline: until,
                    notifications: Arc::new(Notices),
                },
            )
            .map_err(native)?;
        runtime
            .bind_stdio(
                &prepared.prepared,
                StandardIo {
                    stdin: Some(File::open("/dev/null")?),
                    stdout: Some(File::create(home.0.join("stdout"))?),
                    stderr: Some(File::create(home.0.join("stderr"))?),
                },
            )
            .map_err(native)?;
        let mut owned = Self {
            runtime,
            process: prepared.process,
            root: home.0.clone(),
            record: None,
            released: false,
            _executor: executor,
        };
        let ticket = match owned.runtime.begin_launch(prepared.prepared) {
            LaunchStart::Pending { ticket, .. } => ticket,
            LaunchStart::Failed(f) => return Err(format!("begin: {:?}", f.error).into()),
        };
        loop {
            match owned.runtime.poll_launch(&ticket).map_err(native)? {
                LaunchProgress::Started(started) => {
                    owned.record = Some(started.record);
                    return Ok(owned);
                }
                LaunchProgress::AwaitingExecCommit(_) => {
                    owned.runtime.authorize_exec(&ticket).map_err(native)?
                }
                LaunchProgress::Failed(f) => return Err(format!("poll: {:?}", f.error).into()),
                LaunchProgress::Pending => {
                    assert!(Instant::now() < until, "native launch deadline");
                    std::thread::park_timeout(Duration::from_millis(5));
                }
            }
        }
    }
    fn wait_ready(&self) -> Check<ProcessId> {
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(text) = fs::read_to_string(self.root.join("ready"))
                && let Some((pid, word)) = text.split_once('\n')
                && word == WORD
            {
                return Ok(ProcessId(pid.parse()?));
            }
            assert!(Instant::now() < until, "actual child ready marker");
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
    fn finish(&mut self) -> Check {
        fs::write(self.root.join("finish"), b"finish owned child")?;
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(StopObservation::Complete(witness)) = self.runtime.witness_exit(&self.process)
            {
                self.runtime
                    .release(&self.process, &witness)
                    .map_err(native)?;
                self.released = true;
                return Ok(());
            }
            assert!(Instant::now() < until, "exact scope exit remains unproved");
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if !self.released
            && let Err(error) = self.finish()
        {
            eprintln!("retained scope {}: {error}", self.root.display());
        }
    }
}
#[test]
fn script_reexec_keeps_stable_root_and_literal_arguments() -> Check {
    let home = Home::new()?;
    let mut scope = Scope::launch(&home, home.invocation(true, false)?)?;
    let child = scope.wait_ready()?;
    let record = scope.record.as_ref().ok_or("missing root record")?;
    println!("script root={} child={}", record.root.pid.0, child.0);
    assert_ne!(record.root.pid, child, "script re-exec stays a descendant");
    for _ in 0..3 {
        let observed = scope.runtime.observe(&scope.process).map_err(native)?;
        assert_eq!(
            observed.record.root, record.root,
            "root image and birth remain exact"
        );
        assert!(
            observed
                .scope
                .remaining
                .known_live
                .iter()
                .any(|p| p.pid == child)
        );
    }
    let stop = scope
        .runtime
        .prepare_stop(
            &scope.process,
            GenerationId::new(1)?,
            Instant::now() + Duration::from_secs(5),
        )
        .map_err(native)?;
    scope
        .runtime
        .request_stop(stop)
        .map_err(native)?
        .dispatch
        .map_err(native)?;
    scope.finish()
}
#[test]
fn native_image_stays_direct_and_exactly_retirable() -> Check {
    let home = Home::new()?;
    let mut scope = Scope::launch(&home, home.invocation(false, false)?)?;
    let child = scope.wait_ready()?;
    let observed = scope.runtime.observe(&scope.process).map_err(native)?;
    println!("native root={}", observed.record.root.pid.0);
    assert_eq!(
        observed.record.root.pid, child,
        "native provider has no extra parent"
    );
    scope.finish()
}
#[test]
fn genuine_native_root_image_swap_is_still_refused() -> Check {
    let home = Home::new()?;
    let mut scope = Scope::launch(&home, home.invocation(false, true)?)?;
    scope.wait_ready()?;
    let before = scope
        .runtime
        .observe(&scope.process)
        .map_err(native)?
        .record
        .root;
    println!("swapped root={}", before.pid.0);
    fs::write(home.0.join("swap"), b"replace image under the same PID")?;
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match read_process(before.machine.clone(), before.pid).map_err(native)? {
            ProcessRead::Present(live) if live.identity.image != before.image => {
                assert_eq!(live.identity.start, before.start, "same native birth");
                break;
            }
            _ => assert!(Instant::now() < until, "native root never swapped"),
        }
        std::thread::park_timeout(Duration::from_millis(5));
    }
    let refusal = scope
        .runtime
        .observe(&scope.process)
        .err()
        .ok_or("root image swap was accepted")?;
    assert_eq!(refusal.code, ProcErrorCode::IdentityChanged, "{refusal:?}");
    scope.finish()
}
