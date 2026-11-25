use super::*;
use std::{
    fs::File,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
};
struct Notices;
impl ExitSink for Notices {
    fn notify(&self, _: ExitNotice) {}
}
pub fn helper() -> Check<PathBuf> {
    let image = match std::env::var_os("SE_MACOS_HELPER") {
        Some(path) => PathBuf::from(path),
        None => std::env::current_exe()?
            .parent()
            .and_then(Path::parent)
            .ok_or("test binary has no build root")?
            .join("se"),
    };
    let image = fs::canonicalize(image)?;
    if !image.is_absolute() || !fs::metadata(&image)?.is_file() {
        return Err("actual built se helper required".into());
    }
    let version = std::process::Command::new(&image)
        .arg("--version")
        .output()?;
    if !version.status.success() || !version.stdout.starts_with(b"stateengine ") {
        return Err("selected helper is not a working se image".into());
    }
    Ok(image)
}
pub fn runtime() -> Check<NativeProcessRuntime> {
    let nonce = random_secret()?;
    Ok(NativeProcessRuntime::open(HostConfig {
        machine: machine()?,
        instance: HostInstanceId(nonce.expose()[..16].try_into()?),
        helper_executable: helper()?,
        linux_delegation: LinuxDelegation::CurrentScope,
        limits: ResourceLimits {
            max_lifecycles: 8,
            max_diagnostic_members: 32,
            max_observation_bytes: 65536,
            max_stdio_buffer_bytes: 4096,
        },
        reactor: Arc::new(reactor::Reactor),
    })
    .map_err(error)?)
}
pub fn prepare(
    runtime: &NativeProcessRuntime,
    root: &Path,
    containment: ContainmentRequirement,
    mode: LaunchMode,
) -> Check<PreparedScope> {
    let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
    let generation = GenerationId::new(1)?;
    let arena = runtime.arena_snapshot().map_err(error)?;
    assert!(arena.complete);
    // Reuse the explicitly saved fixture config, never infer ownership from a process list.
    let instance: HostInstanceId = serde_json::from_slice(&fs::read(root.join("instance.json"))?)?;
    fs::write(root.join("input"), b"selected provider input")?;
    let sentinel: i32 = fs::read_to_string(root.join("sentinel"))?.parse()?;
    Ok(runtime
        .prepare_launch(
            LaunchReservation {
                format_version: 1,
                lifecycle: lifecycle.clone(),
                host: instance,
                owner: native::identity(ProcessId(std::process::id()))?,
                generation,
                scope_nonce: nonce,
                parent: ReservationParent::MacOs,
                created_at_unix_ns: 1,
            },
            LaunchSpec {
                executable_custody: None,
                lifecycle,
                generation,
                executable: fs::canonicalize(std::env::current_exe()?)?,
                arguments: vec![
                    "--exact".into(),
                    "fixture::provider::controlled_provider".into(),
                    "--ignored".into(),
                    "--nocapture".into(),
                ],
                cwd: root.to_owned(),
                environment: Environment {
                    entries: vec![
                        ("SE_MACOS_JUDGE_ROOT".into(), root.as_os_str().to_owned()),
                        ("SE_MACOS_SENTINEL".into(), sentinel.to_string().into()),
                    ],
                },
                stdio: StandardIo {
                    stdin: None,
                    stdout: None,
                    stderr: None,
                },
                mode,
                window: None,
                policy: LaunchPolicy {
                    containment,
                    writes: WritePolicy::Workspace {
                        roots: vec![root.to_owned()],
                        scratch: root.to_owned(),
                    },
                    network: NetworkPolicy::Allow,
                    hardening: OptionalHardening::Off,
                },
                deadline: until(),
                notifications: Arc::new(Notices),
            },
        )
        .map_err(error)?)
}
/// Config and saved reservation use the same explicit instance; no private runtime access.
pub fn open(root: &Path) -> Check<NativeProcessRuntime> {
    let instance = HostInstanceId(random_secret()?.expose()[..16].try_into()?);
    json(root.join("instance.json"), &instance)?;
    Ok(NativeProcessRuntime::open(HostConfig {
        machine: machine()?,
        instance,
        helper_executable: helper()?,
        linux_delegation: LinuxDelegation::CurrentScope,
        limits: ResourceLimits {
            max_lifecycles: 8,
            max_diagnostic_members: 32,
            max_observation_bytes: 65536,
            max_stdio_buffer_bytes: 4096,
        },
        reactor: Arc::new(reactor::Reactor),
    })
    .map_err(error)?)
}
pub fn sentinel(root: &Path) -> Check<OwnedFd> {
    let file = File::create(root.join("host-only-descriptor"))?;
    // SAFETY: duplicate our owned file at an otherwise unused high descriptor, intentionally without CLOEXEC.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 100) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful fcntl returns a new descriptor owned by this fixture.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
pub fn begin(
    runtime: &NativeProcessRuntime,
    root: &Path,
) -> Check<(LaunchTicket, OwnedProcess, RootCheckpoint)> {
    let prepared = prepare(
        runtime,
        root,
        ContainmentRequirement::TrackedTree,
        LaunchMode::Headless,
    )?;
    assert_eq!(prepared.checkpoint.guarantee, tracked());
    runtime
        .bind_stdio(
            &prepared.prepared,
            StandardIo {
                stdin: Some(File::open(root.join("input"))?),
                stdout: Some(File::create(root.join("output"))?),
                stderr: Some(File::create(root.join("error"))?),
            },
        )
        .map_err(error)?;
    let LaunchStart::Pending { ticket, process } = runtime.begin_launch(prepared.prepared) else {
        return Err("native launch did not enter pending custody".into());
    };
    let mut checkpoint = None;
    wait(|| match runtime.poll_launch(&ticket).map_err(error)? {
        LaunchProgress::AwaitingExecCommit(value) => {
            checkpoint = Some(*value);
            Ok(true)
        }
        LaunchProgress::Pending => Ok(false),
        LaunchProgress::Failed(f) => Err(format!("pre-exec launch: {:?}", f.error).into()),
        LaunchProgress::Started(_) => Err("provider executed without authorization".into()),
    })?;
    let checkpoint = checkpoint.ok_or("root checkpoint absent")?;
    let pin = native::pin(checkpoint.pre_exec.pid)?;
    assert_eq!(pin.identity, checkpoint.pre_exec);
    assert_eq!(pin.identity.image, helper()?);
    json(root.join("pin-helper.json"), &pin)?;
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        !root.join("executions").exists(),
        "provider executed while paused"
    );
    assert!(native::live(&pin)?);
    Ok((ticket, process, checkpoint))
}
pub fn launch(runtime: &NativeProcessRuntime, root: &Path) -> Check<LaunchSuccess> {
    let (ticket, _process, checkpoint) = begin(runtime, root)?;
    runtime.authorize_exec(&ticket).map_err(error)?;
    let mut success = None;
    wait(|| match runtime.poll_launch(&ticket).map_err(error)? {
        LaunchProgress::Started(value) => {
            success = Some(*value);
            Ok(true)
        }
        LaunchProgress::Pending | LaunchProgress::AwaitingExecCommit(_) => Ok(false),
        LaunchProgress::Failed(f) => Err(format!("authorized native launch: {:?}", f.error).into()),
    })?;
    let success = success.ok_or("launch success absent")?;
    assert_eq!(success.record.root.pid, checkpoint.pre_exec.pid);
    assert_eq!(success.record.root.start, checkpoint.pre_exec.start);
    assert_eq!(success.record.root.boot, checkpoint.pre_exec.boot);
    assert_eq!(
        success.record.root.image,
        fs::canonicalize(std::env::current_exe()?)?
    );
    assert_eq!(success.record.guarantee, tracked());
    assert_eq!(success.record.entry, EntryMethod::MacOsSpawn);
    assert_eq!(
        native::identity(success.record.root.pid)?,
        success.record.root
    );
    wait(|| Ok(root.join("provider.json").exists()))?;
    Ok(success)
}
pub fn tracked() -> ContainmentGuarantee {
    ContainmentGuarantee::TrackedTree {
        atomic_signal: false,
        escape_prevented: false,
    }
}
pub fn stop(
    runtime: &NativeProcessRuntime,
    process: &OwnedProcess,
    generation: GenerationId,
) -> Check<StopObservation> {
    let prepared = runtime
        .prepare_stop(process, generation, until())
        .map_err(error)?;
    let attempt = runtime.request_stop(prepared).map_err(error)?;
    attempt.dispatch.map_err(error)?;
    let mut result = None;
    wait(|| {
        let state = runtime.witness_stop(&attempt.ticket).map_err(error)?;
        if matches!(state, StopObservation::Pending { .. }) {
            return Ok(false);
        }
        result = Some(state);
        Ok(true)
    })?;
    result.ok_or_else(|| "stop observation absent".into())
}
pub fn close(
    runtime: &NativeProcessRuntime,
    process: &OwnedProcess,
    generation: GenerationId,
) -> Check {
    let StopObservation::Complete(witness) = stop(runtime, process, generation)? else {
        return Err("ordinary tracked group closure remained bounded".into());
    };
    assert_eq!(witness.guarantee, tracked());
    assert_eq!(witness.scope_exit.remaining.population, Population::Empty);
    assert_eq!(
        witness.scope_exit.remaining.extent,
        EnumerationExtent::Complete
    );
    runtime.release(process, &witness).map_err(error)?;
    assert!(runtime.arena_snapshot().map_err(error)?.entries.is_empty());
    Ok(())
}
