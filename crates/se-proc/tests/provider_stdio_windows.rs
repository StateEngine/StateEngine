//! Protects: real Windows IOCP stream custody, cancellation, generation fencing
//! and exact close witnesses. Run on Windows; cross compilation is not execution.
#![cfg(windows)]
#[path = "../../test-support/directory_owner.rs"]
mod cleanup_directory;
use se_proc::*;
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn error(value: ProcError) -> String {
    format!("{value:?}")
}
#[derive(Default)]
struct Notices(Mutex<Vec<StdioNotice>>);
impl StdioSink for Notices {
    fn notify(&self, notice: StdioNotice) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(notice);
    }
}
impl ExitSink for Notices {
    fn notify(&self, _: ExitNotice) {}
}
fn runtime(machine: MachineId, host: HostInstanceId) -> Check<NativeProcessRuntime> {
    NativeProcessRuntime::open(HostConfig {
        machine,
        instance: host,
        helper_executable: std::env::current_exe()?,
        linux_delegation: LinuxDelegation::CurrentScope,
        limits: ResourceLimits {
            max_lifecycles: 2,
            max_diagnostic_members: 8,
            max_observation_bytes: 65536,
            max_stdio_buffer_bytes: 192,
        },
    })
    .map_err(|e| error(e).into())
}
fn config(id: &StdioIdentity, sink: Arc<Notices>) -> StdioConfig {
    StdioConfig {
        identity: id.clone(),
        limits: StdioLimits {
            max_read_bytes: 64,
            max_write_bytes: 64,
            max_buffer_bytes: 192,
        },
        notifications: sink,
    }
}
fn completion(runtime: &NativeProcessRuntime, ticket: &StdioTicket) -> Check<StdioCompletion> {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match runtime.take_completion(ticket).map_err(error)? {
            StdioCompletion::Pending if Instant::now() < until => {
                std::thread::park_timeout(Duration::from_millis(2))
            }
            StdioCompletion::Pending => return Err("stream completion timed out".into()),
            result => return Ok(result),
        }
    }
}
fn consumed(runtime: &NativeProcessRuntime, ticket: &StdioTicket) -> Check {
    assert!(
        runtime.take_completion(ticket).is_err(),
        "terminal result was taken twice"
    );
    runtime.release_operation(ticket).map_err(error)?;
    assert!(
        runtime.release_operation(ticket).is_err(),
        "operation released twice"
    );
    Ok(())
}
struct Scope<'a> {
    runtime: &'a NativeProcessRuntime,
    process: OwnedProcess,
    generation: GenerationId,
    released: bool,
}
impl Scope<'_> {
    fn release(&mut self) -> Check {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            if let StopObservation::Complete(witness) =
                self.runtime.witness_exit(&self.process).map_err(error)?
            {
                self.runtime
                    .release(&self.process, &witness)
                    .map_err(error)?;
                self.released = true;
                return Ok(());
            }
            if Instant::now() >= until {
                return Err("owned child scope did not exit".into());
            }
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }
}
impl Drop for Scope<'_> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let cleanup = (|| -> Check {
            if let Some(state) = self.runtime.stdio_state(&self.process).map_err(error)? {
                let close = self
                    .runtime
                    .begin_close(&state.port, StdioCloseScope::All)
                    .map_err(error)?;
                let witness = match completion(self.runtime, &close)? {
                    StdioCompletion::Close {
                        result: Ok(witness),
                        ..
                    } => witness,
                    _ => return Err("cleanup All-close lacked a witness".into()),
                };
                for ticket in self
                    .runtime
                    .stdio_state(&self.process)
                    .map_err(error)?
                    .ok_or("cleanup port absent")?
                    .operations
                {
                    if ticket.operation != close.operation {
                        let _ = completion(self.runtime, &ticket);
                    }
                    self.runtime.release_operation(&ticket).map_err(error)?;
                }
                self.runtime
                    .release_stdio(&state.port, &witness)
                    .map_err(error)?;
            }
            let stop = self
                .runtime
                .prepare_stop(
                    &self.process,
                    self.generation,
                    Instant::now() + Duration::from_secs(5),
                )
                .map_err(error)?;
            self.runtime
                .request_stop(stop)
                .map_err(error)?
                .dispatch
                .map_err(error)?;
            self.release()
        })();
        if let Err(error) = cleanup {
            eprintln!("retained exact provider scope for diagnosis: {error}");
        }
    }
}
/// Protects: the child really waits for stdin EOF before producing both streams.
#[test]
#[ignore = "spawned by the independent native Windows stream test"]
fn provider_stdio_child() -> Check {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    assert_eq!(input, "owned provider input");
    std::io::stdout().write_all(b"owned provider stdout\n")?;
    std::io::stderr().write_all(b"owned provider stderr\n")?;
    Ok(())
}
/// Protects: no ticket/port drop frees kernel buffers, stale bindings cannot consume, and only exact drained All-close releases.
#[test]
fn windows_provider_streams_keep_real_io_and_cancellation_custody() -> Check {
    let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let root: PathBuf =
        std::env::temp_dir().join(format!("se-native-streams-{}", se_types::hex_lower(&nonce)));
    fs::create_dir(&root)?;
    let _root_owner = cleanup_directory::PrivateDirectory::for_case(root.clone());
    let root = fs::canonicalize(root)?;
    eprintln!("provider stream fixture: {}", root.display());
    let machine = MachineId::new("independent-provider-streams")?;
    let host = HostInstanceId(nonce);
    let generation = GenerationId::new(1)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
    let runtime = runtime(machine.clone(), host)?;
    let prepared = runtime
        .prepare_launch(
            LaunchReservation {
                format_version: 1,
                lifecycle: lifecycle.clone(),
                host,
                owner: current_process_identity(machine.clone()).map_err(error)?,
                generation,
                scope_nonce: nonce,
                parent: ReservationParent::Windows,
                created_at_unix_ns: 1,
            },
            provider_spec(&root, lifecycle.clone(), generation)?,
        )
        .map_err(error)?;
    let mut scope = Scope {
        runtime: &runtime,
        process: prepared.process,
        generation,
        released: false,
    };
    let identity = pre_root_identity(
        &runtime,
        &scope.process,
        StdioIdentity {
            lifecycle,
            host,
            generation,
        },
    )?;
    let old_sink = Arc::new(Notices::default());
    let streams = runtime
        .create_stdio(&scope.process, config(&identity, old_sink.clone()))
        .map_err(error)?;
    refuse_out_of_bounds_requests(&runtime, &streams.port)?;
    cancel_dropped_read(&runtime, &scope.process, &streams.port)?;
    let foreign = refuse_foreign_arena(machine, &scope.process, &streams.port)?;
    let (stdout, stderr) =
        bind_and_start(&runtime, prepared.prepared, streams.child, &streams.port)?;
    let next = GenerationId::new(2)?;
    re_adopt(&mut scope, next)?;
    assert_stale_binding_fenced(
        &runtime,
        &scope.process,
        &streams.port,
        [&stdout, &stderr],
        config(&identity, old_sink.clone()),
    );
    let identity = StdioIdentity {
        generation: next,
        ..identity
    };
    let sink = Arc::new(Notices::default());
    let state = attach_drained(&runtime, &scope.process, config(&identity, sink.clone()))?;
    let old_count = notice_count(&old_sink);
    let output = rebound(&state, &stdout).ok_or("stdout operation was lost on rebind")?;
    let errors = rebound(&state, &stderr).ok_or("stderr operation was lost on rebind")?;
    write_input_then_close_stdin(&runtime, &state.port, &sink)?;
    drain_output(&runtime, &state.port, output, errors)?;
    close_all_and_release(&runtime, &state.port, &scope.process)?;
    assert_eq!(
        notice_count(&old_sink),
        old_count,
        "old sink received post-rebind notices"
    );
    assert!(
        sink.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .all(|notice| notice.identity == identity)
    );
    scope.release()?;
    assert!(
        runtime.stdio_identity(&scope.process).is_err(),
        "released scope retained a stream identity"
    );
    assert!(runtime.arena_snapshot().map_err(error)?.entries.is_empty());
    drop(scope);
    drop(runtime);
    drop(foreign);

    _root_owner.finish(Ok(()))
}
fn pre_root_identity(
    runtime: &NativeProcessRuntime,
    process: &OwnedProcess,
    expected: StdioIdentity,
) -> Check<StdioIdentity> {
    assert!(
        runtime.describe(process).is_err(),
        "prepared scope unexpectedly has a published root"
    );
    let identity = (runtime as &dyn ProviderStdioApi)
        .stdio_identity(process)
        .map_err(|e| format!("pre-root stream identity unavailable: {e:?}"))?;
    assert_eq!(identity, expected);
    Ok(identity)
}
/// Another arena cannot read the stream identity or write through the port.
fn refuse_foreign_arena(
    machine: MachineId,
    process: &OwnedProcess,
    port: &StdioPort,
) -> Check<NativeProcessRuntime> {
    let foreign = runtime_for_other_arena(machine)?;
    assert!(
        foreign.stdio_identity(process).is_err(),
        "foreign arena read stream identity"
    );
    let rejected = foreign
        .begin_write(port, b"foreign bytes".to_vec())
        .err()
        .ok_or("foreign arena wrote")?;
    assert_eq!(rejected.bytes, b"foreign bytes");
    Ok(foreign)
}
fn re_adopt(scope: &mut Scope<'_>, next: GenerationId) -> Check {
    let runtime = scope.runtime;
    let record = runtime.describe(&scope.process).map_err(error)?;
    scope.process = runtime
        .re_adopt(&record, scope.generation, next)
        .map_err(error)?;
    scope.generation = next;
    Ok(())
}
/// After re-adoption the old port, its tickets and its binding are all refused.
fn assert_stale_binding_fenced(
    runtime: &NativeProcessRuntime,
    process: &OwnedProcess,
    port: &StdioPort,
    [stdout, stderr]: [&StdioTicket; 2],
    stale: StdioConfig,
) {
    assert!(
        runtime
            .begin_read(port, StdioReadStream::Stdout, 8)
            .is_err()
    );
    assert!(runtime.take_completion(stdout).is_err());
    assert!(runtime.cancel(stderr).is_err());
    assert!(runtime.attach_stdio(process, stale).is_err());
}
fn notice_count(sink: &Notices) -> usize {
    sink.0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len()
}
fn rebound<'a>(state: &'a StdioState, ticket: &StdioTicket) -> Option<&'a StdioTicket> {
    state
        .operations
        .iter()
        .find(|t| t.operation == ticket.operation)
}
fn provider_spec(
    root: &Path,
    lifecycle: LifecycleId,
    generation: GenerationId,
) -> Check<LaunchSpec> {
    Ok(LaunchSpec {
        executable_custody: None,
        lifecycle,
        generation,
        executable: std::env::current_exe()?,
        arguments: vec![
            "--exact".into(),
            "provider_stdio_child".into(),
            "--ignored".into(),
            "--nocapture".into(),
            "--test-threads=1".into(),
        ],
        cwd: root.to_path_buf(),
        environment: Environment { entries: vec![] },
        stdio: StandardIo {
            stdin: None,
            stdout: None,
            stderr: None,
        },
        mode: LaunchMode::Headless,
        window: None,
        policy: LaunchPolicy {
            containment: ContainmentRequirement::BestAvailable,
            writes: WritePolicy::Workspace {
                roots: vec![root.to_path_buf()],
                scratch: root.to_path_buf(),
            },
            network: NetworkPolicy::Allow,
            hardening: OptionalHardening::Off,
        },
        deadline: Instant::now() + Duration::from_secs(20),
        notifications: Arc::new(Notices::default()),
    })
}
/// Zero and over-limit reads, and an over-capacity write, refuse and return their buffer.
fn refuse_out_of_bounds_requests(runtime: &NativeProcessRuntime, port: &StdioPort) -> Check {
    assert!(
        runtime
            .begin_read(port, StdioReadStream::Stdout, 0)
            .is_err()
    );
    assert!(
        runtime
            .begin_read(port, StdioReadStream::Stdout, 65)
            .is_err()
    );
    let mut too_large = Vec::with_capacity(128);
    too_large.push(7);
    let refused = runtime
        .begin_write(port, too_large)
        .err()
        .ok_or("over-capacity buffer admitted")?;
    assert_eq!(refused.bytes, [7]);
    assert!(refused.bytes.capacity() >= 128);
    Ok(())
}
/// A dropped pending read stays owned, is recovered from state, and cancels exactly.
fn cancel_dropped_read(
    runtime: &NativeProcessRuntime,
    process: &OwnedProcess,
    port: &StdioPort,
) -> Check {
    let abandoned = runtime
        .begin_read(port, StdioReadStream::Stdout, 8)
        .map_err(error)?;
    let abandoned_id = abandoned.operation;
    assert!(
        runtime.release_operation(&abandoned).is_err(),
        "pending kernel request was freed"
    );
    assert!(
        runtime
            .begin_read(port, StdioReadStream::Stdout, 8)
            .is_err()
    );
    drop(abandoned);
    let recovered = runtime
        .stdio_state(process)
        .map_err(error)?
        .ok_or("lost dropped ticket")?;
    let recovered = recovered
        .operations
        .iter()
        .find(|t| t.operation == abandoned_id)
        .ok_or("dropped request missing")?;
    assert!(matches!(
        runtime.cancel(recovered).map_err(error)?,
        StdioCancel::Requested | StdioCancel::AlreadyCompleted
    ));
    match completion(runtime, recovered)? {
        StdioCompletion::Read {
            bytes,
            eof,
            outcome: StdioOutcome::Cancelled,
            ..
        } => {
            assert!(bytes.is_empty());
            assert!(!eof);
        }
        _ => return Err("cancelled pre-launch read lost its cancellation result".into()),
    }
    consumed(runtime, recovered)
}
/// Binds the child endpoints, queues one read per output stream, then launches.
fn bind_and_start(
    runtime: &NativeProcessRuntime,
    prepared: PreparedLaunch,
    child: StandardIo,
    port: &StdioPort,
) -> Check<(StdioTicket, StdioTicket)> {
    runtime.bind_stdio(&prepared, child).map_err(error)?;
    let stdout = runtime
        .begin_read(port, StdioReadStream::Stdout, 8)
        .map_err(error)?;
    let stderr = runtime
        .begin_read(port, StdioReadStream::Stderr, 8)
        .map_err(error)?;
    let launch = match runtime.begin_launch(prepared) {
        LaunchStart::Pending { ticket, .. } => ticket,
        LaunchStart::Failed(failure) => {
            return Err(format!("launch refused: {:?}", failure.error).into());
        }
    };
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match runtime.poll_launch(&launch).map_err(error)? {
            LaunchProgress::Started(_) => break,
            LaunchProgress::Pending if Instant::now() < until => {
                std::thread::park_timeout(Duration::from_millis(2))
            }
            _ => return Err("Windows vendor launch did not become Started".into()),
        }
    }
    Ok((stdout, stderr))
}
/// Attaches the new binding and waits until the prior callback binding drains.
fn attach_drained(
    runtime: &NativeProcessRuntime,
    process: &OwnedProcess,
    config: StdioConfig,
) -> Check<StdioState> {
    let mut state = runtime.attach_stdio(process, config).map_err(error)?;
    let until = Instant::now() + Duration::from_secs(10);
    while state.binding != StdioBinding::Ready {
        if Instant::now() >= until {
            return Err("prior callback binding did not drain".into());
        }
        std::thread::park_timeout(Duration::from_millis(2));
        state = runtime
            .stdio_state(process)
            .map_err(error)?
            .ok_or("port disappeared")?;
    }
    Ok(state)
}
/// One stdin write completes to the new sink, then a Stdin close cannot release all streams.
fn write_input_then_close_stdin(
    runtime: &NativeProcessRuntime,
    port: &StdioPort,
    sink: &Notices,
) -> Check {
    let input = b"owned provider input".to_vec();
    let write = runtime
        .begin_write(port, input.clone())
        .map_err(|r| error(r.error))?;
    let refused = runtime
        .begin_write(port, b"second write".to_vec())
        .err()
        .ok_or("unreleased stdin write duplicated")?;
    assert_eq!(refused.bytes, b"second write");
    let close = runtime
        .begin_close(port, StdioCloseScope::Stdin)
        .map_err(error)?;
    match completion(runtime, &write)? {
        StdioCompletion::Write {
            bytes,
            written,
            outcome: StdioOutcome::Complete,
        } => {
            assert_eq!(bytes, input);
            assert_eq!(written as usize, input.len());
        }
        _ => return Err("stdin completion lost accepted bytes or count".into()),
    }
    let until = Instant::now() + Duration::from_secs(10);
    while !sink
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(
            |notice| matches!(notice.kind, StdioNoticeKind::Operation(id) if id == write.operation),
        )
    {
        if Instant::now() >= until {
            return Err("new sink did not receive the real write completion".into());
        }
        std::thread::park_timeout(Duration::from_millis(2));
    }
    consumed(runtime, &write)?;
    let stdin_witness = match completion(runtime, &close)? {
        StdioCompletion::Close {
            scope: StdioCloseScope::Stdin,
            result: Ok(witness),
        } => witness,
        _ => return Err("stdin close failed".into()),
    };
    consumed(runtime, &close)?;
    assert!(
        runtime.release_stdio(port, &stdin_witness).is_err(),
        "Stdin witness released all streams"
    );
    assert!(runtime.begin_write(port, b"after EOF".to_vec()).is_err());
    Ok(())
}
/// Reads each stream in bounded chunks until real EOF and finds the child's marker.
fn drain_output(
    runtime: &NativeProcessRuntime,
    port: &StdioPort,
    output: &StdioTicket,
    errors: &StdioTicket,
) -> Check {
    for (stream, first, marker) in [
        (
            StdioReadStream::Stdout,
            output,
            b"owned provider stdout".as_slice(),
        ),
        (
            StdioReadStream::Stderr,
            errors,
            b"owned provider stderr".as_slice(),
        ),
    ] {
        let mut collected = Vec::new();
        let mut ticket = None;
        loop {
            let current = ticket.as_ref().unwrap_or(first);
            let eof = match completion(runtime, current)? {
                StdioCompletion::Read {
                    stream: actual,
                    bytes,
                    eof,
                    outcome: StdioOutcome::Complete,
                } => {
                    assert_eq!(actual, stream);
                    assert!(bytes.len() <= 8);
                    collected.extend(bytes);
                    eof
                }
                _ => return Err("real output read failed or pretended EOF".into()),
            };
            consumed(runtime, current)?;
            if eof {
                break;
            }
            assert!(
                collected.len() < 8192,
                "child output exceeded fixture bound"
            );
            ticket = Some(runtime.begin_read(port, stream, 8).map_err(error)?);
        }
        assert!(
            collected.windows(marker.len()).any(|part| part == marker),
            "real child output marker missing"
        );
    }
    Ok(())
}
/// Only the consumed All-close witness releases the port, and nothing reads after it.
fn close_all_and_release(
    runtime: &NativeProcessRuntime,
    port: &StdioPort,
    process: &OwnedProcess,
) -> Check {
    let close = runtime
        .begin_close(port, StdioCloseScope::All)
        .map_err(error)?;
    let witness = match completion(runtime, &close)? {
        StdioCompletion::Close {
            scope: StdioCloseScope::All,
            result: Ok(witness),
        } => witness,
        _ => return Err("All close failed".into()),
    };
    assert!(
        runtime.release_stdio(port, &witness).is_err(),
        "port released before close operation"
    );
    consumed(runtime, &close)?;
    runtime.release_stdio(port, &witness).map_err(error)?;
    assert!(runtime.stdio_state(process).map_err(error)?.is_none());
    assert!(
        runtime
            .begin_read(port, StdioReadStream::Stdout, 8)
            .is_err()
    );
    Ok(())
}
fn runtime_for_other_arena(machine: MachineId) -> Check<NativeProcessRuntime> {
    runtime(machine, HostInstanceId([99; 16]))
}
