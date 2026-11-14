//! Protects: real Windows IOCP stream custody, cancellation, generation fencing
//! and exact close witnesses. Run on Windows; cross compilation is not execution.
#![cfg(windows)]
#[path = "../../test-support/directory_owner.rs"]
mod cleanup_directory;
use se_proc::*;
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
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
#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
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
            LaunchSpec {
                executable_custody: None,
                lifecycle: lifecycle.clone(),
                generation,
                executable: std::env::current_exe()?,
                arguments: vec![
                    "--exact".into(),
                    "provider_stdio_child".into(),
                    "--ignored".into(),
                    "--nocapture".into(),
                    "--test-threads=1".into(),
                ],
                cwd: root.clone(),
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
                        roots: vec![root.clone()],
                        scratch: root.clone(),
                    },
                    network: NetworkPolicy::Allow,
                    hardening: OptionalHardening::Off,
                },
                deadline: Instant::now() + Duration::from_secs(20),
                notifications: Arc::new(Notices::default()),
            },
        )
        .map_err(error)?;
    let mut scope = Scope {
        runtime: &runtime,
        process: prepared.process,
        generation,
        released: false,
    };
    assert!(
        runtime.describe(&scope.process).is_err(),
        "prepared scope unexpectedly has a published root"
    );
    let identity = (&runtime as &dyn ProviderStdioApi)
        .stdio_identity(&scope.process)
        .map_err(|e| format!("pre-root stream identity unavailable: {e:?}"))?;
    assert_eq!(
        identity,
        StdioIdentity {
            lifecycle,
            host,
            generation
        }
    );
    let old_sink = Arc::new(Notices::default());
    let streams = runtime
        .create_stdio(&scope.process, config(&identity, old_sink.clone()))
        .map_err(error)?;
    assert!(
        runtime
            .begin_read(&streams.port, StdioReadStream::Stdout, 0)
            .is_err()
    );
    assert!(
        runtime
            .begin_read(&streams.port, StdioReadStream::Stdout, 65)
            .is_err()
    );
    let mut too_large = Vec::with_capacity(128);
    too_large.push(7);
    let refused = runtime
        .begin_write(&streams.port, too_large)
        .err()
        .ok_or("over-capacity buffer admitted")?;
    assert_eq!(refused.bytes, [7]);
    assert!(refused.bytes.capacity() >= 128);
    let abandoned = runtime
        .begin_read(&streams.port, StdioReadStream::Stdout, 8)
        .map_err(error)?;
    let abandoned_id = abandoned.operation;
    assert!(
        runtime.release_operation(&abandoned).is_err(),
        "pending kernel request was freed"
    );
    assert!(
        runtime
            .begin_read(&streams.port, StdioReadStream::Stdout, 8)
            .is_err()
    );
    drop(abandoned);
    let recovered = runtime
        .stdio_state(&scope.process)
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
    match completion(&runtime, recovered)? {
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
    consumed(&runtime, recovered)?;
    let foreign = runtime_for_other_arena(machine)?;
    assert!(
        foreign.stdio_identity(&scope.process).is_err(),
        "foreign arena read stream identity"
    );
    let rejected = foreign
        .begin_write(&streams.port, b"foreign bytes".to_vec())
        .err()
        .ok_or("foreign arena wrote")?;
    assert_eq!(rejected.bytes, b"foreign bytes");
    runtime
        .bind_stdio(&prepared.prepared, streams.child)
        .map_err(error)?;
    let stdout = runtime
        .begin_read(&streams.port, StdioReadStream::Stdout, 8)
        .map_err(error)?;
    let stderr = runtime
        .begin_read(&streams.port, StdioReadStream::Stderr, 8)
        .map_err(error)?;
    let launch = match runtime.begin_launch(prepared.prepared) {
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
    let record = runtime.describe(&scope.process).map_err(error)?;
    let next = GenerationId::new(2)?;
    scope.process = runtime.re_adopt(&record, generation, next).map_err(error)?;
    scope.generation = next;
    assert!(
        runtime
            .begin_read(&streams.port, StdioReadStream::Stdout, 8)
            .is_err()
    );
    assert!(runtime.take_completion(&stdout).is_err());
    assert!(runtime.cancel(&stderr).is_err());
    assert!(
        runtime
            .attach_stdio(&scope.process, config(&identity, old_sink.clone()))
            .is_err()
    );
    let identity = StdioIdentity {
        generation: next,
        ..identity
    };
    let sink = Arc::new(Notices::default());
    let mut state = runtime
        .attach_stdio(&scope.process, config(&identity, sink.clone()))
        .map_err(error)?;
    let until = Instant::now() + Duration::from_secs(10);
    while state.binding != StdioBinding::Ready {
        if Instant::now() >= until {
            return Err("prior callback binding did not drain".into());
        }
        std::thread::park_timeout(Duration::from_millis(2));
        state = runtime
            .stdio_state(&scope.process)
            .map_err(error)?
            .ok_or("port disappeared")?;
    }
    let old_count = old_sink
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len();
    let output = state
        .operations
        .iter()
        .find(|t| t.operation == stdout.operation)
        .ok_or("stdout operation was lost on rebind")?;
    let errors = state
        .operations
        .iter()
        .find(|t| t.operation == stderr.operation)
        .ok_or("stderr operation was lost on rebind")?;
    let input = b"owned provider input".to_vec();
    let write = runtime
        .begin_write(&state.port, input.clone())
        .map_err(|r| error(r.error))?;
    let refused = runtime
        .begin_write(&state.port, b"second write".to_vec())
        .err()
        .ok_or("unreleased stdin write duplicated")?;
    assert_eq!(refused.bytes, b"second write");
    let close = runtime
        .begin_close(&state.port, StdioCloseScope::Stdin)
        .map_err(error)?;
    match completion(&runtime, &write)? {
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
    consumed(&runtime, &write)?;
    let stdin_witness = match completion(&runtime, &close)? {
        StdioCompletion::Close {
            scope: StdioCloseScope::Stdin,
            result: Ok(witness),
        } => witness,
        _ => return Err("stdin close failed".into()),
    };
    consumed(&runtime, &close)?;
    assert!(
        runtime.release_stdio(&state.port, &stdin_witness).is_err(),
        "Stdin witness released all streams"
    );
    assert!(
        runtime
            .begin_write(&state.port, b"after EOF".to_vec())
            .is_err()
    );
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
            let eof = match completion(&runtime, current)? {
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
            consumed(&runtime, current)?;
            if eof {
                break;
            }
            assert!(
                collected.len() < 8192,
                "child output exceeded fixture bound"
            );
            ticket = Some(runtime.begin_read(&state.port, stream, 8).map_err(error)?);
        }
        assert!(
            collected.windows(marker.len()).any(|part| part == marker),
            "real child output marker missing"
        );
    }
    let close = runtime
        .begin_close(&state.port, StdioCloseScope::All)
        .map_err(error)?;
    let witness = match completion(&runtime, &close)? {
        StdioCompletion::Close {
            scope: StdioCloseScope::All,
            result: Ok(witness),
        } => witness,
        _ => return Err("All close failed".into()),
    };
    assert!(
        runtime.release_stdio(&state.port, &witness).is_err(),
        "port released before close operation"
    );
    consumed(&runtime, &close)?;
    runtime
        .release_stdio(&state.port, &witness)
        .map_err(error)?;
    assert!(
        runtime
            .stdio_state(&scope.process)
            .map_err(error)?
            .is_none()
    );
    assert!(
        runtime
            .begin_read(&state.port, StdioReadStream::Stdout, 8)
            .is_err()
    );
    assert_eq!(
        old_sink
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
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
fn runtime_for_other_arena(machine: MachineId) -> Check<NativeProcessRuntime> {
    runtime(machine, HostInstanceId([99; 16]))
}
