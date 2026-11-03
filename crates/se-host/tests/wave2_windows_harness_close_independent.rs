//! Native Windows process-boundary judge; a tiny protocol fixture emits one
//! Claude init echo, then idles. The real ClaudeHarness aborts its drain tasks.
//! This is transport custody evidence, not real-provider journey qualification.
#![cfg(windows)]
use se_host::{
    CallContext, ClaudeHarness, Harness, HarnessAttach, HarnessKind, HarnessRequest, ProbeRequest,
    ProviderIoPlatform, SessionIdentity, WindowsProviderIo,
};
use se_proc::*;
use se_types::{Body, IdempotencyKey, NativePath, Read, Secret};
use std::{
    fs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
type Check<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn native(e: ProcError) -> String {
    format!("{e:?}")
}
fn context() -> Check<CallContext> {
    Ok(CallContext::new(se_types::Generation::new(1)?, Duration::from_secs(10)))
}
struct Exit;
impl ExitSink for Exit {
    fn notify(&self, _: ExitNotice) {}
}
fn completion(runtime: &NativeProcessRuntime, ticket: &StdioTicket) -> Check<StdioCompletion> {
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        match runtime.take_completion(ticket).map_err(native)? {
            StdioCompletion::Pending if Instant::now() < end => {
                std::thread::park_timeout(Duration::from_millis(2))
            }
            StdioCompletion::Pending => return Err("native completion deadline".into()),
            value => return Ok(value),
        }
    }
}
struct Scope {
    runtime: Arc<NativeProcessRuntime>,
    process: OwnedProcess,
    generation: GenerationId,
    released: bool,
}
impl Scope {
    fn stopped(&self) -> Check<Box<StopWitness>> {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            match self.runtime.witness_exit(&self.process).map_err(native)? {
                StopObservation::Complete(witness) => return Ok(witness),
                _ if Instant::now() < until => std::thread::park_timeout(Duration::from_millis(2)),
                _ => return Err("owned native scope exit unproved".into()),
            }
        }
    }
    fn stop(&self) -> Check<Box<StopWitness>> {
        if let StopObservation::Complete(witness) =
            self.runtime.witness_exit(&self.process).map_err(native)?
        {
            return Ok(witness);
        }
        let prepared = self
            .runtime
            .prepare_stop(
                &self.process,
                self.generation,
                Instant::now() + Duration::from_secs(10),
            )
            .map_err(native)?;
        self.runtime
            .request_stop(prepared)
            .map_err(native)?
            .dispatch
            .map_err(native)?;
        self.stopped()
    }
    fn cleanup(&mut self) -> Check {
        if self.released {
            return Ok(());
        }
        if let Some(state) = self.runtime.stdio_state(&self.process).map_err(native)? {
            let close = self
                .runtime
                .begin_close(&state.port, StdioCloseScope::All)
                .map_err(native)?;
            let witness = match completion(&self.runtime, &close)? {
                StdioCompletion::Close {
                    result: Ok(witness),
                    ..
                } => witness,
                _ => return Err("cleanup close lacks exact witness".into()),
            };
            for ticket in self
                .runtime
                .stdio_state(&self.process)
                .map_err(native)?
                .ok_or("cleanup port absent")?
                .operations
            {
                if ticket.operation != close.operation {
                    let _ = completion(&self.runtime, &ticket);
                }
                self.runtime.release_operation(&ticket).map_err(native)?;
            }
            self.runtime
                .release_stdio(&state.port, &witness)
                .map_err(native)?;
        }
        let witness = self.stop()?;
        self.runtime
            .release(&self.process, &witness)
            .map_err(native)?;
        self.released = true;
        Ok(())
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("exact native fixture custody remains: {error}");
        }
    }
}
fn helper(root: &std::path::Path) -> Check<PathBuf> {
    let source = root.join("provider.rs");
    let exe = root.join("provider.exe");
    fs::write(
        &source,
        r#"use std::io::{BufRead,Write};
fn main(){
 let args:Vec<String>=std::env::args().collect();
 if args.get(1).map(String::as_str)==Some("--version"){println!("2.1.287 (Claude Code)");return;}
 let mut input=String::new();std::io::stdin().lock().read_line(&mut input).unwrap();
 println!("{{\"type\":\"system\",\"subtype\":\"init\",\"session_id\":\"{}\"}}",args[1]);
 std::io::stdout().flush().unwrap();
 loop{std::thread::park_timeout(std::time::Duration::from_secs(60));}
}"#,
    )?;
    let status = std::process::Command::new("rustc")
        .arg("--edition=2024")
        .arg(&source)
        .arg("-o")
        .arg(&exe)
        .status()?;
    if !status.success() {
        return Err("native protocol helper compilation failed".into());
    }
    Ok(exe)
}
/// Protects: both real quiet reads are retained through task abortion, each
/// completion is consumed/released, and exact All-close frees this native port.
#[test]
fn aborting_actual_claude_drains_releases_every_idle_read_and_exact_port() -> Check {
    let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
    let root =
        std::env::temp_dir().join(format!("5d-harness-close-{}", se_types::hex_lower(&nonce)));
    fs::create_dir(&root)?;
    let root = fs::canonicalize(root)?;
    let executable = helper(&root)?;
    let machine = MachineId::new("independent-harness-close")?;
    let host = HostInstanceId(nonce);
    let generation = GenerationId::new(1)?;
    let runtime = Arc::new(
        NativeProcessRuntime::open(HostConfig {
            machine: machine.clone(),
            instance: host,
            helper_executable: std::env::current_exe()?,
            linux_delegation: LinuxDelegation::CurrentScope,
            limits: ResourceLimits {
                max_lifecycles: 2,
                max_diagnostic_members: 8,
                max_observation_bytes: 65536,
                max_stdio_buffer_bytes: 196608,
            },
        })
        .map_err(native)?,
    );
    let io = Arc::new(WindowsProviderIo::new(
        runtime.clone(),
        StdioLimits {
            max_read_bytes: 65536,
            max_write_bytes: 65536,
            max_buffer_bytes: 196608,
        },
    ));
    let identity = SessionIdentity {
        project: se_types::ProjectId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?,
        agent: se_types::AgentId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?,
        session: se_types::SessionId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?,
    };
    let policy = LaunchPolicy {
        containment: ContainmentRequirement::BestAvailable,
        writes: WritePolicy::Workspace {
            roots: vec![root.clone()],
            scratch: root.clone(),
        },
        network: NetworkPolicy::Allow,
        hardening: OptionalHardening::Off,
    };
    let request = HarnessRequest {
        identity: identity.clone(),
        executable: NativePath::from_local(executable.clone())?,
        cwd: NativePath::from_local(root.clone())?,
        profile: se_store::Profile {
            provider: se_store::Provider::Claude,
            model: None,
            permission: se_store::PermissionProfile::WorkspaceWrite,
            named_profile: "default".into(),
            effort: None,
        },
        policy: policy.clone(),
        mode: LaunchMode::Headless,
        resume: Read::Absent {
            checked: "new protocol fixture".into(),
        },
        initial_input: Body::new("one bounded transport input")?,
        launch_credential: Secret::new(vec![17; 32])?,
        mcp_bearer: Secret::new(vec![19; 32])?,
        key: IdempotencyKey::new("independent-idle-close")?,
    };
    let conversation = se_host::claude_conversation(&request)?;
    let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
    let prepared = runtime
        .prepare_launch(
            LaunchReservation {
                format_version: 1,
                lifecycle: lifecycle.clone(),
                host,
                owner: current_process_identity(machine).map_err(native)?,
                generation,
                scope_nonce: nonce,
                parent: ReservationParent::Windows,
                created_at_unix_ns: 1,
            },
            LaunchSpec {
                lifecycle,
                generation,
                executable,
                arguments: vec![conversation.as_str().into()],
                cwd: root.clone(),
                environment: Environment { entries: vec![] },
                stdio: StandardIo {
                    stdin: None,
                    stdout: None,
                    stderr: None,
                },
                mode: LaunchMode::Headless,
                window: None,
                policy,
                deadline: Instant::now() + Duration::from_secs(20),
                notifications: Arc::new(Exit),
            },
        )
        .map_err(native)?;
    let mut scope = Scope {
        runtime: runtime.clone(),
        process: prepared.process,
        generation,
        released: false,
    };
    let streams = io.open(&scope.process, &identity)?;
    runtime
        .bind_stdio(&prepared.prepared, streams.child)
        .map_err(native)?;
    let ticket = match runtime.begin_launch(prepared.prepared) {
        LaunchStart::Pending { ticket, .. } => ticket,
        LaunchStart::Failed(failure) => return Err(native(failure.error).into()),
    };
    let end = Instant::now() + Duration::from_secs(10);
    let launched = loop {
        match runtime.poll_launch(&ticket).map_err(native)? {
            LaunchProgress::Started(started) => break started,
            LaunchProgress::Pending if Instant::now() < end => {
                std::thread::park_timeout(Duration::from_millis(2))
            }
            _ => return Err("native provider start pending".into()),
        }
    };
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    engine.block_on(async {
        let harness = ClaudeHarness::new(io, std::env::current_exe()?, root.clone(), 43210);
        harness
            .probe(
                ProbeRequest {
                    kind: HarnessKind::ClaudeCode,
                    command: request.executable.to_local()?,
                },
                context()?,
            )
            .await?;
        let outcome = harness
            .attach(
                HarnessAttach {
                    request,
                    process: launched.process,
                    record: launched.record,
                    transport: streams.host,
                    transcript: Read::Absent {
                        checked: "protocol fixture has no transcript".into(),
                    },
                },
                context()?,
            )
            .await?;
        let until = Instant::now() + Duration::from_secs(5);
        let pending = loop {
            let state = runtime
                .stdio_state(&scope.process)
                .map_err(native)?
                .ok_or("port vanished before close")?;
            if state.operations.len() == 2 {
                break state
                    .operations
                    .into_iter()
                    .map(|ticket| ticket.operation)
                    .collect::<Vec<_>>();
            }
            if Instant::now() >= until {
                return Err("both real idle drain operations were not observed".into());
            }
            tokio::task::yield_now().await;
        };
        // Single-thread runtime: stop/witness the child synchronously without polling
        // either drain again. Native completion can arrive, but its future still owns
        // the ticket when the real harness aborts and joins both tasks next.
        let _witness = scope.stop()?;
        let closed = harness.close_binding(&outcome.binding, context()?).await;
        let released = runtime
            .stdio_state(&scope.process)
            .map_err(native)?
            .is_none();
        scope.cleanup()?; // even a red result cannot leak kernel operations or a child
        assert!(
            closed.is_ok(),
            "real harness close lost idle operations {pending:?}: {closed:?}"
        );
        assert!(
            released,
            "harness reported closure but its exact native port remains"
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    // Only ordinary files were created here. Preserve the fixture on any failure.
    fs::remove_file(root.join("provider.exe"))?;
    fs::remove_file(root.join("provider.rs"))?;
    fs::remove_dir(root)?;
    Ok(())
}
