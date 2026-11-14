//! Real prepared Windows scopes and IOCP pipes; no provider process or H05 is
//! claimed. The child endpoints stay owned by the prepared launch until stop.
#[path = "../../../../../test-support/directory_owner.rs"]
mod cleanup_directory;
use super::*;
use se_proc::*;
use std::{fs, future::Future, task::Poll, time::Instant as NativeInstant};
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn proc_error(error: ProcError) -> String {
    format!("{error:?}")
}
fn context() -> Check<CallContext> {
    Ok(CallContext {
        generation: se_types::Generation::new(1)?,
        timeout: Duration::from_secs(5),
        cancellation: Arc::new(crate::CancellationState { _private: () }),
    })
}
struct ExitNotices;
impl ExitSink for ExitNotices {
    fn notify(&self, _: ExitNotice) {}
}
struct Fixture {
    runtime: Arc<NativeProcessRuntime>,
    owner: OwnedProcess,
    prepared: Option<PreparedLaunch>,
    generation: GenerationId,
    released: bool,
    root_owner: Option<cleanup_directory::PrivateDirectory>,
}
impl Fixture {
    fn new() -> Check<Self> {
        let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
        let root = std::env::temp_dir().join(format!("se-wrapper-{}", se_types::hex_lower(&nonce)));
        fs::create_dir(&root)?;
        let root_owner = cleanup_directory::PrivateDirectory::adopt(root.clone());
        let root = fs::canonicalize(root)?;
        let machine = MachineId::new("independent-wrapper-cancellation")?;
        let host = HostInstanceId(nonce);
        let generation = GenerationId::new(1)?;
        let lifecycle = LifecycleId::from_parts(1_700_000_000_000, nonce[..10].try_into()?)?;
        let runtime = Arc::new(
            NativeProcessRuntime::open(HostConfig {
                machine: machine.clone(),
                instance: host,
                helper_executable: std::env::current_exe()?,
                linux_delegation: LinuxDelegation::CurrentScope,
                limits: ResourceLimits {
                    max_lifecycles: 1,
                    max_diagnostic_members: 8,
                    max_observation_bytes: 65536,
                    max_stdio_buffer_bytes: 4096,
                },
            })
            .map_err(proc_error)?,
        );
        let prepared = runtime
            .prepare_launch(
                LaunchReservation {
                    format_version: 1,
                    lifecycle: lifecycle.clone(),
                    host,
                    owner: current_process_identity(machine).map_err(proc_error)?,
                    generation,
                    scope_nonce: nonce,
                    parent: ReservationParent::Windows,
                    created_at_unix_ns: 1,
                },
                LaunchSpec {
                    executable_custody: None,
                    lifecycle,
                    generation,
                    executable: std::env::current_exe()?,
                    arguments: vec![],
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
                    deadline: NativeInstant::now() + Duration::from_secs(30),
                    notifications: Arc::new(ExitNotices),
                },
            )
            .map_err(proc_error)?;
        Ok(Self {
            runtime,
            owner: prepared.process,
            prepared: Some(prepared.prepared),
            generation,
            released: false,
            root_owner: Some(root_owner),
        })
    }
    fn platform(&self) -> WindowsProviderIo<NativeProcessRuntime> {
        WindowsProviderIo::new(
            self.runtime.clone(),
            StdioLimits {
                max_read_bytes: 64,
                max_write_bytes: 64,
                max_buffer_bytes: 4096,
            },
        )
    }
    fn bind(
        &mut self,
        platform: &WindowsProviderIo<NativeProcessRuntime>,
    ) -> Check<ProviderTransport> {
        let identity = SessionIdentity {
            project: se_types::ProjectId::from_parts(1_700_000_000_000, [1; 10])?,
            agent: se_types::AgentId::from_parts(1_700_000_000_000, [2; 10])?,
            session: se_types::SessionId::from_parts(1_700_000_000_000, [3; 10])?,
        };
        // This public startup seam must work before any ProcessRecord exists.
        let io = platform
            .open(&self.owner, &identity)
            .map_err(|e| format!("prepared wrapper open refused before cancellation: {e}"))?;
        self.runtime
            .bind_stdio(
                self.prepared.as_ref().ok_or("prepared launch absent")?,
                io.child,
            )
            .map_err(proc_error)?;
        Ok(io.host)
    }
    fn release(&mut self) -> Check {
        if self.released {
            return Ok(());
        }
        let stop = self
            .runtime
            .prepare_stop(
                &self.owner,
                self.generation,
                NativeInstant::now() + Duration::from_secs(5),
            )
            .map_err(proc_error)?;
        self.runtime
            .request_stop(stop)
            .map_err(proc_error)?
            .dispatch
            .map_err(proc_error)?;
        let until = NativeInstant::now() + Duration::from_secs(5);
        loop {
            match self.runtime.witness_exit(&self.owner).map_err(proc_error)? {
                StopObservation::Complete(witness) => {
                    self.runtime
                        .release(&self.owner, &witness)
                        .map_err(proc_error)?;
                    break;
                }
                _ if NativeInstant::now() < until => {
                    std::thread::park_timeout(Duration::from_millis(2))
                }
                _ => return Err("prepared wrapper scope did not release".into()),
            }
        }
        if !self
            .runtime
            .arena_snapshot()
            .map_err(proc_error)?
            .entries
            .is_empty()
        {
            return Err("released wrapper still owns an arena entry".into());
        }
        self.released = true;
        Ok(())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = self.release()
            && let Some(root) = self.root_owner.take()
        {
            root.retain(&format!("prepared wrapper release failed: {error}"));
        }
    }
}
/// Poll once without replacing the real operation or its native completion.
async fn poll_once<F: Future + ?Sized>(future: std::pin::Pin<&mut F>) -> Option<F::Output> {
    let mut future = future;
    std::future::poll_fn(|cx| {
        Poll::Ready(match future.as_mut().poll(cx) {
            Poll::Pending => None,
            Poll::Ready(value) => Some(value),
        })
    })
    .await
}
/// Cleanup follows the native inventory only after recording the wrapper's
/// result. It cannot turn an unsuccessful consumer close into passing evidence.
async fn repair_for_cleanup(
    f: &Fixture,
    platform: &WindowsProviderIo<NativeProcessRuntime>,
    transport: &ProviderTransport,
) -> Check {
    let Some(state) = f.runtime.stdio_state(&f.owner).map_err(proc_error)? else {
        return Ok(());
    };
    let _ = f.runtime.begin_close(&state.port, StdioCloseScope::All);
    let state = f
        .runtime
        .stdio_state(&f.owner)
        .map_err(proc_error)?
        .ok_or("cleanup stream inventory disappeared")?;
    let mut witness = None;
    for ticket in state.operations {
        let _ = f.runtime.cancel(&ticket);
        let until = NativeInstant::now() + Duration::from_secs(5);
        loop {
            match f.runtime.take_completion(&ticket) {
                Ok(StdioCompletion::Pending) if NativeInstant::now() < until => {
                    tokio::time::sleep(Duration::from_millis(2)).await
                }
                Ok(StdioCompletion::Pending) => {
                    return Err("cleanup native completion stayed pending".into());
                }
                Ok(StdioCompletion::Close {
                    scope: StdioCloseScope::All,
                    result: Ok(closed),
                }) => {
                    witness = Some(closed);
                    break;
                }
                Ok(_) | Err(_) => break,
            }
        }
        f.runtime.release_operation(&ticket).map_err(proc_error)?;
    }
    if let Some(witness) = witness {
        f.runtime
            .release_stdio(&state.port, &witness)
            .map_err(proc_error)?;
    } else {
        platform.close(transport, context()?).await?;
    }
    Ok(())
}
async fn trial(cancel_close: bool) -> Check {
    let mut f = Fixture::new()?;
    let platform = f.platform();
    let transport = match f.bind(&platform) {
        Ok(transport) => transport,
        Err(error) => {
            f.release()?;
            return Err(error);
        }
    };
    let mut read = platform.read(
        &transport,
        ProviderStream::Output,
        NonZeroU32::new(16).ok_or("read bound")?,
        context()?,
    );
    if poll_once(read.as_mut()).await.is_some() {
        return Err("held child pipe did not produce an actual pending read".into());
    }
    let pending = f
        .runtime
        .stdio_state(&f.owner)
        .map_err(proc_error)?
        .ok_or("native read port absent")?;
    if pending.operations.is_empty() {
        return Err("wrapper read did not accept a native ticket".into());
    }
    if cancel_close {
        // The read still holds its wrapper stream lock, so close must await
        // either actual IOCP completion or that reader before it can finish.
        let mut close = platform.close(&transport, context()?);
        if let Some(result) = poll_once(close.as_mut()).await {
            return Err(format!("close did not suspend with a live reader: {result:?}").into());
        }
        drop(close);
        // Resume the real cancelled read, so only the close future was lost.
        let _ = read.await;
    } else {
        drop(read);
    }
    let outcome = platform.close(&transport, context()?).await;
    let inventory = f.runtime.stdio_state(&f.owner).map_err(proc_error)?;
    let correct = outcome.is_ok() && inventory.is_none();
    let diagnostic = format!(
        "outcome={outcome:?}; remaining native operations={}",
        inventory.as_ref().map_or(0, |state| state.operations.len())
    );
    let cleanup = if inventory.is_some() {
        repair_for_cleanup(&f, &platform, &transport).await
    } else {
        Ok(())
    };
    drop(transport);
    drop(platform);
    cleanup.map_err(|error| format!("original wrapper result: {diagnostic}; cleanup: {error}"))?;
    f.release()?;
    if !correct {
        return Err(format!(
            "cancelled {} future lost native ticket custody: {diagnostic}",
            if cancel_close { "close" } else { "read" }
        )
        .into());
    }
    Ok(())
}
/// Protects: close joins the operation accepted by a dropped reader future.
#[test]
fn independent_windows_wrapper_cancelled_read_releases_every_native_ticket() -> Check {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(trial(false))
}
/// Protects: accepted close custody survives cancellation and an ordinary retry.
#[test]
fn independent_windows_wrapper_cancelled_close_releases_every_native_ticket() -> Check {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        for _ in 0..8 {
            trial(true).await?;
        }
        Ok(())
    })
}
