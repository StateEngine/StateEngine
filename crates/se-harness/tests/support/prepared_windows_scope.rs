//! Native prepared wrapper fixture: setup, endpoint binding and exact release.
use crate::test_directory as cleanup_directory;
use crate::{ProviderIoPlatform, ProviderTransport, SessionIdentity, WindowsProviderIo};
use se_proc::*;
use std::{
    fs,
    sync::Arc,
    time::{Duration, Instant as NativeInstant},
};
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(super) fn proc_error(error: ProcError) -> String {
    format!("{error:?}")
}
struct ExitNotices;
impl ExitSink for ExitNotices {
    fn notify(&self, _: ExitNotice) {}
}
pub(super) struct Fixture {
    pub(super) runtime: Arc<NativeProcessRuntime>,
    pub(super) owner: OwnedProcess,
    prepared: Option<PreparedLaunch>,
    generation: GenerationId,
    released: bool,
    root_owner: Option<cleanup_directory::PrivateDirectory>,
}
impl Fixture {
    pub(super) fn new() -> Check<Self> {
        let nonce: [u8; 16] = random_secret()?.expose()[..16].try_into()?;
        let root = std::env::temp_dir().join(format!("se-wrapper-{}", se_types::hex_lower(&nonce)));
        fs::create_dir(&root)?;
        let root_owner = cleanup_directory::PrivateDirectory::for_case(root.clone());
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
    pub(super) fn platform(&self) -> WindowsProviderIo<NativeProcessRuntime> {
        WindowsProviderIo::new(
            self.runtime.clone(),
            StdioLimits {
                max_read_bytes: 64,
                max_write_bytes: 64,
                max_buffer_bytes: 4096,
            },
        )
    }
    pub(super) fn bind(
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
    pub(super) fn finish(&self) -> Check {
        self.root_owner
            .as_ref()
            .ok_or("wrapper root owner absent")?
            .finish(Ok(()))
    }
    pub(super) fn release(&mut self) -> Check {
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
