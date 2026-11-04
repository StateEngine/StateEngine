//! Host-private detached startup. No agent may be admitted until the child
//! receives an exact lease/endpoint commit over its inherited private channel.
use crate::support::*;
use crate::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{self, Read},
    path::PathBuf,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as os;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as os;
mod diagnostics;
pub use diagnostics::RuntimeStartupStderr;
mod validation;
use validation::{endpoint_matches, validate_spec};

const ENTRY: &str = "--stateengine-private-runtime-bootstrap";
const MAX_FRAME: usize = 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Argument(#[serde(with = "crate::checkpoint::native_path")] PathBuf);
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    version: u32,
    parent: ProcessIdentity,
    nonce: [u8; 16],
    #[serde(with = "crate::checkpoint::decimal::u64")]
    deadline_ms: u64,
    arguments: Vec<Argument>,
    #[cfg(windows)]
    handles: [u64; 2],
}
/// Native self observation with the host's protected, persisted machine ID.
/// Machine identity is never invented from hostname, hardware or a new UUID.
pub fn current_process_identity(machine: MachineId) -> ProcResult<ProcessIdentity> {
    match crate::read_process(machine, ProcessId(std::process::id()))? {
        ProcessRead::Present(live) if live.state != NativeState::ExitedAwaitingReap => {
            Ok(live.identity)
        }
        _ => Err(input(
            "native self",
            "current process is absent or not executing",
        )),
    }
}
/// The persisted machine ID stays in process.machine. boot_id is read from
/// the native boot, suitable for the host's canonical lease/endpoint DTO.
pub struct NativeRuntimeIdentity {
    pub process: ProcessIdentity,
    pub boot_id: se_types::BootId,
}
pub fn current_runtime_identity(machine: MachineId) -> ProcResult<NativeRuntimeIdentity> {
    let process = current_process_identity(machine)?;
    let boot_id = os::boot_id()?;
    Ok(NativeRuntimeIdentity { process, boot_id })
}
fn check(deadline: Instant) -> ProcResult<()> {
    if Instant::now() >= deadline {
        Err(error(
            ProcErrorCode::LaunchTimedOut,
            ProcErrorDetail::Input {
                field: "runtime startup".into(),
                reason: "original startup deadline elapsed".into(),
            },
        ))
    } else {
        Ok(())
    }
}
fn frame_write(file: &mut File, bytes: &[u8], deadline: Instant) -> ProcResult<()> {
    if bytes.len() > MAX_FRAME {
        return Err(capacity("runtime frame bytes", MAX_FRAME as u64));
    }
    os::write(file, &(bytes.len() as u32).to_le_bytes(), deadline)?;
    os::write(file, bytes, deadline)
}
fn frame_read(file: &mut File, deadline: Instant) -> ProcResult<Vec<u8>> {
    let mut length = [0; 4];
    os::read(file, &mut length, deadline)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(capacity("runtime frame bytes", MAX_FRAME as u64));
    }
    let mut bytes = vec![0; length];
    os::read(file, &mut bytes, deadline)?;
    Ok(bytes)
}
struct Created {
    native: os::Child,
    events: File,
    authorization: File,
    detachment: RuntimeDetachment,
    plan: File,
    encoded: Vec<u8>,
    error: Option<ProcError>,
    diagnostics: diagnostics::Capture,
}
pub(crate) struct Parent {
    native: os::Child,
    events: File,
    authorization: Option<File>,
    nonce: [u8; 16],
    deadline: Instant,
    identity: Option<ProcessIdentity>,
    detachment: RuntimeDetachment,
    commit_sent: bool,
    released: bool,
    diagnostics: diagnostics::Capture,
}
impl RuntimeChild {
    /// Returns the retained stderr tail, waiting at most 250 ms and never past
    /// the supplied deadline. Incomplete, failed and complete-empty differ.
    pub fn startup_stderr(&self, deadline: Instant) -> ProcResult<RuntimeStartupStderr> {
        self.state.diagnostics.readback(deadline)
    }
    /// An ambiguous commit may have enabled admission. Core must reconcile the
    /// authenticated lease/endpoint; abort refuses after this point.
    pub fn commit_pending(&self) -> bool {
        self.state.commit_sent
    }
    pub fn identity(&self) -> Option<&ProcessIdentity> {
        self.state.identity.as_ref()
    }
}
/// This guard belongs only to the admitted private executable entry. Dropping
/// an uncommitted guard exits that bootstrap process, never its launching host.
pub struct RuntimeBootstrap {
    frame: Frame,
    events: File,
    authorization: File,
    identity: ProcessIdentity,
    deadline: Instant,
    committed: bool,
    diagnostics: File,
}
/// Child-side proof that the parent committed this exact ready owner.
pub struct RuntimeAdmission {
    pub identity: ProcessIdentity,
    pub host: HostInstanceId,
}
impl Drop for RuntimeBootstrap {
    fn drop(&mut self) {
        if !self.committed {
            std::process::exit(78);
        }
    }
}
impl RuntimeBootstrap {
    /// Invoke before parsing public CLI arguments or creating runtime threads.
    /// Its marker grants no authority; the native inherited channel does.
    pub fn from_process_entry() -> ProcResult<Option<Self>> {
        let args: Vec<_> = std::env::args_os().collect();
        if args.get(1).is_none_or(|a| a != ENTRY) {
            return Ok(None);
        }
        if args.len() != 2 {
            return Err(input(
                "runtime private entry",
                "no public arguments accepted",
            ));
        }
        let (frame, mut events, mut authorization, diagnostics, deadline) = os::receive()?;
        if frame.version != 1 || frame.nonce == [0; 16] || frame.arguments.len() > 1024 {
            return Err(input(
                "runtime envelope",
                "invalid version, nonce or argument bound",
            ));
        }
        let identity = current_process_identity(frame.parent.machine.clone())?;
        let bytes =
            serde_json::to_vec(&identity).map_err(|e| input("runtime identity", &e.to_string()))?;
        os::hello(&mut events, deadline)?;
        frame_write(&mut events, &bytes, deadline)?;
        // Do not expose the early-entry guard to host code until its parent
        // has retained and externally verified this exact native instance.
        // A fast guard drop can then never outrun acquisition of cleanup custody.
        let mut pinned = [0; 17];
        os::read(&mut authorization, &mut pinned, deadline)?;
        if pinned[0] != b'P' || pinned[1..] != frame.nonce {
            return Err(input(
                "runtime child pin",
                "exact parent pin acknowledgment required",
            ));
        }
        Ok(Some(Self {
            frame,
            events,
            authorization,
            identity,
            deadline,
            committed: false,
            diagnostics,
        }))
    }
    pub fn arguments(&self) -> impl ExactSizeIterator<Item = &std::ffi::OsStr> {
        self.frame.arguments.iter().map(|a| a.0.as_os_str())
    }
    pub fn identity(&self) -> &ProcessIdentity {
        &self.identity
    }
    pub fn startup_nonce(&self) -> [u8; 16] {
        self.frame.nonce
    }
    /// Writes only a fixed stage and already public/redacted refusal. Never
    /// supply credentials, raw arguments or the authenticated bootstrap frame.
    /// Public stdio remains detached; this bounded private stream is startup-only.
    pub fn report_startup_failure(&mut self, stage: &str, public_refusal: &str) -> ProcResult<()> {
        if self.committed {
            return Err(input("startup failure", "runtime already committed"));
        }
        let bytes = diagnostics::public_line(stage, public_refusal)?;
        // A refusal after the admission deadline still needs a finite chance
        // to reach its parent; this grants no additional admission time.
        os::write(
            &mut self.diagnostics,
            &bytes,
            Instant::now() + Duration::from_millis(100),
        )
    }
    /// The host has acquired its lease and authenticated endpoint, while still
    /// refusing agent admission. EOF, deadline or a different owner refuses.
    pub fn await_commit(mut self, host: HostInstanceId) -> ProcResult<RuntimeAdmission> {
        self.await_commit_retained(host)
    }
    /// Retains the guard so the host can close and retire its published listener
    /// before dropping an uncommitted guard after refusal. Only success supplies
    /// admission; the original deadline, checks and diagnostics are unchanged.
    /// An authenticated commit still precedes its ACK, including an ACK failure.
    pub fn await_commit_retained(&mut self, host: HostInstanceId) -> ProcResult<RuntimeAdmission> {
        if self.committed {
            return Err(input(
                "runtime ownership commit",
                "runtime already committed",
            ));
        }
        let result = self.receive_commit(host);
        if let Err(error) = &result
            && !self.committed
        {
            // Only fixed input descriptions/native operation names, never
            // nonce bytes, frames, supplied argv or credential material.
            let message = match error.detail.as_ref() {
                ProcErrorDetail::Input { field, reason } => format!("{field}: {reason}"),
                _ => format!("native ownership commit refused: {:?}", error.code),
            };
            let _ = self.report_startup_failure("await_commit", &message);
        }
        result
    }
    fn receive_commit(&mut self, host: HostInstanceId) -> ProcResult<RuntimeAdmission> {
        let mut command = [0; 33];
        os::read(&mut self.authorization, &mut command, self.deadline)?;
        if command[0] != b'C' || command[1..17] != self.frame.nonce || command[17..] != host.0 {
            return Err(input(
                "runtime ownership commit",
                "nonce or host instance differs from the child lease",
            ));
        }
        if current_process_identity(self.frame.parent.machine.clone())? != self.identity {
            return Err(input(
                "runtime ownership commit",
                "native child identity changed",
            ));
        }
        let mut acknowledgment = command;
        acknowledgment[0] = b'A';
        // Parent may disappear after authorizing this exact owner. Mark the
        // child committed before ACK: an ACK failure is ambiguous to the caller
        // and must never cause a blind kill of an admitting runtime.
        self.committed = true;
        os::write(&mut self.events, &acknowledgment, self.deadline)?;
        Ok(RuntimeAdmission {
            identity: self.identity.clone(),
            host,
        })
    }
}
impl NativeProcessApi for NativeProcessRuntime {
    fn read_process(machine: MachineId, pid: ProcessId) -> ProcResult<ProcessRead> {
        crate::read_process(machine, pid)
    }
    fn spawn_runtime(spec: RuntimeLaunchSpec) -> Result<RuntimeLaunch, Box<RuntimeSpawnFailure>> {
        let before = || -> ProcResult<Frame> {
            check(spec.deadline)?;
            validate_spec(&spec)?;
            if !spec.executable.is_absolute()
                || spec.startup_nonce == [0; 16]
                || spec.arguments.len() > 1024
                || spec.deadline.duration_since(Instant::now()) > Duration::from_secs(300)
            {
                return Err(input(
                    "runtime launch",
                    "absolute installed image, nonzero nonce and deadline within 300 seconds required",
                ));
            }
            Ok(Frame {
                version: 1,
                parent: current_process_identity(spec.machine.clone())?,
                nonce: spec.startup_nonce,
                deadline_ms: os::clock()?
                    .checked_add(
                        spec.deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis() as u64,
                    )
                    .ok_or_else(|| input("runtime deadline", "native clock overflow"))?,
                arguments: spec
                    .arguments
                    .iter()
                    .map(|a| Argument(PathBuf::from(a)))
                    .collect(),
                #[cfg(windows)]
                handles: [0; 2],
            })
        };
        let frame = before().map_err(|error| {
            Box::new(RuntimeSpawnFailure {
                error,
                remaining: None,
            })
        })?;
        let Created {
            native,
            events,
            authorization,
            detachment,
            mut plan,
            encoded,
            error: creation_error,
            diagnostics,
        } = os::spawn(&spec, frame).map_err(|error| {
            Box::new(RuntimeSpawnFailure {
                error,
                remaining: None,
            })
        })?;
        let mut child = RuntimeChild {
            state: Parent {
                native,
                events,
                authorization: Some(authorization),
                nonce: spec.startup_nonce,
                deadline: spec.deadline,
                identity: None,
                detachment,
                commit_sent: false,
                released: false,
                diagnostics,
            },
        };
        let result = (|| {
            child.state.identity = os::initial_identity(&child.state.native, &spec.machine)?;
            if let Some(cause) = creation_error {
                return Err(cause);
            }
            frame_write(&mut plan, &encoded, spec.deadline)?;
            drop(plan);
            let pid = os::receive_hello(
                &mut child.state.native,
                &mut child.state.events,
                spec.deadline,
            )?;
            // Establish exact cleanup custody before parsing any reported bytes.
            os::pin(&mut child.state.native, pid)?;
            let observed = match crate::read_process(spec.machine.clone(), pid)? {
                ProcessRead::Present(live) => live.identity,
                _ => return Err(input("runtime startup", "native child has already exited")),
            };
            child.state.identity = Some(observed.clone());
            let reported: ProcessIdentity =
                serde_json::from_slice(&frame_read(&mut child.state.events, spec.deadline)?)
                    .map_err(|e| input("runtime identity frame", &e.to_string()))?;
            if reported != observed {
                return Err(changed(&observed, Some(&reported)));
            }
            os::verify_image(&child.state.native, &spec.executable, &observed)?;
            os::settle_launcher(&mut child.state.native, spec.deadline)?;
            let mut pinned = [0; 17];
            pinned[0] = b'P';
            pinned[1..].copy_from_slice(&spec.startup_nonce);
            os::write(
                child.state.authorization.as_mut().ok_or_else(|| {
                    input("runtime child pin", "private authorization channel absent")
                })?,
                &pinned,
                spec.deadline,
            )?;
            Ok(observed)
        })();
        match result {
            Ok(identity) => Ok(RuntimeLaunch {
                detachment,
                child,
                identity,
            }),
            Err(error) => Err(Box::new(RuntimeSpawnFailure {
                error,
                remaining: Some(child),
            })),
        }
    }
    fn commit_runtime(
        mut child: RuntimeChild,
        proof: RuntimeReadyProof,
    ) -> Result<RuntimeReady, Box<RuntimeCommitFailure>> {
        let result = (|| {
            check(child.state.deadline)?;
            let identity = child
                .state
                .identity
                .as_ref()
                .ok_or_else(|| input("runtime commit", "native identity not yet proved"))?;
            if proof.startup_nonce != child.state.nonce
                || &proof.owner != identity
                || child.state.commit_sent
            {
                return Err(input(
                    "runtime commit",
                    "exact nonce/owner and uncommitted child required",
                ));
            }
            os::alive(&child.state.native, identity)?;
            endpoint_matches(&proof.endpoint, identity, child.state.deadline)?;
            let mut command = [0; 33];
            command[0] = b'C';
            command[1..17].copy_from_slice(&proof.startup_nonce);
            command[17..].copy_from_slice(&proof.host.0);
            child.state.commit_sent = true;
            os::write(
                child
                    .state
                    .authorization
                    .as_mut()
                    .ok_or_else(|| input("runtime commit", "authorization already closed"))?,
                &command,
                child.state.deadline,
            )?;
            let mut ack = [0; 33];
            os::read(&mut child.state.events, &mut ack, child.state.deadline)?;
            command[0] = b'A';
            if ack != command {
                return Err(input(
                    "runtime commit",
                    "child acknowledgment mismatch; reconcile ownership",
                ));
            }
            Ok(RuntimeReady {
                detachment: child.state.detachment,
                identity: identity.clone(),
                host: proof.host,
            })
        })();
        match result {
            Ok(ready) => Ok(ready),
            Err(error) => Err(Box::new(RuntimeCommitFailure { error, child })),
        }
    }
    fn abort_runtime(child: &mut RuntimeChild) -> ProcResult<()> {
        if child.state.commit_sent {
            return Err(input(
                "runtime abort",
                "ownership commit may have enabled admission; reconcile the authenticated lease first",
            ));
        }
        os::revoke(&child.state.events)?;
        child.state.authorization = None;
        os::abort(&mut child.state.native, child.state.identity.as_ref())
    }
    fn witness_runtime(child: &RuntimeChild) -> ProcResult<RuntimeExitObservation> {
        let identity = child.state.identity.as_ref().ok_or_else(|| {
            input(
                "runtime exit",
                "child native identity remains unproved; retain pending startup custody",
            )
        })?;
        os::witness(&child.state.native, identity)
    }
    fn release_runtime(child: &mut RuntimeChild, witness: &RuntimeExitWitness) -> ProcResult<()> {
        if child.state.released || child.state.identity.as_ref() != Some(&witness.identity) {
            return Err(input(
                "runtime release",
                "matching unreleased child and fresh exit witness required",
            ));
        }
        if !matches!(
            Self::witness_runtime(child)?,
            RuntimeExitObservation::Exited(_)
        ) {
            return Err(input("runtime release", "exact child still running"));
        }
        os::release(&mut child.state.native)?;
        child.state.released = true;
        child.state.authorization = None;
        Ok(())
    }
}
