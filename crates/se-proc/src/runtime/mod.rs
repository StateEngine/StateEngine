mod arena;
mod launch_stop;
pub(crate) use se_native_proc::notify;
mod observation;
mod reboot;
mod recovery;
pub(crate) use se_native_proc::validate;
#[cfg(target_os = "linux")]
mod window;

use crate::*;
pub(crate) use arena::{Arena, LaunchState, Reference, Slot, SlotEntry};

pub fn read_process(machine: MachineId, pid: ProcessId) -> ProcResult<ProcessRead> {
    crate::platform::read_process(machine, pid)
}

/// Read a process within the caller's original bound. Native image queries can
/// race teardown; wait for a conclusive observation without inferring exit
/// from an unreadable executable.
pub fn read_process_until(
    machine: MachineId,
    pid: ProcessId,
    deadline: std::time::Instant,
) -> ProcResult<ProcessRead> {
    if std::time::Instant::now() >= deadline {
        return Err(crate::support::input(
            "process observation",
            "original deadline elapsed",
        ));
    }
    crate::platform::read_process_until(machine, pid, deadline)
}

impl NativeProcessRuntime {
    /// Observe the retained process within the caller's original bound. An
    /// inaccessible image during native teardown is not proof of process exit.
    pub fn observe_until(
        &self,
        process: &OwnedProcess,
        deadline: std::time::Instant,
    ) -> ProcResult<OwnedObservation> {
        if std::time::Instant::now() >= deadline {
            return Err(crate::support::input(
                "owned process observation",
                "original deadline elapsed",
            ));
        }
        let root = self.describe(process)?.root;
        loop {
            #[cfg(all(test, windows))]
            let observed = owned_observation_tests::sample(self, process);
            #[cfg(not(all(test, windows)))]
            let observed = self.observe(process);
            let original = match observed {
                Ok(observed) => return Ok(observed),
                // A descendant may exec between image reads. Re-observe the
                // whole owned scope without renewing the caller's bound; root
                // image changes and birth replacement still refuse immediately.
                Err(error) if observation::settling(&error, &root) => error,
                Err(error) => return Err(error),
            };
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(original);
            }
            std::thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
            if std::time::Instant::now() >= deadline {
                return Err(original);
            }
        }
    }

    /// The exact native console server pinned through the original root's
    /// kernel console connection. Unreadable or changed associations refuse.
    #[cfg(windows)]
    pub fn window_viewer(&self, process: &OwnedProcess) -> ProcResult<Option<ProcessIdentity>> {
        self.inner
            .apply(&process.key, true, |slot| slot.native()?.window_viewer())
    }

    /// Read-only process query; no arena, watcher, random identity or runtime.
    pub fn read_process(machine: MachineId, pid: ProcessId) -> ProcResult<ProcessRead> {
        read_process(machine, pid)
    }

    pub fn read_process_until(
        machine: MachineId,
        pid: ProcessId,
        deadline: std::time::Instant,
    ) -> ProcResult<ProcessRead> {
        read_process_until(machine, pid, deadline)
    }
}

impl NativeProcessApi for NativeProcessRuntime {
    fn read_process(machine: MachineId, pid: ProcessId) -> ProcResult<ProcessRead> {
        se_native_proc::read_process(machine, pid)
    }
    fn spawn_runtime(spec: RuntimeLaunchSpec) -> Result<RuntimeLaunch, Box<RuntimeSpawnFailure>> {
        se_native_proc::bootstrap::spawn_runtime(spec)
    }
    fn commit_runtime(
        child: RuntimeChild,
        proof: RuntimeReadyProof,
    ) -> Result<RuntimeReady, Box<RuntimeCommitFailure>> {
        se_native_proc::bootstrap::commit_runtime(child, proof)
    }
    fn abort_runtime(child: &mut RuntimeChild) -> ProcResult<()> {
        se_native_proc::bootstrap::abort_runtime(child)
    }
    fn witness_runtime(child: &RuntimeChild) -> ProcResult<RuntimeExitObservation> {
        se_native_proc::bootstrap::witness_runtime(child)
    }
    fn release_runtime(child: &mut RuntimeChild, witness: &RuntimeExitWitness) -> ProcResult<()> {
        se_native_proc::bootstrap::release_runtime(child, witness)
    }
}

#[cfg(windows)]
mod stdio;

#[cfg(all(test, windows))]
mod owned_observation_tests;
