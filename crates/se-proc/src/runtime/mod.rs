mod arena;
mod launch_stop;
pub(crate) mod notify;
mod recovery;
mod validate;
#[cfg(target_os = "linux")]
mod window;

use crate::*;
pub(crate) use arena::{Arena, Reference, Slot, SlotEntry};

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

#[cfg(windows)]
mod stdio;
