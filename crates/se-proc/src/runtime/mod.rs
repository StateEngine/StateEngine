mod arena;
mod launch_stop;
pub(crate) mod notify;
mod recovery;
mod validate;

use crate::*;
pub(crate) use arena::{Arena, Reference, Slot, SlotEntry};

pub fn read_process(machine: MachineId, pid: ProcessId) -> ProcResult<ProcessRead> {
    crate::platform::read_process(machine, pid)
}

/// Read a process within the caller's original bound. Windows may temporarily
/// deny its image query during teardown; retain that process object and wait
/// for a conclusive observation rather than treating denial as proof of exit.
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
    #[cfg(windows)]
    return crate::platform::read_process_until(machine, pid, deadline);
    #[cfg(target_os = "linux")]
    read_process(machine, pid)
}

impl NativeProcessRuntime {
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
