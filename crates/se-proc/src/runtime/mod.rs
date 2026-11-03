mod arena;
mod launch_stop;
pub(crate) mod notify;
mod recovery;
mod validate;

use crate::*;
pub(crate) use arena::{Arena, Reference, Slot};

pub fn read_process(machine: MachineId, pid: ProcessId) -> ProcResult<ProcessRead> {
    crate::platform::read_process(machine, pid)
}

impl NativeProcessRuntime {
    /// Read-only process query; no arena, watcher, random identity or runtime.
    pub fn read_process(machine: MachineId, pid: ProcessId) -> ProcResult<ProcessRead> {
        read_process(machine, pid)
    }
}

#[cfg(windows)]
mod stdio;
