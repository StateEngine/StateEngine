//! Keep process-reader contracts callable on macOS without inventing liveness.
//! Native supervision is not implemented there; every observation refuses.
use crate::{
    MachineId, NativeProcessRuntime, ProcError, ProcErrorCode, ProcErrorDetail, ProcResult,
    ProcessId, ProcessRead,
};
use std::time::Instant;

fn unsupported() -> ProcError {
    ProcError {
        code: ProcErrorCode::UnsupportedPlatform,
        detail: Box::new(ProcErrorDetail::Input {
            field: "native process observation".into(),
            reason: "native process supervision is only implemented on Linux and Windows".into(),
        }),
        native: None,
    }
}

pub fn read_process(_machine: MachineId, _pid: ProcessId) -> ProcResult<ProcessRead> {
    Err(unsupported())
}

pub fn read_process_until(
    _machine: MachineId,
    _pid: ProcessId,
    _deadline: Instant,
) -> ProcResult<ProcessRead> {
    Err(unsupported())
}

impl NativeProcessRuntime {
    pub fn read_process(machine: MachineId, pid: ProcessId) -> ProcResult<ProcessRead> {
        read_process(machine, pid)
    }

    pub fn read_process_until(
        machine: MachineId,
        pid: ProcessId,
        deadline: Instant,
    ) -> ProcResult<ProcessRead> {
        read_process_until(machine, pid, deadline)
    }
}
