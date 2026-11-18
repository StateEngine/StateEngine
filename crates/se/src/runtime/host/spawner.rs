//! Exact native identity for an explicitly spawner-bound runtime.
use se_proc::{ProcErrorCode, ProcessId, ProcessIdentity, StartIdentity};
use se_types::{MachineId, Result, SeError};
use std::time::Instant;

/// Authenticate the requested PID and native birth against the CLI's live parent.
/// The parent edge and both births are read again before returning.
pub(crate) fn resolve(
    machine: MachineId,
    value: &str,
    deadline: Instant,
) -> Result<ProcessIdentity> {
    let (pid, birth) = value.split_once(':').ok_or_else(invalid)?;
    let pid: u32 = pid.parse().map_err(|_| invalid())?;
    let birth: u64 = birth.parse().map_err(|_| invalid())?;
    if pid == 0 || birth == 0 {
        return Err(invalid());
    }
    let (_, parent) = se_proc::read_direct_parent_until(
        machine,
        ProcessId(std::process::id()),
        ProcessId(pid),
        deadline,
    )
    .map_err(|error| match error.code {
        ProcErrorCode::InvalidInput => invalid(),
        _ => se_core::scope::unreadable("spawner identity", &format!("{error:?}")),
    })?;
    let matches_birth = match &parent.start {
        StartIdentity::Linux { start_ticks } => *start_ticks == birth,
        StartIdentity::Windows { creation_filetime } => *creation_filetime == birth,
        StartIdentity::MacOs { .. } => false,
    };
    if !matches_birth {
        return Err(invalid());
    }
    Ok(parent)
}

fn invalid() -> SeError {
    SeError::invalid(
        "spawner identity",
        "the live direct parent as PID:BIRTH on Linux or Windows",
    )
}
