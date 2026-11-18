mod arena;
mod launch_stop;
pub(crate) mod notify;
mod observation;
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

/// Read the live child and its claimed direct parent within the original bound.
/// A retained Windows creator PID can be reused, so its current birth must also
/// precede the child's birth.
pub fn read_direct_parent_until(
    machine: MachineId,
    child: ProcessId,
    parent: ProcessId,
    deadline: std::time::Instant,
) -> ProcResult<(ProcessIdentity, ProcessIdentity)> {
    let missing =
        || crate::support::input("process parent", "expected the exact live direct parent");
    let read_live = |pid| match read_process_until(machine.clone(), pid, deadline)? {
        ProcessRead::Present(value)
            if !matches!(
                value.state,
                NativeState::Exited | NativeState::ExitedAwaitingReap
            ) =>
        {
            Ok(value)
        }
        _ => Err(missing()),
    };
    let read_edge = |child: &LiveObservation| {
        #[cfg(windows)]
        let edge = crate::platform::read_parent(&child.identity);
        #[cfg(unix)]
        let edge = Ok(child.parent);
        edge
    };
    let before = read_live(child)?;
    if child == parent || read_edge(&before)? != Some(parent) {
        return Err(missing());
    }
    let parent = read_live(parent)?.identity;
    let after = read_live(child)?;
    let parent_again = read_live(parent.pid)?.identity;
    if before.identity != after.identity
        || parent != parent_again
        || read_edge(&after)? != Some(parent.pid)
        || parent.boot != after.identity.boot
    {
        return Err(missing());
    }
    if let (
        StartIdentity::Windows {
            creation_filetime: parent,
        },
        StartIdentity::Windows {
            creation_filetime: child,
        },
    ) = (&parent.start, &after.identity.start)
        && parent > child
    {
        return Err(missing());
    }
    Ok((after.identity, parent))
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

#[cfg(windows)]
mod stdio;

#[cfg(all(test, windows))]
mod owned_observation_tests;
