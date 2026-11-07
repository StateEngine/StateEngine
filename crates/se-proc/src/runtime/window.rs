//! The backend is covered by the first C2. The root's console argv is staged
//! separately and must be durably recorded by the host before its final permit.
use super::*;
use crate::support::*;
use std::ffi::OsString;

impl NativeProcessRuntime {
    /// The exact viewer retained before the provider was allowed to execute.
    /// Recovered custody without that observation does not invent a viewer.
    pub fn window_viewer(&self, process: &OwnedProcess) -> ProcResult<Option<ProcessIdentity>> {
        self.inner.apply(&process.key, true, |slot| {
            Ok(slot.native()?.window_viewer())
        })
    }
    pub fn prepare_window_exec(
        &self,
        process: &OwnedProcess,
        arguments: Vec<OsString>,
    ) -> ProcResult<(RootCheckpoint, [u8; 32])> {
        self.inner.apply(&process.key, false, |slot| {
            if slot.phase != LifecycleState::Starting || std::time::Instant::now() >= slot.deadline
            {
                return Err(input(
                    "console exec",
                    "requires a pending launch within its original deadline",
                ));
            }
            let root = slot
                .root_checkpoint
                .clone()
                .ok_or_else(|| input("console exec", "the original root must be checkpointed"))?;
            let digest = slot.native()?.prepare_window_exec(&arguments)?;
            slot.argv_sha256 = digest;
            Ok((root, digest))
        })
    }
    pub fn authorize_window_exec(&self, process: &OwnedProcess) -> ProcResult<()> {
        self.inner.apply(&process.key, false, |slot| {
            if slot.phase != LifecycleState::Starting || std::time::Instant::now() >= slot.deadline
            {
                return Err(input(
                    "console exec",
                    "requires a pending launch within its original deadline",
                ));
            }
            slot.native()?.authorize_window_exec()
        })
    }
}
