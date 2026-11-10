//! One serialization point for grant admission, finite output enqueue and revoke.
//! No guard spans a network operation, store read/transaction, serialization or await.
use se_core::scope;
use se_types::Result;
use std::sync::{Arc, Mutex, MutexGuard, Weak};

const MAX_CONNECTIONS_PER_GRANT: usize = 32;

/// Implementations only discard bounded queued frames and signal cancellation.
/// They do not perform network I/O or wait for a reader/writer to exit.
pub trait OutputInvalidation: Send + Sync {
    fn invalidate(&self);
    /// True only after the connection task has closed its socket and dropped private output.
    fn closed(&self) -> bool;
}
struct State {
    open: bool,
    outputs: Vec<Weak<dyn OutputInvalidation>>,
}
pub(crate) struct GrantFence {
    state: Mutex<State>,
}
pub struct OutputFence<'a> {
    _guard: MutexGuard<'a, State>,
}

impl GrantFence {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                open: true,
                outputs: Vec::new(),
            }),
        }
    }
    /// The returned guard is not Clone or Send and cannot escape to an async writer.
    pub(crate) fn output(&self) -> Result<OutputFence<'_>> {
        let guard = self.state.lock().map_err(|_| {
            scope::unreadable(
                "remote grant fence",
                "grant fence poisoned; reconnect after resolving revocation",
            )
        })?;
        if !guard.open {
            return Err(scope::unreadable(
                "remote grant fence",
                "grant admission and output are fenced",
            ));
        }
        Ok(OutputFence { _guard: guard })
    }
    pub(crate) fn register(&self, output: &Arc<dyn OutputInvalidation>) -> Result<()> {
        let mut guard = self
            .state
            .lock()
            .map_err(|_| scope::unreadable("remote grant fence", "grant fence poisoned"))?;
        if !guard.open {
            return Err(scope::unreadable(
                "remote grant fence",
                "grant admission and output are fenced",
            ));
        }
        guard
            .outputs
            .retain(|v| v.upgrade().is_some_and(|output| !output.closed()));
        if guard.outputs.len() >= MAX_CONNECTIONS_PER_GRANT {
            return Err(super::super::channel::busy(
                "bounded grant connection capacity reached; close an existing connection",
            ));
        }
        guard.outputs.push(Arc::downgrade(output));
        Ok(())
    }
    pub(crate) fn outputs_closed(&self) -> Result<bool> {
        let guard = self
            .state
            .lock()
            .map_err(|_| scope::unreadable("remote output closure", "fence poisoned"))?;
        Ok(guard
            .outputs
            .iter()
            .filter_map(|v| v.upgrade())
            .all(|output| output.closed()))
    }
    /// Irreversible for this instance, including on a failed/unknown FULL revoke.
    /// A later socket cannot reactivate a cached fence merely by proving its key.
    pub(crate) fn revoke(&self) -> Result<()> {
        let mut guard = self.state.lock().map_err(|_| {
            scope::unreadable(
                "remote grant fence",
                "grant fence poisoned; admission remains refused",
            )
        })?;
        guard.open = false;
        guard
            .outputs
            .retain(|v| v.upgrade().is_some_and(|output| !output.closed()));
        for output in guard.outputs.iter().filter_map(|v| v.upgrade()) {
            output.invalidate()
        }
        Ok(())
    }
}
