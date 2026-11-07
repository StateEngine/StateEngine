use super::{Scope, identity::*};
use crate::support::*;
use crate::*;

pub(super) struct ConsoleHost {
    pin: Handle,
    identity: ProcessIdentity,
}

impl Scope {
    /// Exempt only the kernel console server associated with this exact root.
    /// The first observation retains its process object; later observations
    /// must join that same birth, image and still-current native association.
    pub fn window_viewer(&mut self) -> ProcResult<Option<ProcessIdentity>> {
        if !self.window {
            return Ok(None);
        }
        let child = self.child.as_ref().ok_or_else(|| {
            input(
                "console host inventory",
                "original root custody is unavailable",
            )
        })?;
        let root = child.identity.as_ref().ok_or_else(|| {
            input(
                "console host inventory",
                "original root identity is unpublished",
            )
        })?;
        let live_root = || -> ProcResult<()> {
            if !matches!(observe(root, &child.pin)?, ProcessObservation::Live(_)) {
                return Err(input(
                    "console host inventory",
                    "original root is no longer live; no console host can be exempted",
                ));
            }
            Ok(())
        };
        let server = || {
            crate::windows_native::console::server(child.pin.0, root.pid.0)
                .map(ProcessId)
                .map_err(|e| native(ProcErrorCode::ScopeUnreadable, e.operation, e.source))
        };
        live_root()?;
        let pid = server()?;
        if self.console_host.is_none() {
            let pin = lookup(pid)?.ok_or_else(|| {
                input(
                    "console host inventory",
                    "native console server disappeared before it could be pinned",
                )
            })?;
            let identity = identity(root.machine.clone(), pid, &pin)?;
            self.console_host = Some(ConsoleHost { pin, identity });
        }
        let host = self.console_host.as_ref().ok_or_else(|| {
            input(
                "console host inventory",
                "native console server pin is unavailable",
            )
        })?;
        if pid != host.identity.pid
            || !matches!(
                observe(&host.identity, &host.pin)?,
                ProcessObservation::Live(_)
            )
            || server()? != pid
        {
            return Err(input(
                "console host inventory",
                "native console server changed or exited; no process was stopped",
            ));
        }
        live_root()?;
        Ok(Some(host.identity.clone()))
    }
}
