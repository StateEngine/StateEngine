//! Safe arena-facing provider stream operations; native layouts stay in the
//! Windows backend and every reference is fenced by the process generation.
use super::*;
use crate::support::*;
use std::sync::Arc;

fn identity(slot: &Slot) -> StdioIdentity {
    StdioIdentity {
        lifecycle: slot.reservation.lifecycle.clone(),
        host: slot.reservation.host,
        generation: slot.generation,
    }
}
fn configured(slot: &Slot, config: &StdioConfig) -> ProcResult<()> {
    if identity(slot) != config.identity {
        return Err(input(
            "stdio identity",
            "exact owned lifecycle, host and generation required",
        ));
    }
    Ok(())
}
fn snapshot(native: &Arc<crate::platform::NativeStdio>, key: &Reference) -> StdioState {
    let (identity, binding, operations, stdin_closed, status) = native.snapshot();
    StdioState {
        port: StdioPort {
            key: key.clone(),
            binding,
        },
        operations: operations
            .into_iter()
            .map(|id| StdioTicket {
                operation: StdioOperationId(id),
                identity: identity.clone(),
                key: key.clone(),
                binding,
            })
            .collect(),
        stdin_closed,
        binding: status,
    }
}
impl NativeProcessRuntime {
    fn with_stdio<T>(
        &self,
        key: &Reference,
        binding: u64,
        cleanup: bool,
        run: impl FnOnce(&Arc<crate::platform::NativeStdio>) -> ProcResult<T>,
    ) -> ProcResult<T> {
        self.inner.apply(key, cleanup, |slot| {
            let native = slot
                .stdio
                .as_ref()
                .ok_or_else(|| input("stdio", "owned process has no stream port"))?;
            native.validate(&identity(slot), binding)?;
            run(native)
        })
    }
}
impl ProviderStdioApi for NativeProcessRuntime {
    fn create_stdio(&self, owner: &OwnedProcess, config: StdioConfig) -> ProcResult<ProviderStdio> {
        self.inner.apply(&owner.key, false, |slot| {
            let result = (|| {
                configured(slot, &config)?;
                if slot.launched
                    || slot.phase != LifecycleState::Starting
                    || slot.stdio.is_some()
                    || slot.stdio_bound
                {
                    return Err(state(
                        &owner.key.lifecycle,
                        slot.phase,
                        "create_stdio once before launch",
                    ));
                }
                if let Some(failure) = &slot.failure {
                    return Err(failure.clone());
                }
                if slot
                    .spec
                    .as_ref()
                    .is_none_or(|spec| spec.mode != LaunchMode::Headless)
                {
                    return Err(input("stdio mode", "headless prepared launch required"));
                }
                let native = self.inner.driver.create_stdio(&config)?;
                // Publish ownership before pipe creation: failures retain every
                // partial endpoint/request for stdio_state and ordinary cleanup.
                slot.stdio = Some(native.clone());
                let child = native.initialize()?;
                let (_, binding, _, _, _) = native.snapshot();
                Ok(ProviderStdio {
                    child,
                    port: StdioPort {
                        key: owner.key.clone(),
                        binding,
                    },
                })
            })();
            if !slot.launched
                && slot.phase == LifecycleState::Starting
                && let Err(failure) = &result
            {
                slot.failure = Some(failure.clone());
                if let Some(native) = &slot.stdio {
                    native.fail(failure.clone());
                }
            }
            result
        })
    }
    fn attach_stdio(&self, owner: &OwnedProcess, config: StdioConfig) -> ProcResult<StdioState> {
        self.inner.apply(&owner.key, true, |slot| {
            configured(slot, &config)?;
            let native = slot
                .stdio
                .as_ref()
                .ok_or_else(|| input("stdio", "no existing provider port to attach"))?;
            native.attach(&config)?;
            Ok(snapshot(native, &owner.key))
        })
    }
    fn stdio_state(&self, owner: &OwnedProcess) -> ProcResult<Option<StdioState>> {
        self.inner.apply(&owner.key, true, |slot| {
            Ok(slot
                .stdio
                .as_ref()
                .filter(|native| !native.released())
                .map(|native| snapshot(native, &owner.key)))
        })
    }
    fn begin_read(
        &self,
        port: &StdioPort,
        stream: StdioReadStream,
        max_bytes: u32,
    ) -> ProcResult<StdioTicket> {
        self.with_stdio(&port.key, port.binding, false, |native| {
            let operation = native.read(stream, max_bytes)?;
            let (identity, _, _, _, _) = native.snapshot();
            Ok(StdioTicket {
                operation: StdioOperationId(operation),
                identity,
                key: port.key.clone(),
                binding: port.binding,
            })
        })
    }
    fn begin_write(
        &self,
        port: &StdioPort,
        bytes: Vec<u8>,
    ) -> Result<StdioTicket, StdioWriteRejection> {
        // Retain the original buffer outside the arena closure until all
        // reference checks pass; even stale/foreign keys return it untouched.
        let mut retained = bytes;
        let result = self.with_stdio(&port.key, port.binding, false, |native| {
            let bytes = std::mem::take(&mut retained);
            match native.write(bytes) {
                Ok(operation) => {
                    let (identity, _, _, _, _) = native.snapshot();
                    Ok(StdioTicket {
                        operation: StdioOperationId(operation),
                        identity,
                        key: port.key.clone(),
                        binding: port.binding,
                    })
                }
                Err(failure) => {
                    let error = failure.error.clone();
                    retained = failure.bytes;
                    Err(error)
                }
            }
        });
        result.map_err(|error| StdioWriteRejection {
            error,
            bytes: retained,
        })
    }
    fn cancel(&self, ticket: &StdioTicket) -> ProcResult<StdioCancel> {
        self.with_stdio(&ticket.key, ticket.binding, true, |native| {
            native.validate(&ticket.identity, ticket.binding)?;
            native.cancel_operation(ticket.operation.0)
        })
    }
    fn take_completion(&self, ticket: &StdioTicket) -> ProcResult<StdioCompletion> {
        self.with_stdio(&ticket.key, ticket.binding, true, |native| {
            native.validate(&ticket.identity, ticket.binding)?;
            native.take(ticket.operation.0, ticket.binding)
        })
    }
    fn begin_close(&self, port: &StdioPort, scope: StdioCloseScope) -> ProcResult<StdioTicket> {
        self.with_stdio(&port.key, port.binding, true, |native| {
            let operation = native.close(scope)?;
            let (identity, _, _, _, _) = native.snapshot();
            Ok(StdioTicket {
                operation: StdioOperationId(operation),
                identity,
                key: port.key.clone(),
                binding: port.binding,
            })
        })
    }
    fn release_operation(&self, ticket: &StdioTicket) -> ProcResult<()> {
        self.with_stdio(&ticket.key, ticket.binding, true, |native| {
            native.validate(&ticket.identity, ticket.binding)?;
            native.release_operation(ticket.operation.0)
        })
    }
    fn release_stdio(&self, port: &StdioPort, witness: &StdioClosed) -> ProcResult<()> {
        self.with_stdio(&port.key, port.binding, true, |native| {
            native.release(witness, port.binding)
        })
    }
}
