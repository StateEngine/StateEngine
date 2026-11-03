use super::*;
use std::ptr;
use windows_sys::Win32::{
    Storage::FileSystem::{ReadFile, WriteFile},
    System::IO::{CancelIoEx, OVERLAPPED},
};

impl NativeStdio {
    pub fn read(&self, stream: StdioReadStream, maximum: u32) -> ProcResult<u64> {
        let mut state = self.lock();
        state.ready()?;
        if state.all_gated {
            return Err(transition("output close has begun"));
        }
        if maximum == 0 {
            return Err(input("read size", "positive byte count required"));
        }
        if maximum > state.limits.max_read_bytes {
            return Err(capacity(
                "provider read bytes",
                state.limits.max_read_bytes as u64,
            ));
        }
        let kind = Kind::Read(stream);
        if state.operations.values().any(|op| op.kind == kind) {
            return Err(transition(
                "read stream already owns an unreleased operation",
            ));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(maximum as usize)
            .map_err(|_| capacity("provider read allocation", maximum as u64))?;
        bytes.resize(maximum as usize, 0);
        let charge = self.admit_buffer(&state, &bytes, state.limits.max_read_bytes)?;
        self.submit(&mut state, kind, bytes, charge)
    }
    pub fn write(&self, bytes: Vec<u8>) -> Result<u64, StdioWriteRejection> {
        let mut state = self.lock();
        let validation = (|| {
            state.ready()?;
            if state.write_gated || state.all_gated {
                return Err(transition("stdin close has begun"));
            }
            if state.operations.values().any(|op| op.kind == Kind::Write) {
                return Err(transition("stdin already owns an unreleased write"));
            }
            if bytes.len() > u32::MAX as usize {
                return Err(capacity("provider write count", u32::MAX as u64));
            }
            let charge = self.admit_buffer(&state, &bytes, state.limits.max_write_bytes)?;
            // Check every fallible admission before moving the caller's buffer.
            let id = state.next_id()?;
            if state.handles[0].is_none() {
                return Err(transition("stdin endpoint is closed"));
            }
            Ok((charge, id))
        })();
        match validation {
            Err(error) => Err(StdioWriteRejection { error, bytes }),
            Ok((charge, id)) => {
                self.dispatch(&mut state, id, Kind::Write, bytes, charge);
                Ok(id)
            }
        }
    }
    fn admit_buffer(&self, state: &State, bytes: &Vec<u8>, maximum: u32) -> ProcResult<Charge> {
        let retained = state.retained_bytes();
        if bytes.capacity() > maximum as usize
            || bytes.capacity() > state.limits.max_buffer_bytes as usize
            || retained > state.limits.max_buffer_bytes as usize - bytes.capacity()
        {
            return Err(capacity(
                "provider stream buffer capacity",
                state.limits.max_buffer_bytes as u64,
            ));
        }
        self.budget.charge(bytes.capacity())
    }
    fn submit(
        &self,
        state: &mut State,
        kind: Kind,
        bytes: Vec<u8>,
        charge: Charge,
    ) -> ProcResult<u64> {
        let index = endpoint(kind);
        if state.handles[index].is_none() {
            return Err(transition("output endpoint is closed"));
        }
        let id = state.next_id()?;
        self.dispatch(state, id, kind, bytes, charge);
        Ok(id)
    }
    fn dispatch(&self, state: &mut State, id: u64, kind: Kind, bytes: Vec<u8>, charge: Charge) {
        let index = endpoint(kind);
        let Some(handle) = state.handles[index].as_ref() else {
            let mut operation = Operation::new(kind, bytes, Some(charge));
            operation.status = Status::Done {
                bytes: 0,
                code: ERROR_INVALID_HANDLE,
            };
            state.operations.insert(id, operation);
            state.notices.insert(id);
            self.nudge();
            return;
        };
        let handle = handle.0;
        let mut operation = Operation::new(kind, bytes, Some(charge));
        let address = operation.address();
        let data = operation.bytes.as_mut_ptr();
        let count = operation.bytes.len() as u32;
        state.operations.insert(id, operation);
        // SAFETY: stable boxed OVERLAPPED and Vec allocation were retained before
        // dispatch. No take/release can reclaim either while its packet is due.
        let ok = unsafe {
            if matches!(kind, Kind::Write) {
                WriteFile(
                    handle,
                    data,
                    count,
                    ptr::null_mut(),
                    address as *mut OVERLAPPED,
                )
            } else {
                ReadFile(
                    handle,
                    data,
                    count,
                    ptr::null_mut(),
                    address as *mut OVERLAPPED,
                )
            }
        };
        // SAFETY: immediately read the dispatch status on this submitting thread.
        let code = if ok == 0 {
            // SAFETY: immediate thread-local status from the native call.
            unsafe { GetLastError() }
        } else {
            ERROR_SUCCESS
        };
        if ok == 0 && code != ERROR_IO_PENDING {
            if let Some(operation) = state.operations.get_mut(&id) {
                operation.status = Status::Done { bytes: 0, code };
            }
            state.notices.insert(id);
            self.nudge();
        }
    }
    pub(super) fn complete_native(&self, address: usize, bytes: u32, code: u32) {
        let mut state = self.lock();
        let found = state.operations.iter_mut().find_map(|(id, operation)| {
            (operation.address() == address && operation.pending()).then_some(*id)
        });
        let Some(id) = found else {
            state.failure = Some(input(
                "stdio completion",
                "unknown or duplicate native completion address",
            ));
            return;
        };
        let Some(operation) = state.operations.get_mut(&id) else {
            return;
        };
        if matches!(operation.kind, Kind::Connect(_)) {
            state.operations.remove(&id);
            if code != ERROR_SUCCESS {
                state.failure = Some(native(
                    ProcErrorCode::LaunchFailed,
                    "provider pipe connection",
                    std::io::Error::from_raw_os_error(code as i32),
                ));
            }
        } else {
            operation.status = Status::Done { bytes, code };
            state.notices.insert(id);
        }
    }
    pub fn cancel_operation(&self, id: u64) -> ProcResult<StdioCancel> {
        let mut state = self.lock();
        let operation = state
            .operations
            .get_mut(&id)
            .ok_or_else(|| transition("unknown stream operation"))?;
        if !operation.pending() {
            return Ok(StdioCancel::AlreadyCompleted);
        }
        if matches!(operation.kind, Kind::Close(_)) {
            return Err(transition(
                "close control is not a cancellable native request",
            ));
        }
        let index = endpoint(operation.kind);
        let address = operation.address();
        let handle = state.handles[index]
            .as_ref()
            .ok_or_else(|| transition("pending request lost its endpoint"))?;
        Ok(cancel(handle, address))
    }
    pub(super) fn cancel_all(&self) {
        let mut state = self.lock();
        let requests = state
            .operations
            .values_mut()
            .filter(|op| op.pending() && !matches!(op.kind, Kind::Close(_)))
            .map(|op| (endpoint(op.kind), op.address()))
            .collect::<Vec<_>>();
        for (index, address) in requests {
            if let Some(handle) = state.handles[index].as_ref()
                && let StdioCancel::Failed(cause) = cancel(handle, address)
            {
                state.failure = Some(ProcError {
                    code: ProcErrorCode::StopIncomplete,
                    detail: Box::new(ProcErrorDetail::Input {
                        field: "stdio cancellation".into(),
                        reason: "native cancellation failed; requests remain retained".into(),
                    }),
                    native: Some(cause),
                });
            }
        }
    }
}
fn cancel(handle: &Handle, address: usize) -> StdioCancel {
    // SAFETY: immutable retained endpoint and stable pending OVERLAPPED address.
    if unsafe { CancelIoEx(handle.0, address as *const OVERLAPPED) } != 0 {
        return StdioCancel::Requested;
    }
    // SAFETY: immediate thread-local cancellation status.
    let code = unsafe { GetLastError() };
    if code == ERROR_NOT_FOUND {
        StdioCancel::Requested
    } else {
        StdioCancel::Failed(failure("CancelIoEx", code))
    }
}
pub(super) fn endpoint(kind: Kind) -> usize {
    match kind {
        Kind::Write => 0,
        Kind::Read(StdioReadStream::Stdout) => 1,
        Kind::Read(StdioReadStream::Stderr) => 2,
        Kind::Connect(index) => index,
        Kind::Close(_) => 0,
    }
}
