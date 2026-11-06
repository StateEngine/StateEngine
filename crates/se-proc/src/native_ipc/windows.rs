use super::windows_security as security;
use super::*;
use std::{
    ffi::OsStr,
    io::{Read, Write},
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, OwnedHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::*,
    System::{IO::*, Pipes::*, Threading::*},
};
pub(super) fn owned(raw: HANDLE, operation: &'static str) -> IpcNativeResult<OwnedHandle> {
    crate::windows_native::handle(raw, operation).map_err(|e| error(e.operation, e.source))
}
fn wide(name: &OsStr) -> IpcNativeResult<Vec<u16>> {
    let value: Vec<_> = name.encode_wide().collect();
    let prefix: Vec<_> = OsStr::new(r"\\.\pipe\").encode_wide().collect();
    if !value.starts_with(&prefix)
        || value.len() <= prefix.len()
        || value.len() > 1024
        || value.contains(&0)
        || value[prefix.len()..]
            .iter()
            .any(|unit| *unit == b'\\' as u16 || *unit == b'/' as u16)
        || matches!(&value[prefix.len()..], [46] | [46, 46])
    {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "a bounded local named pipe is required",
        ));
    }
    Ok(value.into_iter().chain(Some(0)).collect())
}
fn create(name: &OsStr) -> IpcNativeResult<OwnedHandle> {
    let name = wide(name)?;
    let descriptor = security::descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let flags = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
    // SAFETY: the descriptor/string/attributes remain allocated for this call;
    // the returned noninheritable handle receives unique ownership below.
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            flags,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            &attributes,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let creation_error = io::Error::last_os_error();
        if matches!(creation_error.raw_os_error(), Some(code)
            if code == ERROR_ACCESS_DENIED as i32 || code == ERROR_PIPE_BUSY as i32)
        {
            let display = String::from_utf16_lossy(&name[..name.len().saturating_sub(1)]);
            let (code, reason) = match security::named_owner(&name) {
                Ok(sid) => (
                    IpcNativeErrorCode::AlreadyExists,
                    format!(
                        "first-instance pipe {display:?} already exists (owner SID {sid}); if it is yours, run se down for its data home, otherwise choose an unused protected name; this host will not adopt or remove it"
                    ),
                ),
                Err(owner_error) => (
                    IpcNativeErrorCode::Unreadable,
                    format!(
                        "first-instance pipe {display:?} refused creation ({creation_error}); owner SID is unreadable ({owner_error}); restore owner visibility or use an unused protected name; do not adopt or remove the existing name"
                    ),
                ),
            };
            return Err(IpcNativeError {
                code,
                operation: "create first owner-only IPC pipe",
                source: io::Error::new(io::ErrorKind::PermissionDenied, reason),
            });
        }
        return Err(error("create first owner-only IPC pipe", creation_error));
    }
    let handle = owned(raw, "create owner-only IPC pipe")?;
    security::verify(handle.as_raw_handle())?;
    Ok(handle)
}
pub struct NativePipeStream {
    handle: OwnedHandle,
    bound: IpcIoBound,
}
impl NativePipeStream {
    /// Synchronous stderr writer for the C/Rust standard-stream APIs. The
    /// parent peeks before reading; exactly one reader consumes this pipe.
    pub(crate) fn worker_stderr() -> IpcNativeResult<(std::fs::File, OwnedHandle)> {
        let descriptor = security::descriptor()?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 1,
        };
        let (mut reader, mut writer) = (ptr::null_mut(), ptr::null_mut());
        // SAFETY: owner-only descriptor, initialized handle outputs; ownership
        // transfers into RAII immediately after this successful native call.
        if unsafe { CreatePipe(&mut reader, &mut writer, &attributes, 65536) } == 0 {
            return Err(last("create worker stderr pipe"));
        }
        let reader = owned(reader, "own worker stderr reader")?;
        let writer = owned(writer, "own worker stderr writer")?;
        // SAFETY: only this retained reader loses inheritance; the closed
        // startup handle list contains its distinct writer alone.
        if unsafe { SetHandleInformation(reader.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(last("protect worker stderr reader"));
        }
        Ok((reader.into(), writer))
    }
    /// One connected owner-only pair for a private inherited worker channel.
    /// The caller inherits only the client duplicate through its closed handle list.
    pub(crate) fn worker_pair(bound: IpcIoBound) -> IpcNativeResult<(Self, OwnedHandle)> {
        let mut entropy = [0; 16];
        crate::fill_entropy(&mut entropy)
            .map_err(|e| error("allocate worker pipe name", io::Error::other(e)))?;
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let name = std::ffi::OsString::from(format!(r"\\.\pipe\se-atlas-cold-{suffix}"));
        let pair = NativePipeReservation::create(&name)?;
        let mut inherited = ptr::null_mut();
        // SAFETY: retained client and process pseudo handles; ownership of the
        // new inheritable duplicate transfers immediately into an OwnedHandle.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                pair._client.as_raw_handle(),
                GetCurrentProcess(),
                &mut inherited,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(last("duplicate private worker channel"));
        }
        Ok((
            Self {
                handle: pair._server,
                bound,
            },
            owned(inherited, "duplicate worker channel")?,
        ))
    }
    pub(crate) fn worker_inherited(
        handle: OwnedHandle,
        bound: IpcIoBound,
    ) -> IpcNativeResult<Self> {
        security::verify(handle.as_raw_handle())?;
        Ok(Self { handle, bound })
    }
    pub(crate) fn readable_bytes(&self) -> io::Result<usize> {
        let mut available = 0;
        // SAFETY: retained byte pipe and exact writable count; no read is issued.
        if unsafe {
            PeekNamedPipe(
                self.handle.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut available,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(available as usize)
    }
    pub fn connect(name: &OsStr, bound: IpcIoBound) -> IpcNativeResult<Self> {
        let name = wide(name)?;
        loop {
            let remaining = bound
                .remaining()
                .map_err(|e| error("connect IPC deadline", e))?;
            // Identification SQOS is present before connect, preventing a
            // squatter from impersonating this client with its full token.
            // SAFETY: the bounded native pipe name outlives CreateFile; Identification SQOS is set before connection.
            let raw = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    ptr::null_mut(),
                )
            };
            if raw != INVALID_HANDLE_VALUE {
                let handle = owned(raw, "open IPC pipe")?;
                security::verify(handle.as_raw_handle())?;
                let stream = Self { handle, bound };
                return Ok(stream);
            }
            // SAFETY: reads the error of the immediately preceding native call on this thread.
            // SAFETY: reads this thread's immediately preceding native operation error.
            let code = unsafe { GetLastError() };
            if code != ERROR_PIPE_BUSY {
                return Err(error(
                    "connect IPC pipe",
                    io::Error::from_raw_os_error(code as i32),
                ));
            }
            let milliseconds = remaining.as_millis().clamp(1, 10) as u32;
            // SAFETY: retained NUL-terminated pipe name and bounded native wait; no ownership transfers.
            if unsafe { WaitNamedPipeW(name.as_ptr(), milliseconds) } == 0 {
                // SAFETY: reads the error of the immediately preceding native call on this thread.
                // SAFETY: reads this thread's immediately preceding native operation error.
                let code = unsafe { GetLastError() };
                if code != ERROR_SEM_TIMEOUT {
                    return Err(error(
                        "wait IPC pipe",
                        io::Error::from_raw_os_error(code as i32),
                    ));
                }
            }
        }
    }
    pub fn channel(&self) -> BorrowedIpc<'_> {
        use std::os::windows::io::AsHandle;
        self.handle.as_handle()
    }
    pub fn set_bound(&mut self, bound: IpcIoBound) {
        self.bound = bound;
    }
    fn transfer(&mut self, buffer: PipeBuffer<'_>) -> io::Result<usize> {
        let length = match &buffer {
            PipeBuffer::Read(bytes) => bytes.len(),
            PipeBuffer::Write(bytes) => bytes.len(),
        };
        if length == 0 {
            return Ok(0);
        }
        self.bound.remaining()?;
        let event = owned(
            // SAFETY: null descriptor/name select a new noninherited unnamed event, uniquely owned by owned().
            unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) },
            "create IPC I/O event",
        )
        .map_err(|e| e.source)?;
        // SAFETY: zero is the documented initial OVERLAPPED state; the event
        // and stack record stay alive until this exact operation is drained.
        let mut operation: OVERLAPPED = unsafe { zeroed() };
        operation.hEvent = event.as_raw_handle();
        let length = length.min(u32::MAX as usize) as u32;
        // SAFETY: pointers come from the live borrowed slice, the unique pipe
        // handle remains owned, and wait drains OVERLAPPED before any return.
        let reading = matches!(&buffer, PipeBuffer::Read(_));
        let result = match buffer {
            // SAFETY: writable live slice and OVERLAPPED/event remain retained until wait drains this operation.
            PipeBuffer::Read(bytes) => unsafe {
                ReadFile(
                    self.handle.as_raw_handle(),
                    bytes.as_mut_ptr(),
                    length,
                    ptr::null_mut(),
                    &mut operation,
                )
            },
            // SAFETY: readable live slice and OVERLAPPED/event remain retained until wait drains this operation.
            PipeBuffer::Write(bytes) => unsafe {
                WriteFile(
                    self.handle.as_raw_handle(),
                    bytes.as_ptr(),
                    length,
                    ptr::null_mut(),
                    &mut operation,
                )
            },
        };
        if result == 0 {
            // SAFETY: reads the error of the immediately preceding native call on this thread.
            // SAFETY: reads this thread's immediately preceding native operation error.
            let code = unsafe { GetLastError() };
            if code != ERROR_IO_PENDING {
                if reading
                    && matches!(
                        code,
                        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_HANDLE_EOF
                    )
                {
                    return Ok(0);
                }
                return Err(io::Error::from_raw_os_error(code as i32));
            }
        }
        // The caller's slice and OVERLAPPED remain live until completion or
        // cancellation has been drained, including timeout/error paths.
        wait(self.handle.as_raw_handle(), &mut operation, &self.bound)
    }
}
fn wait(handle: HANDLE, operation: &mut OVERLAPPED, bound: &IpcIoBound) -> io::Result<usize> {
    loop {
        let mut count = 0;
        // SAFETY: live pipe and the same retained OVERLAPPED, with writable count output.
        if unsafe { GetOverlappedResult(handle, operation, &mut count, 0) } != 0 {
            return Ok(count as usize);
        }
        // SAFETY: reads this thread's immediately preceding native operation error.
        let code = unsafe { GetLastError() };
        if code != ERROR_IO_INCOMPLETE {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        let remaining = match bound.remaining() {
            Ok(value) => value,
            Err(reason) => {
                // SAFETY: cancellation targets this exact live operation. Joining
                // it before returning keeps its buffer/event/OVERLAPPED allocated.
                unsafe {
                    CancelIoEx(handle, operation);
                    GetOverlappedResult(handle, operation, &mut count, 1);
                }
                return if count > 0 {
                    Ok(count as usize)
                } else {
                    Err(reason)
                };
            }
        };
        // SAFETY: the event belongs to the retained operation and the wait is bounded by its original deadline.
        let outcome = unsafe {
            WaitForSingleObject(operation.hEvent, remaining.as_millis().clamp(1, 10) as u32)
        };
        if outcome == WAIT_FAILED {
            let reason = io::Error::last_os_error();
            // SAFETY: cancel and join this exact operation before its buffers/event can be dropped.
            unsafe {
                CancelIoEx(handle, operation);
                GetOverlappedResult(handle, operation, &mut count, 1);
            }
            return if count > 0 {
                Ok(count as usize)
            } else {
                Err(reason)
            };
        }
    }
}
enum PipeBuffer<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}
impl Read for NativePipeStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.transfer(PipeBuffer::Read(bytes))
    }
}
impl Write for NativePipeStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.transfer(PipeBuffer::Write(bytes))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.bound.remaining()?;
        Ok(())
    }
}
/// Reserves the first protected instance while an evented host creates later
/// instances through its existing reactor. The occupied reservation cannot
/// receive application calls. No Tokio dependency or handle ownership cast is
/// needed in the host: the named pipe's first-instance DACL protects its name.
pub struct NativePipeReservation {
    name: std::ffi::OsString,
    _server: OwnedHandle,
    _client: OwnedHandle,
}
impl NativePipeReservation {
    pub fn create(name: &OsStr) -> IpcNativeResult<Self> {
        let server = create(name)?;
        let path = wide(name)?;
        // SAFETY: the private first instance is held above, the native string
        // lives through CreateFile, and identification precedes connection.
        let client = owned(
            unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
                    0,
                    ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    ptr::null_mut(),
                )
            },
            "occupy protected IPC reservation",
        )?;
        security::verify(client.as_raw_handle())?;
        let mut pid = 0;
        // SAFETY: retained pipe handle and initialized writable PID output; this call grants no authority.
        if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &mut pid) } == 0 {
            return Err(last("verify IPC reservation server"));
        }
        if pid != std::process::id() {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "IPC reservation belongs to another process",
            ));
        }
        Ok(Self {
            name: name.to_owned(),
            _server: server,
            _client: client,
        })
    }
    pub fn name(&self) -> &OsStr {
        &self.name
    }
    /// Observes the current server-instance count through this retained first
    /// instance. One means only the reservation remains at this observation;
    /// greater counts are pending retirement, never permission to adopt or remove.
    /// The caller must stop creating instances and keep driving its reactor
    /// while cancelled overlapped operations release their retained handles.
    pub fn current_instances(&self, bound: &IpcIoBound) -> IpcNativeResult<u32> {
        bound
            .remaining()
            .map_err(|e| error("observe IPC reservation deadline", e))?;
        let mut instances = 0;
        // SAFETY: retained query-capable server handle and one writable DWORD;
        // every unused output is null. This neither connects nor adopts a name.
        if unsafe {
            GetNamedPipeHandleStateW(
                self._server.as_raw_handle(),
                ptr::null_mut(),
                &mut instances,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            )
        } == 0
        {
            return Err(last("read owned IPC pipe instance count"));
        }
        bound
            .remaining()
            .map_err(|e| error("observe IPC reservation deadline", e))?;
        if instances == 0 {
            return Err(error(
                "read owned IPC pipe instance count",
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "retained reservation returned zero instances",
                ),
            ));
        }
        Ok(instances)
    }
    /// Waits on the caller's blocking pool until only this reservation remains.
    /// Keep the reactor running and stop creating instances before this call.
    /// Success permits the owner to drop its reservation last. On failure the
    /// borrowed reservation is still owned by the caller: report pending release
    /// and retain it for reconciliation rather than claiming transport closure.
    /// Poll delays back off from 1 to 32 ms, clipped to the original deadline.
    pub fn wait_until_exclusive(&self, bound: &IpcIoBound) -> IpcNativeResult<()> {
        let mut delay = std::time::Duration::from_millis(1);
        loop {
            if self.current_instances(bound)? == 1 {
                return Ok(());
            }
            let remaining = bound
                .remaining()
                .map_err(|e| error("wait for owned IPC pipe retirement", e))?;
            std::thread::sleep(remaining.min(delay));
            delay = (delay * 2).min(std::time::Duration::from_millis(32));
        }
    }
    /// Read the actual evented instance back before it accepts any credential.
    /// If the platform ever creates a permissive descriptor instead of sharing
    /// the protected named-pipe object, this refuses and the host drops it.
    pub fn verify_reactor_instance(&self, channel: BorrowedIpc<'_>) -> IpcNativeResult<()> {
        security::verify(channel.as_raw_handle())?;
        let mut pid = 0;
        // SAFETY: retained pipe handle and initialized writable PID output; this call grants no authority.
        if unsafe { GetNamedPipeServerProcessId(channel.as_raw_handle(), &mut pid) } == 0 {
            return Err(last("verify evented IPC server"));
        }
        if pid != std::process::id() {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "evented pipe belongs to another server",
            ));
        }
        Ok(())
    }
}

pub(super) use super::windows_peer::{peer, self_peer, stop_server};
