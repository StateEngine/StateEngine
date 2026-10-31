use super::windows_security as security;
use super::*;
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    mem::{size_of, zeroed},
    num::NonZeroU64,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::PathBuf,
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::*,
    System::{IO::*, Pipes::*, Threading::*},
};
fn owned(raw: HANDLE, operation: &'static str) -> IpcNativeResult<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(last(operation));
    }
    // SAFETY: the successful native allocation transfers one unique handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
fn wide(name: &OsStr) -> IpcNativeResult<Vec<u16>> {
    let value: Vec<_> = name.encode_wide().collect();
    let prefix: Vec<_> = OsStr::new(r"\\.\pipe\").encode_wide().collect();
    if !value.starts_with(&prefix)
        || value.len() <= prefix.len()
        || value.len() > 1024
        || value.contains(&0)
    {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "a bounded local named pipe is required",
        ));
    }
    Ok(value.into_iter().chain(Some(0)).collect())
}
fn create(name: &OsStr, first: bool) -> IpcNativeResult<OwnedHandle> {
    let name = wide(name)?;
    let descriptor = security::descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let flags = PIPE_ACCESS_DUPLEX
        | FILE_FLAG_OVERLAPPED
        | if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
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
    let handle = owned(raw, "create owner-only IPC pipe")?;
    security::verify(handle.as_raw_handle())?;
    Ok(handle)
}
/// One pending instance remains held while accepted instances are in use.
/// First-instance collision refuses; no existing pipe is adopted or removed.
pub struct NativePipeEndpoint {
    name: std::ffi::OsString,
    pending: OwnedHandle,
}
impl NativePipeEndpoint {
    pub fn bind(name: &OsStr) -> IpcNativeResult<Self> {
        Ok(Self {
            name: name.to_owned(),
            pending: create(name, true)?,
        })
    }
    pub fn accept(&mut self, bound: IpcIoBound) -> IpcNativeResult<NativePipeStream> {
        let event = owned(
            unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) },
            "create IPC connect event",
        )?;
        // SAFETY: zero is the documented initial OVERLAPPED state; the event
        // and stack record stay alive until this exact operation is drained.
        let mut operation: OVERLAPPED = unsafe { zeroed() };
        operation.hEvent = event.as_raw_handle();
        let connected = unsafe { ConnectNamedPipe(self.pending.as_raw_handle(), &mut operation) };
        if connected == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_IO_PENDING {
                wait(self.pending.as_raw_handle(), &mut operation, &bound)
                    .map_err(|e| error("accept IPC client", e))?;
            } else if code != ERROR_PIPE_CONNECTED {
                return Err(error(
                    "accept IPC client",
                    io::Error::from_raw_os_error(code as i32),
                ));
            }
        }
        let next = create(&self.name, false)?;
        let handle = std::mem::replace(&mut self.pending, next);
        let stream = NativePipeStream { handle, bound };
        peer(stream.channel(), IpcPeerSide::Client)?;
        Ok(stream)
    }
}
pub struct NativePipeStream {
    handle: OwnedHandle,
    bound: IpcIoBound,
}
impl NativePipeStream {
    pub fn connect(name: &OsStr, bound: IpcIoBound) -> IpcNativeResult<Self> {
        let name = wide(name)?;
        loop {
            let remaining = bound
                .remaining()
                .map_err(|e| error("connect IPC deadline", e))?;
            // Identification SQOS is present before connect, preventing a
            // squatter from impersonating this client with its full token.
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
            let code = unsafe { GetLastError() };
            if code != ERROR_PIPE_BUSY {
                return Err(error(
                    "connect IPC pipe",
                    io::Error::from_raw_os_error(code as i32),
                ));
            }
            let milliseconds = remaining.as_millis().clamp(1, 10) as u32;
            if unsafe { WaitNamedPipeW(name.as_ptr(), milliseconds) } == 0 {
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
            PipeBuffer::Read(bytes) => unsafe {
                ReadFile(
                    self.handle.as_raw_handle(),
                    bytes.as_mut_ptr(),
                    length,
                    ptr::null_mut(),
                    &mut operation,
                )
            },
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
        if unsafe { GetOverlappedResult(handle, operation, &mut count, 0) } != 0 {
            return Ok(count as usize);
        }
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
        let outcome = unsafe {
            WaitForSingleObject(operation.hEvent, remaining.as_millis().clamp(1, 10) as u32)
        };
        if outcome == WAIT_FAILED {
            let reason = io::Error::last_os_error();
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
pub(super) fn peer(channel: BorrowedIpc<'_>, side: IpcPeerSide) -> IpcNativeResult<NativeIpcPeer> {
    let mut pid = 0;
    let ok = match side {
        IpcPeerSide::Client => unsafe {
            GetNamedPipeClientProcessId(channel.as_raw_handle(), &mut pid)
        },
        IpcPeerSide::Server => unsafe {
            GetNamedPipeServerProcessId(channel.as_raw_handle(), &mut pid)
        },
    };
    if ok == 0 {
        return Err(last("read native pipe peer process ID"));
    }
    observe(pid)
}
pub(super) fn self_peer() -> IpcNativeResult<NativeIpcPeer> {
    observe(std::process::id())
}
fn observe(pid: u32) -> IpcNativeResult<NativeIpcPeer> {
    // SAFETY: query-only process pin, no inherited handle or native mutation.
    let process = owned(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) },
        "pin IPC peer process",
    )?;
    let sid = security::process_sid(process.as_raw_handle())?;
    if sid != security::current_sid()? {
        return Err(refuse(
            IpcNativeErrorCode::UnsafeEndpoint,
            "IPC peer process SID differs from current user",
        ));
    }
    let mut creation = unsafe { zeroed() };
    let mut exit = unsafe { zeroed() };
    let mut kernel = unsafe { zeroed() };
    let mut user = unsafe { zeroed() };
    // SAFETY: one pinned process and four aligned stack FILETIME outputs.
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(last("read peer process creation clock"));
    }
    let creation_filetime = NonZeroU64::new(
        (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime),
    )
    .ok_or_else(|| {
        refuse(
            IpcNativeErrorCode::Unreadable,
            "invalid native process birth",
        )
    })?;
    let mut image = vec![0; 32768];
    let mut length = image.len() as u32;
    // SAFETY: retained bounded UTF-16 output buffer and native process pin.
    if unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), 0, image.as_mut_ptr(), &mut length)
    } == 0
    {
        return Err(last("read IPC peer executable"));
    }
    image.truncate(length as usize);
    let image = PathBuf::from(std::ffi::OsString::from_wide(&image));
    let image_sha256 =
        hash_image(File::open(&image).map_err(|e| error("pin IPC peer executable", e))?)?;
    let mut status = 0;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut status) } == 0 {
        return Err(last("reobserve IPC peer liveness"));
    }
    if status != STILL_ACTIVE as u32 {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "IPC peer exited during identity readback",
        ));
    }
    Ok(NativeIpcPeer {
        principal: IpcPrincipal::Windows { sid },
        pid,
        started: StartIdentity::Windows { creation_filetime },
        image: native_path(&image)?,
        image_sha256,
    })
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
        let server = create(name, true)?;
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
    /// Read the actual evented instance back before it accepts any credential.
    /// If the platform ever creates a permissive descriptor instead of sharing
    /// the protected named-pipe object, this refuses and the host drops it.
    pub fn verify_reactor_instance(&self, channel: BorrowedIpc<'_>) -> IpcNativeResult<()> {
        security::verify(channel.as_raw_handle())?;
        let mut pid = 0;
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
