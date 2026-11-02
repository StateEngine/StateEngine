use super::*;
use std::{fs::File, os::windows::io::FromRawHandle, ptr};
use windows_sys::Win32::{
    Storage::FileSystem::*,
    System::{IO::*, Pipes::*},
};

pub(super) fn initialize(port: &NativeStdio) -> ProcResult<StandardIo> {
    let mut child = [None, None, None];
    for (index, endpoint) in child.iter_mut().enumerate() {
        *endpoint = Some(pair(port, index)?);
    }
    Ok(StandardIo {
        stdin: child[0].take(),
        stdout: child[1].take(),
        stderr: child[2].take(),
    })
}
fn pair(port: &NativeStdio, index: usize) -> ProcResult<File> {
    let random = crate::random_secret().map_err(|e| {
        native(
            ProcErrorCode::LaunchFailed,
            "random provider pipe name",
            std::io::Error::other(e.to_string()),
        )
    })?;
    let name = wide(std::ffi::OsStr::new(&format!(
        r"\\.\pipe\se-provider-{}",
        se_types::hex_lower(random.expose())
    )));
    let security = super::super::security::Security::owner_only()?;
    let attributes = security.attributes();
    let access = if index == 0 {
        PIPE_ACCESS_OUTBOUND
    } else {
        PIPE_ACCESS_INBOUND
    };
    // SAFETY: private CSPRNG first-instance byte pipe; the descriptor and name
    // backing remain live for creation. The returned handle is immediately owned.
    let server = Handle::new(
        unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                access | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                &attributes,
            )
        },
        "create provider byte pipe",
    )?;
    let queue = port.queue()?;
    // SAFETY: server and the one host IOCP are retained; no skip-success mode is set.
    if unsafe { CreateIoCompletionPort(server.0, queue.handle.0, queue.key, 0) }.is_null() {
        return Err(last(
            ProcErrorCode::LaunchFailed,
            "associate provider pipe with IOCP",
        ));
    }
    let mut state = port.lock();
    state.handles[index] = Some(server);
    let desired = if index == 0 {
        GENERIC_READ
    } else {
        GENERIC_WRITE
    };
    // SAFETY: matching synchronous client endpoint, noninheritable until the
    // launch backend duplicates exactly the supplied standard-stream handles.
    let client = Handle::new(
        unsafe {
            CreateFileW(
                name.as_ptr(),
                desired,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        },
        "open provider child endpoint",
    )?;
    let id = state.next_id()?;
    let mut operation = Operation::new(Kind::Connect(index), Vec::new(), None);
    let address = operation.address();
    state.operations.insert(id, operation);
    let server = state.handles[index]
        .as_ref()
        .ok_or_else(|| input("stdio", "pipe creation lost its owner"))?;
    // SAFETY: the boxed OVERLAPPED was installed in retained arena storage
    // before dispatch. It remains there for any accepted completion packet.
    let ok = unsafe { ConnectNamedPipe(server.0, address as *mut OVERLAPPED) };
    // SAFETY: immediate thread-local status, before any other native operation.
    let code = if ok == 0 {
        // SAFETY: immediate thread-local status from the native call.
        unsafe { GetLastError() }
    } else {
        ERROR_SUCCESS
    };
    if ok == 0 && code != ERROR_IO_PENDING {
        state.operations.remove(&id); // Native non-acceptance expects no packet.
        if code != ERROR_PIPE_CONNECTED {
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "connect provider pipe",
                std::io::Error::from_raw_os_error(code as i32),
            ));
        }
    }
    // A connected synchronous child is now ready; any successful/pending server
    // connect completion is internal and stays pinned until its actual packet.
    // SAFETY: ownership moves from the native RAII handle into File exactly once.
    Ok(unsafe { File::from_raw_handle(client.into_raw()) })
}
impl Handle {
    fn into_raw(mut self) -> std::os::windows::io::RawHandle {
        let handle = self.0;
        self.0 = ptr::null_mut();
        handle
    }
}
