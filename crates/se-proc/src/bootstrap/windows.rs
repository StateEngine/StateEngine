use super::*;
use std::io::Write;
use std::{
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::{Console::*, Pipes::*, Threading::*},
};
mod launch;
pub(super) use launch::{receive, spawn};

pub(super) struct Child {
    process: Option<OwnedHandle>,
    pid: ProcessId,
    image: File,
}
fn fail(api: &str, cause: io::Error) -> ProcError {
    native(ProcErrorCode::LaunchFailed, api, cause)
}
fn last(api: &str) -> ProcError {
    fail(api, io::Error::last_os_error())
}
fn handle(raw: HANDLE, api: &'static str) -> ProcResult<OwnedHandle> {
    crate::windows_native::handle(raw, api).map_err(|e| fail(e.operation, e.source))
}
fn duplicate(raw: HANDLE, inherit: bool) -> ProcResult<OwnedHandle> {
    let mut out = ptr::null_mut();
    // SAFETY: borrowed valid source, native current-process references and writable new-handle output.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut out,
            0,
            i32::from(inherit),
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(last("duplicate bootstrap handle"));
    }
    handle(out, "own bootstrap handle")
}
fn clear(raw: HANDLE) -> ProcResult<()> {
    // SAFETY: modifies only the inheritance bit of this retained local handle-table entry.
    if unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(last("clear bootstrap handle inheritance"));
    }
    Ok(())
}
fn inherited(raw: HANDLE) -> ProcResult<File> {
    let mut flags = 0;
    // SAFETY: native validates this inherited startup selector; no ownership assumed yet.
    if unsafe { GetHandleInformation(raw, &mut flags) } == 0 {
        return Err(last("inspect inherited bootstrap handle"));
    }
    if flags & HANDLE_FLAG_INHERIT == 0 {
        return Err(input(
            "runtime private entry",
            "startup handle was not inherited",
        ));
    }
    let owned = duplicate(raw, false)?;
    clear(raw)?;
    Ok(File::from(owned))
}
fn pipe() -> ProcResult<(File, File)> {
    let mut a = ptr::null_mut();
    let mut b = ptr::null_mut();
    // SAFETY: two initialized writable handle outputs; resulting handles are immediately owned.
    if unsafe { CreatePipe(&mut a, &mut b, ptr::null(), 4096) } == 0 {
        return Err(last("create runtime startup pipe"));
    }
    let read = File::from(handle(a, "own startup reader")?);
    let write = File::from(handle(b, "own startup writer")?);
    let mode = PIPE_NOWAIT;
    // SAFETY: private pipe write handle and exact native mode value. Nonblocking
    // writes preserve the single startup deadline even when a child stops reading.
    if unsafe { SetNamedPipeHandleState(write.as_raw_handle(), &mode, ptr::null(), ptr::null()) }
        == 0
    {
        return Err(last("bound runtime pipe writes"));
    }
    Ok((read, write))
}
pub(super) fn clock() -> ProcResult<u64> {
    // SAFETY: immutable machine monotonic clock; no pointers.
    Ok(unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() })
}
pub(super) fn read(file: &mut File, mut out: &mut [u8], deadline: Instant) -> ProcResult<()> {
    while !out.is_empty() {
        check(deadline)?;
        let mut available = 0;
        // SAFETY: retained private pipe and exact writable availability output; no bytes consumed.
        if unsafe {
            PeekNamedPipe(
                file.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut available,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(last("read runtime startup pipe"));
        }
        if available == 0 {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        let amount = out.len().min(available as usize);
        match file.read(&mut out[..amount]) {
            Ok(0) => {
                return Err(input(
                    "runtime startup channel",
                    "EOF before ownership commit",
                ));
            }
            Ok(n) => out = &mut out[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(fail("read runtime startup pipe", e)),
        }
    }
    Ok(())
}
pub(super) fn write(file: &mut File, mut bytes: &[u8], deadline: Instant) -> ProcResult<()> {
    while !bytes.is_empty() {
        check(deadline)?;
        match file.write(&bytes[..bytes.len().min(4096)]) {
            Ok(0) => std::thread::sleep(Duration::from_millis(1)),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.raw_os_error() == Some(ERROR_NO_DATA as i32) => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(e) => return Err(fail("write runtime startup pipe", e)),
        }
    }
    Ok(())
}

pub(super) fn read_diagnostics(
    file: &mut File,
    buffer: &mut [u8],
) -> ProcResult<diagnostics::ReadResult> {
    let mut available = 0;
    // SAFETY: this is the sole reader of a retained private anonymous pipe.
    if unsafe {
        PeekNamedPipe(
            file.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut available,
            ptr::null_mut(),
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
            return Ok(diagnostics::ReadResult::Eof);
        }
        return Err(fail("inspect runtime startup stderr", error));
    }
    if available == 0 {
        return Ok(diagnostics::ReadResult::Pending);
    }
    let amount = buffer.len().min(available as usize);
    // The sole reader consumes only bytes already reported available, so this
    // cannot wait on a live child. Oversized output is drained by the collector.
    match file.read(&mut buffer[..amount]) {
        Ok(0) => Ok(diagnostics::ReadResult::Eof),
        Ok(length) => Ok(diagnostics::ReadResult::Bytes(length)),
        Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => {
            Ok(diagnostics::ReadResult::Eof)
        }
        Err(error) => Err(fail("read runtime startup stderr", error)),
    }
}

pub(super) fn hello(events: &mut File, deadline: Instant) -> ProcResult<()> {
    write(events, b"R", deadline)
}
pub(super) fn receive_hello(
    child: &mut Child,
    events: &mut File,
    deadline: Instant,
) -> ProcResult<ProcessId> {
    let mut byte = [0];
    read(events, &mut byte, deadline)?;
    if byte != *b"R" {
        return Err(input(
            "runtime hello",
            "private child acknowledgment differs",
        ));
    }
    Ok(child.pid)
}
pub(super) fn pin(child: &mut Child, pid: ProcessId) -> ProcResult<()> {
    if child.pid != pid || child.process.is_none() {
        return Err(input(
            "runtime custody",
            "exact created native process reference required",
        ));
    }
    Ok(())
}
pub(super) fn verify_image(
    child: &Child,
    path: &std::path::Path,
    identity: &ProcessIdentity,
) -> ProcResult<()> {
    use crate::windows_native::{file_identity as file_id, open_image};
    let expected =
        file_id(&child.image).map_err(|e| fail("read pinned runtime image", e.source))?;
    let observed = open_image(&identity.image, false)
        .and_then(|f| file_id(&f))
        .map_err(|e| fail("read executed runtime image", e.source))?;
    let requested = open_image(path, false)
        .and_then(|f| file_id(&f))
        .map_err(|e| fail("read installed runtime image", e.source))?;
    if expected != observed || expected != requested {
        return Err(input(
            "runtime image",
            "native child is not the pinned installed executable",
        ));
    }
    Ok(())
}
pub(super) fn alive(child: &Child, identity: &ProcessIdentity) -> ProcResult<()> {
    let process = child
        .process
        .as_ref()
        .ok_or_else(|| input("runtime custody", "released native process"))?;
    // SAFETY: exact retained synchronize-capable native process reference.
    if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT {
        return Err(input(
            "runtime custody",
            "exact child exited or became unreadable",
        ));
    }
    let start = crate::windows_native::process_start(process.as_raw_handle())
        .map_err(|e| fail(e.operation, e.source))?;
    if identity.start
        != (StartIdentity::Windows {
            creation_filetime: start,
        })
    {
        return Err(changed(identity, None));
    }
    Ok(())
}
pub(super) fn abort(child: &mut Child, _identity: Option<&ProcessIdentity>) -> ProcResult<()> {
    let process = child
        .process
        .as_ref()
        .ok_or_else(|| input("runtime custody", "released native process"))?;
    // SAFETY: exact process returned by this startup; never a numeric PID or external job selector.
    if unsafe { TerminateProcess(process.as_raw_handle(), 1) } == 0 {
        let cause = io::Error::last_os_error();
        // SAFETY: zero-timeout query on the same retained exact process reference.
        if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_OBJECT_0 {
            return Err(fail("abort uncommitted runtime", cause));
        }
    }
    Ok(())
}
pub(super) fn witness(
    child: &Child,
    identity: &ProcessIdentity,
) -> ProcResult<RuntimeExitObservation> {
    let process = child
        .process
        .as_ref()
        .ok_or_else(|| input("runtime custody", "released native process"))?;
    // SAFETY: immutable zero-timeout query on the retained exact startup process.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_TIMEOUT => Ok(RuntimeExitObservation::Pending {
            identity: identity.clone(),
        }),
        WAIT_OBJECT_0 => {
            let mut status = 0;
            // SAFETY: process is independently signalled; status 259 is now a real exit status.
            if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut status) } == 0 {
                return Err(last("read runtime exit status"));
            }
            Ok(RuntimeExitObservation::Exited(Box::new(
                RuntimeExitWitness {
                    identity: identity.clone(),
                    evidence: ExitEvidence::KernelHandleSignalled,
                    status: ExitStatus::Code(status),
                    observed_at_unix_ns: now()?,
                },
            )))
        }
        _ => Err(last("observe runtime native exit")),
    }
}
pub(super) fn release(child: &mut Child) -> ProcResult<()> {
    child.process = None;
    Ok(())
}
pub(super) fn revoke(_events: &File) -> ProcResult<()> {
    Ok(())
}

pub(super) fn boot_id() -> ProcResult<se_types::BootId> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    #[repr(C)]
    struct BootEnvironment {
        identifier: windows_sys::core::GUID,
        firmware: u32,
        flags: u64,
    }
    type Query = unsafe extern "system" fn(i32, *mut std::ffi::c_void, u32, *mut u32) -> i32;
    let name: Vec<_> = "ntdll.dll".encode_utf16().chain(Some(0)).collect();
    // SAFETY: constant module name; ntdll is a system-owned process-lifetime module.
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    if module.is_null() {
        return Err(last("locate native boot query"));
    }
    // SAFETY: constant exported symbol and retained process-lifetime module.
    let address = unsafe { GetProcAddress(module, c"NtQuerySystemInformation".as_ptr().cast()) }
        .ok_or_else(|| input("runtime boot", "native boot query unavailable"))?;
    // SAFETY: this exact ntdll export has the documented NT system-information ABI.
    let query: Query = unsafe { std::mem::transmute(address) };
    // SAFETY: POD native output initialized to zero before the exact size query.
    let mut value: BootEnvironment = unsafe { zeroed() };
    let mut length = 0;
    // SAFETY: information class 90 returns SYSTEM_BOOT_ENVIRONMENT_INFORMATION;
    // aligned output uses the native GUID/firmware/flags layout and exact capacity.
    let status = unsafe {
        query(
            90,
            (&mut value as *mut BootEnvironment).cast(),
            size_of::<BootEnvironment>() as u32,
            &mut length,
        )
    };
    if status < 0 || length < 20 || length as usize > size_of::<BootEnvironment>() {
        return Err(input(
            "runtime boot",
            &format!("native boot environment unreadable: NTSTATUS {status:#x}, length {length}"),
        ));
    }
    let id = value.identifier;
    if id.data1 == 0 && id.data2 == 0 && id.data3 == 0 && id.data4 == [0; 8] {
        return Err(input("runtime boot", "native boot identifier is zero"));
    }
    let tail: String = se_types::hex_lower(&id.data4);
    se_types::BootId::new(format!(
        "windows:{:08x}-{:04x}-{:04x}-{tail}",
        id.data1, id.data2, id.data3
    ))
    .map_err(|e| input("runtime boot", &e.to_string()))
}

pub(super) fn initial_identity(
    child: &Child,
    machine: &MachineId,
) -> ProcResult<Option<ProcessIdentity>> {
    match crate::read_process(machine.clone(), child.pid)? {
        ProcessRead::Present(live) => Ok(Some(live.identity)),
        _ => Err(input(
            "runtime creation",
            "created native process exited before its identity could be read",
        )),
    }
}
pub(super) fn settle_launcher(_child: &mut Child, _deadline: Instant) -> ProcResult<()> {
    Ok(())
}
