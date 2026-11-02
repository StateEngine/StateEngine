use super::*;
use std::io::Write;
use std::{
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::{Console::*, Pipes::*, Threading::*},
};

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

pub(super) fn spawn(spec: &RuntimeLaunchSpec, mut frame: Frame) -> ProcResult<Created> {
    let image = crate::windows_native::open_image(&spec.executable, false).map_err(|e| {
        let mut error = fail("pin runtime executable", e.source);
        error.detail = Box::new(ProcErrorDetail::Executable {
            program: spec.executable.clone(),
        });
        error
    })?;
    let (plan_read, plan_write) = pipe()?;
    let (events, ready) = pipe()?;
    let (authorization, authorize) = pipe()?;
    let (diagnostic_reader, diagnostic_writer) = pipe()?;
    let diagnostics = diagnostics::Capture::start(diagnostic_reader, spec.deadline)?;
    // SAFETY: constant native current-process pseudo handle; output is uniquely owned on success.
    let parent = duplicate(unsafe { GetCurrentProcess() }, true)?;
    let auth = duplicate(authorization.as_raw_handle(), true)?;
    frame.handles = [
        parent.as_raw_handle() as usize as u64,
        auth.as_raw_handle() as usize as u64,
    ];
    let bytes = serde_json::to_vec(&frame).map_err(|e| input("runtime frame", &e.to_string()))?;
    if bytes.len() > MAX_FRAME {
        return Err(capacity("runtime frame bytes", MAX_FRAME as u64));
    }
    let input = duplicate(plan_read.as_raw_handle(), true)?;
    let output = duplicate(ready.as_raw_handle(), true)?;
    let error_stream = duplicate(diagnostic_writer.as_raw_handle(), true)?;
    let handles = [&parent, &auth, &input, &output, &error_stream];
    let inherited: Vec<_> = handles.iter().map(|h| h.as_raw_handle()).collect();
    let mut attributes = crate::windows_native::attributes::Attributes::new(
        1,
        "size runtime process attributes",
        "initialize runtime process attributes",
    )
    .map_err(|e| fail(e.operation, e.source))?;
    attributes
        .set(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            &inherited,
            "set runtime handle inheritance",
        )
        .map_err(|e| fail(e.operation, e.source))?;
    // SAFETY: startup and process outputs are native POD; used fields are initialized below.
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = input.as_raw_handle();
    startup.StartupInfo.hStdOutput = output.as_raw_handle();
    startup.StartupInfo.hStdError = error_stream.as_raw_handle();
    startup.lpAttributeList = attributes.pointer();
    let mut line: Vec<_> = format!("se {ENTRY}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let path: Vec<_> = spec
        .executable
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut sorted: Vec<_> = spec.environment.entries.iter().collect();
    sorted.sort_by_key(|(key, _)| key.to_string_lossy().to_uppercase());
    let mut environment = Vec::new();
    for (key, value) in sorted {
        environment.extend(key.encode_wide());
        environment.push(b'=' as u16);
        environment.extend(value.encode_wide());
        environment.push(0);
    }
    if environment.is_empty() {
        environment.push(0);
    }
    environment.push(0);
    // SAFETY: native process output POD is writable and owned only after successful creation.
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    // SAFETY: exact installed application, owned terminated argv/env, explicit
    // inherited handles and retained initialized native startup structure.
    let created = unsafe {
        CreateProcessW(
            path.as_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_BREAKAWAY_FROM_JOB
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            ptr::null(),
            &startup.StartupInfo,
            &mut info,
        )
    };
    let cause = io::Error::last_os_error();
    // Handles are about to close in the parent, regardless of native outcome.
    // Clearing their flags first also covers an independent later child spawn.
    let mut clear_error = None;
    for borrowed in handles {
        if let Err(cause) = clear(borrowed.as_raw_handle()) {
            clear_error.get_or_insert(cause);
        }
    }
    if created == 0 {
        return Err(native(
            if cause.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                ProcErrorCode::BreakawayDenied
            } else {
                ProcErrorCode::LaunchFailed
            },
            "create detached runtime outside caller jobs",
            cause,
        ));
    }
    // SAFETY: successful CreateProcessW transfers two valid independent owned
    // references. No fallible operation occurs before custody is returned.
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    // SAFETY: distinct valid thread reference returned by the same successful native call.
    let _thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };
    Ok(Created {
        native: Child {
            process: Some(process),
            pid: ProcessId(info.dwProcessId),
            image,
        },
        events,
        authorization: authorize,
        detachment: RuntimeDetachment::WindowsBreakaway,
        plan: plan_write,
        encoded: bytes,
        error: clear_error,
        diagnostics,
    })
}

pub(super) fn receive() -> ProcResult<(Frame, File, File, File, Instant)> {
    // SAFETY: static native standard-handle selectors; caller is the exact private early entry.
    let startup_stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut input = inherited(startup_stdin)?;
    // SAFETY: immutable type query on a retained private startup handle.
    if unsafe { GetFileType(input.as_raw_handle()) } != FILE_TYPE_PIPE {
        return Err(input_error());
    }
    let initial = Instant::now() + Duration::from_secs(300);
    let frame: Frame = serde_json::from_slice(&frame_read(&mut input, initial)?)
        .map_err(|e| crate::support::input("runtime frame", &e.to_string()))?;
    let remaining = frame
        .deadline_ms
        .checked_sub(clock()?)
        .filter(|n| *n > 0 && *n <= 300000)
        .ok_or_else(|| {
            crate::support::input("runtime deadline", "expired or outside startup bound")
        })?;
    let deadline = Instant::now() + Duration::from_millis(remaining);
    let parent = inherited(frame.handles[0] as usize as HANDLE)?;
    let authorize = inherited(frame.handles[1] as usize as HANDLE)?;
    // SAFETY: static stdout selector; inherited duplicates become noninheritable before any later child.
    let startup_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let events = inherited(startup_stdout)?;
    let actual_parent = crate::windows_native::parents()
        .map_err(|e| fail(e.operation, e.source))?
        .get(&std::process::id())
        .copied();
    if actual_parent != Some(frame.parent.pid.0) {
        return Err(input_error());
    }
    let expected_sid = crate::windows_native::process_sid(parent.as_raw_handle())
        .map_err(|e| fail(e.operation, e.source))?;
    // SAFETY: immutable current-process pseudo handle for native token observation.
    let own_sid = crate::windows_native::process_sid(unsafe { GetCurrentProcess() })
        .map_err(|e| fail(e.operation, e.source))?;
    // SAFETY: retained query/synchronize-capable actual parent reference.
    if unsafe { WaitForSingleObject(parent.as_raw_handle(), 0) } != WAIT_TIMEOUT
        || expected_sid != own_sid
    {
        return Err(input_error());
    }
    match crate::read_process(frame.parent.machine.clone(), frame.parent.pid)? {
        ProcessRead::Present(live) if live.identity == frame.parent => (),
        _ => return Err(input_error()),
    }
    // Standard handles must stop naming the private frame/ACK channels before
    // the host initializes logging or creates another process.
    // SAFETY: read-only standard handle selector in this private early entry.
    let stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    let diagnostics = inherited(stderr)?;
    // SAFETY: constant native null-device spelling and explicit noninheritance.
    let null = File::from(handle(
        unsafe {
            CreateFileW(
                [b'N' as u16, b'U' as u16, b'L' as u16, 0].as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        },
        "open detached runtime standard streams",
    )?);
    for which in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let stream = duplicate(null.as_raw_handle(), false)?;
        // SAFETY: transfer one noninheritable null-device reference to the
        // standard-handle table of this private bootstrap process.
        if unsafe { SetStdHandle(which, stream.as_raw_handle()) } == 0 {
            return Err(last("detach runtime standard streams"));
        }
        use std::os::windows::io::IntoRawHandle;
        let _table_reference = stream.into_raw_handle();
    }
    for original in [startup_stdin, startup_stdout, stderr] {
        // SAFETY: each distinct startup handle was duplicated into a retained
        // private File, cleared of inheritance and replaced in the stdio table.
        // Closing the old stderr writer is necessary for an honest later EOF.
        if unsafe { CloseHandle(original) } == 0 {
            return Err(last("close replaced runtime startup standard handle"));
        }
    }
    Ok((frame, events, authorize, diagnostics, deadline))
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
fn input_error() -> ProcError {
    input(
        "runtime private entry",
        "inherited pipe and live exact same-user native creator required",
    )
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
