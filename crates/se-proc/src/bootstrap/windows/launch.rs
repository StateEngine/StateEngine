use super::*;
use std::{
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
};

pub(in crate::bootstrap) fn spawn(
    spec: &RuntimeLaunchSpec,
    mut frame: Frame,
) -> ProcResult<Created> {
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

pub(in crate::bootstrap) fn receive() -> ProcResult<(Frame, File, File, File, Instant)> {
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

fn input_error() -> ProcError {
    input(
        "runtime private entry",
        "inherited pipe and live exact same-user native creator required",
    )
}
