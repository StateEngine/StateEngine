use super::identity::*;
use crate::support::*;
use crate::*;
use std::{
    ffi::OsStr,
    mem::{size_of, zeroed},
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{Foundation::*, Storage::FileSystem::*, System::Threading::*};

fn quoted(arg: &OsStr) -> Vec<u16> {
    let mut out = vec![b'"' as u16];
    let mut slashes = 0;
    for unit in arg.encode_wide() {
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        out.extend(std::iter::repeat_n(
            b'\\' as u16,
            if unit == b'"' as u16 {
                slashes * 2 + 1
            } else {
                slashes
            },
        ));
        slashes = 0;
        out.push(unit);
    }
    out.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    out.push(b'"' as u16);
    out
}

pub(super) struct Child {
    pub pin: Handle,
    pub identity: Option<ProcessIdentity>,
    pub pid: ProcessId,
}
pub(super) fn create(spec: LaunchSpec, job: &Handle) -> ProcResult<Child> {
    create_command(
        Command {
            executable: spec.executable,
            arguments: spec.arguments,
            environment: spec.environment,
            stdio: spec.stdio,
            mode: spec.mode,
            cwd: spec.cwd,
            capabilities: Vec::new(),
        },
        job,
    )
}
struct Command {
    executable: std::path::PathBuf,
    arguments: Vec<std::ffi::OsString>,
    environment: Environment,
    stdio: StandardIo,
    mode: LaunchMode,
    cwd: std::path::PathBuf,
    capabilities: Vec<Handle>,
}
pub(super) fn interrupt_helper(
    helper: &std::path::Path,
    root: &ProcessIdentity,
    root_pin: &Handle,
    job: &Handle,
) -> ProcResult<Child> {
    let cwd = helper
        .parent()
        .ok_or_else(|| input("console helper", "an absolute installed image"))?;
    let root_pin = capability(
        root_pin,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
    )?;
    let job_pin = capability(
        job,
        windows_sys::Win32::System::SystemServices::JOB_OBJECT_QUERY | READ_CONTROL,
    )?;
    let request = serde_json::to_string(&super::interrupt::Request {
        root: root.clone(),
        root_handle: root_pin.0 as usize as u64,
        job_handle: job_pin.0 as usize as u64,
    })
    .map_err(|_| input("console helper", "a serializable original identity"))?;
    if request.len() > 8192 {
        return Err(capacity("console helper identity bytes", 8192));
    }
    create_command(
        Command {
            executable: helper.to_owned(),
            arguments: vec![super::CONSOLE_INTERRUPT_ENTRY.into(), request.into()],
            environment: Environment {
                entries: Vec::new(),
            },
            stdio: StandardIo {
                stdin: None,
                stdout: None,
                stderr: None,
            },
            mode: LaunchMode::Headless,
            cwd: cwd.to_owned(),
            capabilities: vec![root_pin, job_pin],
        },
        job,
    )
}
fn capability(source: &Handle, rights: u32) -> ProcResult<Handle> {
    let mut copy = ptr::null_mut();
    // SAFETY: live original object, explicit reduced rights, unique inheritable
    // duplicate retained until atomic handle-list creation has completed.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source.0,
            GetCurrentProcess(),
            &mut copy,
            rights,
            1,
            0,
        )
    } == 0
    {
        return Err(last(
            ProcErrorCode::StopDispatchFailed,
            "duplicate console capability",
        ));
    }
    Handle::new(copy, "own console capability")
}
fn create_command(spec: Command, job: &Handle) -> ProcResult<Child> {
    let mut line = quoted(spec.executable.as_os_str());
    for arg in &spec.arguments {
        line.push(b' ' as u16);
        line.extend(quoted(arg));
    }
    line.push(0);
    if line.len() > 32767 {
        return Err(capacity("Windows command line UTF-16 units", 32767));
    }
    let mut environment = spec.environment.entries;
    environment.sort_by_key(|(key, _)| key.to_string_lossy().to_uppercase());
    let mut env = Vec::new();
    for (key, value) in environment {
        env.extend(key.encode_wide());
        env.push(b'=' as u16);
        env.extend(value.encode_wide());
        env.push(0);
    }
    if env.is_empty() {
        env.push(0);
    }
    env.push(0);
    // SAFETY: native startup POD starts zeroed; size and used fields are set below.
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    let streams = [spec.stdio.stdin, spec.stdio.stdout, spec.stdio.stderr];
    let redirected = streams.iter().any(Option::is_some);
    if spec.mode == LaunchMode::Window && redirected {
        return Err(unsupported(
            "partial/new-console redirection requires the terminal adapter; launch a window without redirections or use headless streams",
        ));
    }
    let mut inherited = Vec::new();
    if spec.mode.is_headless() {
        for stream in streams {
            let handle = if let Some(file) = stream {
                // Borrowed File owns this handle; duplicate without transferring it.
                let mut duplicate = ptr::null_mut();
                // SAFETY: the File and process pseudo handles outlive duplication;
                // output ownership transfers immediately into inherited's RAII handle.
                if unsafe {
                    DuplicateHandle(
                        GetCurrentProcess(),
                        file.as_raw_handle(),
                        GetCurrentProcess(),
                        &mut duplicate,
                        0,
                        1,
                        DUPLICATE_SAME_ACCESS,
                    )
                } == 0
                {
                    return Err(last(ProcErrorCode::LaunchFailed, "duplicate child stdio"));
                }
                Handle(duplicate)
            } else {
                // SAFETY: native security POD starts zeroed, with its size/inheritance filled next.
                let mut security: windows_sys::Win32::Security::SECURITY_ATTRIBUTES =
                    unsafe { zeroed() };
                security.nLength = size_of_val(&security) as u32;
                security.bInheritHandle = 1;
                // SAFETY: static null device name, explicit inheritance only for this duplicated stream.
                Handle::new(
                    // SAFETY: constant terminated null-device name and live attributes;
                    // only this explicit stream duplicate is inheritable.
                    unsafe {
                        CreateFileW(
                            wide(OsStr::new("NUL")).as_ptr(),
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            &security,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            ptr::null_mut(),
                        )
                    },
                    "open child null stream",
                )?
            };
            inherited.push(handle);
        }
        startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = inherited[0].0;
        startup.StartupInfo.hStdOutput = inherited[1].0;
        startup.StartupInfo.hStdError = inherited[2].0;
    }
    inherited.extend(spec.capabilities);
    let jobs = [job.0];
    let handles: Vec<_> = inherited.iter().map(|h| h.0).collect();
    let mut attributes = crate::windows_native::attributes::Attributes::new(
        if inherited.is_empty() { 1 } else { 2 },
        "size process attributes",
        "initialize process attributes",
    )
    .map_err(|e| native(ProcErrorCode::LaunchFailed, e.operation, e.source))?;
    attributes
        .set(
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            &jobs,
            "UpdateProcThreadAttribute",
        )
        .map_err(|e| native(ProcErrorCode::LaunchFailed, e.operation, e.source))?;
    if !handles.is_empty() {
        attributes
            .set(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                &handles,
                "UpdateProcThreadAttribute",
            )
            .map_err(|e| native(ProcErrorCode::LaunchFailed, e.operation, e.source))?;
    }
    startup.lpAttributeList = attributes.pointer();
    if spec.mode == LaunchMode::HeadlessConsole {
        startup.StartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
        startup.StartupInfo.wShowWindow =
            windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE as u16;
    }
    // SAFETY: native process output is POD; ownership is taken only on success.
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    let flags = CREATE_BREAKAWAY_FROM_JOB
        | CREATE_UNICODE_ENVIRONMENT
        | EXTENDED_STARTUPINFO_PRESENT
        | if spec.mode == LaunchMode::Headless {
            CREATE_NO_WINDOW
        } else {
            CREATE_NEW_CONSOLE
        };
    // SAFETY: application/cwd/environment/argv and aligned attribute backing
    // storage live for the call. JOB_LIST is atomic creation membership. Only
    // the closed explicit stream/capability handle list is inherited.
    let ok = unsafe {
        CreateProcessW(
            wide(spec.executable.as_os_str()).as_ptr(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            i32::from(!handles.is_empty()),
            flags,
            env.as_ptr().cast(),
            wide(spec.cwd.as_os_str()).as_ptr(),
            &startup.StartupInfo,
            &mut info,
        )
    };
    if ok == 0 {
        let cause = std::io::Error::last_os_error();
        return Err(native(
            if cause.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                ProcErrorCode::BreakawayDenied
            } else {
                ProcErrorCode::LaunchFailed
            },
            "CreateProcessW atomic job/breakaway",
            cause,
        ));
    }
    // Ownership immediately leaves raw PROCESS_INFORMATION. No fallible query
    // occurs before the caller stores this Child in its retained arena slot.
    let _thread = Handle(info.hThread);
    Ok(Child {
        pin: Handle(info.hProcess),
        identity: None,
        pid: ProcessId(info.dwProcessId),
    })
}
