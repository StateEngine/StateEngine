use super::identity::*;
use crate::support::*;
use crate::{windows_native::attributes::Attributes, *};
use std::{
    ffi::OsStr,
    mem::{size_of, zeroed},
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::*, Security::SECURITY_ATTRIBUTES, Storage::FileSystem::*, System::Threading::*,
};

fn quoted(arg: &OsStr) -> Vec<u16> {
    let mut out = vec![b'"' as u16];
    let mut slashes = 0;
    for unit in arg.encode_wide() {
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        let count = if unit == b'"' as u16 {
            slashes * 2 + 1
        } else {
            slashes
        };
        out.extend(std::iter::repeat_n(b'\\' as u16, count));
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
pub(super) fn create(spec: LaunchSpec, job: &Handle, persistent: bool) -> ProcResult<Child> {
    // Keep exclusion through CreateProcess, then permit ordinary package updates.
    let custody = spec.executable_custody;
    let creation = custody
        .as_ref()
        .map(|image| image.creation_guard())
        .transpose()
        .map_err(|e| input("qualified image", &e.to_string()))?;
    if std::time::Instant::now() >= spec.deadline {
        return Err(error(
            ProcErrorCode::LaunchTimedOut,
            ProcErrorDetail::Input {
                field: "deadline".into(),
                reason: "image custody exceeded the original launch deadline".into(),
            },
        ));
    }
    let capabilities = if persistent {
        // Keep one minimal non-privileged handle in the child so Windows
        // retains the named job in the object namespace after host exit.
        vec![capability(
            job,
            SYNCHRONIZE,
            ProcErrorCode::LaunchFailed,
            "duplicate persistent job anchor",
        )?]
    } else {
        Vec::new()
    };
    let result = create_command(
        Command {
            executable: custody
                .as_ref()
                .map_or(spec.executable, |image| image.path().to_owned()),
            arguments: spec.arguments,
            environment: spec.environment,
            stdio: spec.stdio,
            mode: spec.mode,
            cwd: spec.cwd,
            capabilities,
        },
        job,
    );
    drop(creation);
    drop(custody);
    result
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
        ProcErrorCode::StopDispatchFailed,
        "duplicate console capability",
    )?;
    let job_pin = capability(
        job,
        windows_sys::Win32::System::SystemServices::JOB_OBJECT_QUERY | READ_CONTROL,
        ProcErrorCode::StopDispatchFailed,
        "duplicate console capability",
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
fn capability(source: &Handle, rights: u32, code: ProcErrorCode, api: &str) -> ProcResult<Handle> {
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
        return Err(last(code, api));
    }
    // SAFETY: the successful duplication above transferred a new owned reference to `copy`.
    unsafe { Handle::new(copy, api) }
}
fn command_line(executable: &OsStr, arguments: &[std::ffi::OsString]) -> ProcResult<Vec<u16>> {
    let mut line = quoted(executable);
    for arg in arguments {
        line.push(b' ' as u16);
        line.extend(quoted(arg));
    }
    line.push(0);
    if line.len() > 32767 {
        return Err(capacity("Windows command line UTF-16 units", 32767));
    }
    Ok(line)
}
fn environment_block(environment: Environment) -> Vec<u16> {
    let mut entries = environment.entries;
    entries.sort_by_key(|(key, _)| key.to_string_lossy().to_uppercase());
    let mut env = Vec::new();
    for (key, value) in entries {
        env.extend(key.encode_wide());
        env.push(b'=' as u16);
        env.extend(value.encode_wide());
        env.push(0);
    }
    if env.is_empty() {
        env.push(0);
    }
    env.push(0);
    env
}
fn prepare_stdio_handles(mode: LaunchMode, stdio: StandardIo) -> ProcResult<Vec<Handle>> {
    let streams = [stdio.stdin, stdio.stdout, stdio.stderr];
    if mode == LaunchMode::Window && streams.iter().any(Option::is_some) {
        return Err(unsupported(
            "partial/new-console redirection requires the terminal adapter; launch a window without redirections or use headless streams",
        ));
    }
    if !mode.is_headless() {
        return Ok(Vec::new());
    }
    let mut inherited = Vec::with_capacity(3);
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
            let mut security: SECURITY_ATTRIBUTES = unsafe { zeroed() };
            security.nLength = size_of_val(&security) as u32;
            security.bInheritHandle = 1;
            // SAFETY: constant terminated null-device name and live attributes;
            // only this explicit stream duplicate is inheritable.
            let raw = unsafe {
                CreateFileW(
                    wide(OsStr::new("NUL")).as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    &security,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    ptr::null_mut(),
                )
            };
            // SAFETY: the successful open above transferred unique ownership to `raw`.
            unsafe { Handle::new(raw, "open child null stream") }?
        };
        inherited.push(handle);
    }
    Ok(inherited)
}
fn set_attr<'a>(attrs: &mut Attributes<'a>, key: u32, value: &'a [HANDLE]) -> ProcResult<()> {
    attrs
        .set(key as usize, value, "UpdateProcThreadAttribute")
        .map_err(|e| native(ProcErrorCode::LaunchFailed, e.operation, e.source))
}
fn create_command(spec: Command, job: &Handle) -> ProcResult<Child> {
    let line = command_line(spec.executable.as_os_str(), &spec.arguments)?;
    let env = environment_block(spec.environment);
    // SAFETY: native startup POD starts zeroed; size and used fields are set below.
    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    let mut inherited = prepare_stdio_handles(spec.mode, spec.stdio)?;
    if spec.mode.is_headless() {
        startup.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = inherited[0].0;
        startup.StartupInfo.hStdOutput = inherited[1].0;
        startup.StartupInfo.hStdError = inherited[2].0;
    }
    inherited.extend(spec.capabilities);
    let jobs = [job.0];
    let handles: Vec<_> = inherited.iter().map(|h| h.0).collect();
    let mut attributes = Attributes::new(
        if inherited.is_empty() { 1 } else { 2 },
        "size process attributes",
        "initialize process attributes",
    )
    .map_err(|e| native(ProcErrorCode::LaunchFailed, e.operation, e.source))?;
    set_attr(&mut attributes, PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
    if !handles.is_empty() {
        set_attr(&mut attributes, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &handles)?;
    }
    startup.lpAttributeList = attributes.pointer();
    // SAFETY: native process output is POD; ownership is taken only on success.
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    let mode_flag = if spec.mode.is_headless() {
        CREATE_NO_WINDOW
    } else {
        CREATE_NEW_CONSOLE
    };
    let flags = CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | mode_flag;
    let application = wide(spec.executable.as_os_str());
    let cwd = wide(spec.cwd.as_os_str());
    let create = |flags, info: &mut PROCESS_INFORMATION| {
        // CreateProcessW may modify its command line, including on failure.
        let mut command_line = line.clone();
        // SAFETY: application/cwd/environment/argv and aligned attribute backing
        // storage live for the call. JOB_LIST is atomic creation membership. Only
        // the closed explicit stream/capability handle list is inherited.
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                i32::from(!handles.is_empty()),
                flags,
                env.as_ptr().cast(),
                cwd.as_ptr(),
                &startup.StartupInfo,
                info,
            )
        } == 0
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    let creation = match create(flags | CREATE_BREAKAWAY_FROM_JOB, &mut info) {
        Err(cause) if cause.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
            // A compatible enclosing job can deny breakaway while permitting
            // nesting. Keep our atomic JOB_LIST and exact handle inheritance;
            // never create an uncontained child or modify the enclosing job.
            create(flags, &mut info)
        }
        outcome => outcome,
    };
    creation.map_err(|cause| {
        native(
            ProcErrorCode::LaunchFailed,
            "CreateProcessW atomic job assignment",
            cause,
        )
    })?;
    // Ownership immediately leaves raw PROCESS_INFORMATION. No fallible query
    // occurs before the caller stores this Child in its retained arena slot.
    let _thread = Handle(info.hThread);
    Ok(Child {
        pin: Handle(info.hProcess),
        identity: None,
        pid: ProcessId(info.dwProcessId),
    })
}
