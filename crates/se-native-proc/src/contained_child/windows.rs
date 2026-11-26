use super::*;
use crate::windows_native::attributes::Attributes;
use std::{
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
        SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::{
        JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        },
        Pipes::CreatePipe,
        Threading::{
            CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW,
            CREATE_UNICODE_ENVIRONMENT, CreateProcessW, EXTENDED_STARTUPINFO_PRESENT,
            GetExitCodeProcess, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW, WaitForSingleObject,
        },
    },
};

struct JobGuard {
    handle: HANDLE,
}

// SAFETY: A Win32 Job Object handle is an opaque kernel handle safe to transfer
// across threads; `CloseHandle` runs only once in `Drop`.
unsafe impl Send for JobGuard {}
// SAFETY: `AssignProcessToJobObject`, `TerminateJobObject`, and `QueryInformationJobObject`
// are kernel-synchronized on the handle; `CloseHandle` runs only after the last `Arc` drops.
unsafe impl Sync for JobGuard {}

impl JobGuard {
    fn create_kill_on_close() -> io::Result<Self> {
        // SAFETY: Null security attributes and null name create an anonymous job.
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let guard = Self { handle };
        // SAFETY: Zeroed POD struct for Win32 SetInformationJobObject.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `guard.handle` is a live job handle and `info` has exact size.
        let ok = unsafe {
            SetInformationJobObject(
                guard.handle,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(guard)
    }

    fn raw(&self) -> HANDLE {
        self.handle
    }

    fn active_processes(&self) -> io::Result<u32> {
        // SAFETY: Zeroed POD struct for `QueryInformationJobObject`.
        let mut acct: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        // SAFETY: `self.handle` is live and `acct` has exact size.
        let ok = unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectBasicAccountingInformation,
                (&raw mut acct).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(acct.ActiveProcesses)
    }

    fn terminate_and_drain(&self) -> io::Result<()> {
        // SAFETY: `self.handle` is a live job handle owned by `self`.
        let ok = unsafe { TerminateJobObject(self.handle, 1) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + KILL_DRAIN_TIMEOUT;
        loop {
            if self.active_processes()? == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(io::Error::other(
                    "Windows Job Object still has active processes after TerminateJobObject",
                ));
            }
            std::thread::sleep(KILL_POLL_INTERVAL);
        }
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: `self.handle` is uniquely owned and closed once on drop.
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct KillerState {
    job: Arc<JobGuard>,
}

impl KillerState {
    pub(super) fn kill_tree(&self) -> io::Result<()> {
        self.job.terminate_and_drain()
    }
}

fn create_inheritable_pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read_raw = ptr::null_mut();
    let mut write_raw = ptr::null_mut();
    // SAFETY: `CreatePipe` writes two valid handles on success.
    if unsafe { CreatePipe(&mut read_raw, &mut write_raw, &sa, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Both raw handles were just created and uniquely owned.
    let read = unsafe { OwnedHandle::from_raw_handle(read_raw) };
    // SAFETY: Both raw handles were just created and uniquely owned.
    let write = unsafe { OwnedHandle::from_raw_handle(write_raw) };
    // Parent's read end must NOT be inherited by the child.
    // SAFETY: `read` is a live pipe handle.
    if unsafe { SetHandleInformation(read.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((read, write))
}

fn open_nul_inheritable() -> io::Result<OwnedHandle> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let nul: Vec<u16> = "NUL\0".encode_utf16().collect();
    // SAFETY: `nul` is NUL-terminated and `sa` is valid for this call.
    let raw = unsafe {
        CreateFileW(
            nul.as_ptr(),
            windows_sys::Win32::Foundation::GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `CreateFileW` transferred one uniquely owned handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn quote_win_arg(arg: &OsStr, out: &mut Vec<u16>) {
    let units: Vec<u16> = arg.encode_wide().collect();
    let needs_quotes = units.is_empty()
        || units
            .iter()
            .any(|&u| u == b' ' as u16 || u == b'\t' as u16 || u == b'"' as u16);
    if !needs_quotes {
        out.extend_from_slice(&units);
        return;
    }
    out.push(b'"' as u16);
    let mut backslashes = 0usize;
    for u in units {
        if u == b'\\' as u16 {
            backslashes += 1;
        } else if u == b'"' as u16 {
            for _ in 0..(backslashes * 2 + 1) {
                out.push(b'\\' as u16);
            }
            out.push(b'"' as u16);
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push(b'\\' as u16);
            }
            backslashes = 0;
            out.push(u);
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push(b'\\' as u16);
    }
    out.push(b'"' as u16);
}

fn build_win_cmdline(command: &OsStr, args: &[OsString]) -> Vec<u16> {
    let mut out = Vec::new();
    quote_win_arg(command, &mut out);
    for arg in args {
        out.push(b' ' as u16);
        quote_win_arg(arg, &mut out);
    }
    out.push(0);
    out
}

fn build_win_env_block(entries: &[(OsString, OsString)]) -> Vec<u16> {
    let mut out = Vec::new();
    for (k, v) in entries {
        out.extend(k.encode_wide());
        out.push(b'=' as u16);
        out.extend(v.encode_wide());
        out.push(0);
    }
    if out.is_empty() {
        out.push(0);
    }
    out.push(0);
    out
}

pub(super) struct Inner {
    process: OwnedHandle,
    killer: KillerState,
    reaped_exit: Option<ContainedExit>,
}

impl Inner {
    pub(super) fn spawn(spec: ContainedChildSpec) -> io::Result<(Self, File, File)> {
        let job = Arc::new(JobGuard::create_kill_on_close()?);
        let stdin_nul = open_nul_inheritable()?;
        let (stdout_read, stdout_write) = create_inheritable_pipe()?;
        let (stderr_read, stderr_write) = create_inheritable_pipe()?;

        let cmdline = build_win_cmdline(&spec.command, &spec.args);
        let env_block = build_win_env_block(&build_sanitized_env(&spec.env));
        let mut cwd_wide: Vec<u16> = spec.cwd.as_os_str().encode_wide().collect();
        cwd_wide.push(0);

        let jobs = [job.raw()];
        let handles = [
            stdin_nul.as_raw_handle(),
            stdout_write.as_raw_handle(),
            stderr_write.as_raw_handle(),
        ];
        let mut attributes = Attributes::new(
            2,
            "size process attributes",
            "initialize process attributes",
        )
        .map_err(|e| e.source)?;
        attributes
            .set(
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                &jobs,
                "UpdateProcThreadAttribute",
            )
            .map_err(|e| e.source)?;
        attributes
            .set(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                &handles,
                "UpdateProcThreadAttribute",
            )
            .map_err(|e| e.source)?;

        // SAFETY: Zeroed POD `STARTUPINFOEXW` with explicit stdio handles and
        // closed handle/job attribute lists so no unrelated host handles leak.
        let mut si: STARTUPINFOEXW = unsafe { zeroed() };
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = stdin_nul.as_raw_handle();
        si.StartupInfo.hStdOutput = stdout_write.as_raw_handle();
        si.StartupInfo.hStdError = stderr_write.as_raw_handle();
        si.lpAttributeList = attributes.pointer();

        // SAFETY: Zeroed POD output struct for `CreateProcessW`.
        let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };
        let flags = CREATE_NO_WINDOW
            | CREATE_NEW_PROCESS_GROUP
            | CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT;
        let create = |launch_flags, pi: &mut PROCESS_INFORMATION| {
            let mut cmd_buf = cmdline.clone();
            // SAFETY: `cmd_buf`, `env_block`, `cwd_wide`, `si`, and `attributes`
            // remain valid for this call. `JOB_LIST` attaches the child to the
            // `KILL_ON_JOB_CLOSE` job atomically and `HANDLE_LIST` restricts
            // inheritance strictly to the three stdio handles.
            if unsafe {
                CreateProcessW(
                    ptr::null(),
                    cmd_buf.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    1,
                    launch_flags,
                    env_block.as_ptr().cast(),
                    cwd_wide.as_ptr(),
                    &si.StartupInfo,
                    pi,
                )
            } == 0
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        };
        let creation = match create(flags | CREATE_BREAKAWAY_FROM_JOB, &mut pi) {
            Err(cause) if cause.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                create(flags, &mut pi)
            }
            outcome => outcome,
        };
        drop(attributes);
        drop(stdin_nul);
        drop(stdout_write);
        drop(stderr_write);
        creation?;
        // SAFETY: `CreateProcessW` succeeded and transferred unique ownership of both handles.
        let process = unsafe { OwnedHandle::from_raw_handle(pi.hProcess) };
        // SAFETY: `CreateProcessW` succeeded and transferred unique ownership of both handles.
        let _thread = unsafe { OwnedHandle::from_raw_handle(pi.hThread) };

        Ok((
            Self {
                process,
                killer: KillerState { job },
                reaped_exit: None,
            },
            File::from(stdout_read),
            File::from(stderr_read),
        ))
    }

    pub(super) fn killer(&self) -> KillerState {
        self.killer.clone()
    }

    pub(super) fn try_wait(&mut self) -> io::Result<Option<ContainedExit>> {
        if let Some(exit) = &self.reaped_exit {
            return Ok(Some(exit.clone()));
        }
        // SAFETY: `self.process` is a live process handle.
        let rc = unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) };
        if rc == WAIT_TIMEOUT {
            return Ok(None);
        }
        if rc != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let exit = self.read_exit_code()?;
        self.reaped_exit = Some(exit.clone());
        Ok(Some(exit))
    }

    pub(super) fn wait(&mut self) -> io::Result<ContainedExit> {
        if let Some(exit) = &self.reaped_exit {
            return Ok(exit.clone());
        }
        // SAFETY: `self.process` is a live process handle.
        let rc = unsafe { WaitForSingleObject(self.process.as_raw_handle(), u32::MAX) };
        if rc != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        let exit = self.read_exit_code()?;
        self.reaped_exit = Some(exit.clone());
        Ok(exit)
    }

    pub(super) fn terminate_and_reap(&mut self) -> io::Result<()> {
        self.killer.kill_tree()
    }

    fn read_exit_code(&self) -> io::Result<ContainedExit> {
        let mut code = 0u32;
        // SAFETY: `self.process` is a live exited process handle.
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(ContainedExit {
            exit_code: Some(code),
            signal: None,
        })
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.killer.kill_tree();
    }
}
