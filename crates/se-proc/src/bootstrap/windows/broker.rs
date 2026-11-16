//! A same-user native parent supplies job detachment without a service or shell.
//! Only our explicit startup handles enter its handle table; it executes no code.
//! https://devblogs.microsoft.com/oldnewthing/20260511-00/?p=112313
use super::*;
use std::os::windows::io::FromRawHandle;
use windows_sys::Win32::System::JobObjects::IsProcessInJob;

fn in_job(process: HANDLE) -> ProcResult<bool> {
    let mut member = 0;
    // SAFETY: retained query-capable process and writable BOOL; null means any job.
    if unsafe { IsProcessInJob(process, ptr::null_mut(), &mut member) } == 0 {
        return Err(last("observe detached runtime job membership"));
    }
    Ok(member != 0)
}
pub(super) fn outside_job(process: HANDLE) -> ProcResult<()> {
    if in_job(process)? {
        return Err(error(
            ProcErrorCode::BreakawayDenied,
            ProcErrorDetail::Input {
                field: "runtime detachment".into(),
                reason: "native process is still inside a Windows job".into(),
            },
        ));
    }
    Ok(())
}

mod token;
pub(super) use token::{Context, context};

struct BrokerScan {
    caller: Context,
    verified: Option<(OwnedHandle, ProcessIdentity)>,
    examined: usize,
    unreadable: usize,
}
/// Verifies same-user detached broker candidates in the shared launch order.
/// The first fully verified candidate wins; absent and unreadable remain
/// separate facts for every caller of the scan.
fn scan(machine: &MachineId, deadline: Instant) -> ProcResult<BrokerScan> {
    // SAFETY: immutable current-process pseudo handle.
    let caller = context(unsafe { GetCurrentProcess() }).map_err(|error| {
        native(
            ProcErrorCode::BreakawayDenied,
            "verify caller security context for detached broker",
            io::Error::other(format!(
                "{error:?}; open a normal terminal directly from Start using this account"
            )),
        )
    })?;
    let processes = crate::windows_native::parents().map_err(|e| fail(e.operation, e.source))?;
    let mut scan = BrokerScan {
        caller,
        verified: None,
        examined: 0,
        unreadable: 0,
    };
    for pid in processes
        .keys()
        .copied()
        .filter(|pid| *pid != std::process::id())
    {
        check(deadline)?;
        scan.examined += 1;
        // SAFETY: read/query/duplicate/create-child rights only; native validates PID.
        let process = match handle(
            unsafe {
                OpenProcess(
                    PROCESS_CREATE_PROCESS
                        | PROCESS_DUP_HANDLE
                        | PROCESS_QUERY_LIMITED_INFORMATION
                        | SYNCHRONIZE,
                    0,
                    pid,
                )
            },
            "open detached broker candidate",
        ) {
            Ok(process) => process,
            Err(_) => {
                scan.unreadable += 1;
                continue;
            }
        };
        // SAFETY: retained synchronize handle, no wait or mutation.
        if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT {
            continue;
        }
        let candidate = match context(process.as_raw_handle()) {
            Ok(value) => value,
            Err(_) => {
                scan.unreadable += 1;
                continue;
            }
        };
        if candidate != scan.caller {
            continue;
        }
        match in_job(process.as_raw_handle()) {
            Ok(false) => (),
            Ok(true) => continue,
            Err(_) => {
                scan.unreadable += 1;
                continue;
            }
        }
        let identity = match crate::read_process(machine.clone(), ProcessId(pid))? {
            ProcessRead::Present(live) => live.identity,
            _ => continue,
        };
        // The open handle pins the birth; do not trust a second PID-only read after reuse.
        let start = crate::windows_native::process_start(process.as_raw_handle())
            .map_err(|e| fail(e.operation, e.source))?;
        if identity.start
            != (StartIdentity::Windows {
                creation_filetime: start,
            })
        {
            continue;
        }
        scan.verified = Some((process, identity));
        break;
    }
    Ok(scan)
}
/// Whether a detached (outside-all-jobs) runtime host can be launched from the
/// current process on this venue, classified without attempting a launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachedVenue {
    /// A direct launch from the caller lands outside all jobs: the caller is
    /// in no job, or its job permits breakaway (probed with a short-lived child).
    Direct,
    /// A verified same-user detached broker supplies the launch context.
    Broker,
    /// No verified broker: `examined` same-user processes were fully verified as
    /// non-brokers and `unreadable` process contexts could not be verified.
    NoBroker { examined: usize, unreadable: usize },
}
impl DetachedVenue {
    /// The one venue fact a control prints when reporting unsupported coverage.
    pub fn coverage(&self) -> String {
        match self {
            Self::Direct => {
                "caller is not contained in a Windows job; a direct launch lands outside all jobs"
                    .into()
            }
            Self::Broker => {
                "a verified same-user detached broker supplies the launch context".into()
            }
            Self::NoBroker {
                examined,
                unreadable,
            } => format!(
                "no verified detached broker among {examined} examined same-user processes; {unreadable} process contexts unreadable"
            ),
        }
    }
}
/// Probes the venue's direct breakaway the same way a launch resolves it:
/// a short-lived native child is created with `CREATE_BREAKAWAY_FROM_JOB`,
/// then joined and closed before the result returns. `Ok(false)` is the exact
/// denial a launch maps to `BreakawayDenied`; any other spawn or wait failure
/// is an error, never a guessed venue.
fn direct_breakaway_probe(deadline: Instant) -> ProcResult<bool> {
    let mut line: Vec<u16> = "C:\\Windows\\System32\\cmd.exe /d /c exit 0"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: native process output POD starts zeroed; success fills it.
    let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
    // SAFETY: native startup POD starts zeroed; its size is set below.
    let mut startup: STARTUPINFOW = unsafe { zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    // SAFETY: writable probe command line, startup and process information;
    // null application, environment and working directory inherit the
    // caller's, and no streams are inherited.
    if unsafe {
        CreateProcessW(
            ptr::null(),
            line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_BREAKAWAY_FROM_JOB,
            ptr::null(),
            ptr::null(),
            &startup,
            &mut info,
        )
    } == 0
    {
        let cause = io::Error::last_os_error();
        if cause.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            return Ok(false);
        }
        return Err(fail("direct breakaway probe", cause));
    }
    // SAFETY: success returns owned handles; the thread handle is closed here.
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    // SAFETY: the thread handle came from our successful CreateProcessW.
    let _ = unsafe { CloseHandle(info.hThread) };
    let escaped = in_job(process.as_raw_handle())?;
    let bound = deadline
        .saturating_duration_since(Instant::now())
        .min(std::time::Duration::from_secs(10));
    // SAFETY: the probe process handle is valid until its close below.
    let state = unsafe {
        WaitForSingleObject(
            process.as_raw_handle(),
            bound.as_millis().min(u32::MAX as u128) as u32,
        )
    };
    if state != WAIT_OBJECT_0 {
        // SAFETY: the probe child is this process's exact child; retire it
        // before reporting so a stuck probe never leaks a running process.
        unsafe {
            TerminateProcess(process.as_raw_handle(), 1);
        }
        return Err(native(
            ProcErrorCode::LaunchFailed,
            "join direct breakaway probe child",
            io::Error::other("probe child did not exit within the venue bound"),
        ));
    }
    Ok(!escaped)
}
/// Classifies the venue the way a launch resolves it: a direct breakaway is
/// probed with a short-lived child, and the shared broker scan runs only when
/// the venue denies breakaway. Absent and unreadable remain separate facts.
pub fn detached_venue(machine: &MachineId, deadline: Instant) -> ProcResult<DetachedVenue> {
    let mut member = 0;
    // SAFETY: current-process query and writable native membership output; null tests every job.
    if unsafe { IsProcessInJob(GetCurrentProcess(), ptr::null_mut(), &mut member) } == 0 {
        return Err(last("observe current process job membership"));
    }
    if member == 0 {
        return Ok(DetachedVenue::Direct);
    }
    if direct_breakaway_probe(deadline)? {
        return Ok(DetachedVenue::Direct);
    }
    let scan = scan(machine, deadline)?;
    Ok(match scan.verified {
        Some(_) => DetachedVenue::Broker,
        None => DetachedVenue::NoBroker {
            examined: scan.examined,
            unreadable: scan.unreadable,
        },
    })
}

pub(super) struct Broker {
    process: OwnedHandle,
    pub identity: ProcessIdentity,
    pub context: Context,
}
impl Broker {
    pub fn find(machine: &MachineId, deadline: Instant) -> ProcResult<Self> {
        let scan = scan(machine, deadline)?;
        match scan.verified {
            Some((process, identity)) => Ok(Self {
                process,
                identity,
                context: scan.caller,
            }),
            None => Err(native(
                ProcErrorCode::BreakawayDenied,
                "find same-user detached broker",
                io::Error::other(format!(
                    "no verified broker among {} processes; {} contexts unreadable; open a normal terminal directly from Start using this account",
                    scan.examined, scan.unreadable
                )),
            )),
        }
    }
    pub fn handle(&self) -> HANDLE {
        self.process.as_raw_handle()
    }
    pub fn duplicate<'a>(&'a self, sources: &[HANDLE]) -> ProcResult<RemoteHandles<'a>> {
        let mut result = RemoteHandles {
            broker: self,
            values: Vec::new(),
        };
        for source in sources {
            let mut target = ptr::null_mut();
            // SAFETY: source is our retained handle; broker handle pins its native table.
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    *source,
                    self.handle(),
                    &mut target,
                    0,
                    1,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(last(
                    "duplicate private startup handle into detached broker",
                ));
            }
            result.values.push(target);
        }
        Ok(result)
    }
}
pub(super) struct RemoteHandles<'a> {
    broker: &'a Broker,
    pub values: Vec<HANDLE>,
}
impl RemoteHandles<'_> {
    pub fn close(&mut self) -> ProcResult<()> {
        let mut failure = None;
        for source in self.values.drain(..) {
            let mut local = ptr::null_mut();
            // SAFETY: closes only our exact duplicate in the retained broker table.
            // CLOSE_SOURCE closes the source even if duplicating it fails.
            let closed = unsafe {
                DuplicateHandle(
                    self.broker.handle(),
                    source,
                    GetCurrentProcess(),
                    &mut local,
                    0,
                    0,
                    DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
                )
            };
            if closed == 0 {
                failure.get_or_insert_with(|| last("close private broker handle"));
            } else {
                drop(handle(local, "own returned broker handle")?);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}
impl Drop for RemoteHandles<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            eprintln!("private detached broker handle cleanup failed: {error:?}");
        }
    }
}
