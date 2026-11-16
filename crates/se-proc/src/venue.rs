//! Windows detached-launch venue, classified without attempting a launch:
//! the shared scan verifies same-user detached broker candidates in the
//! launch order, and the venue names what a launch can do from the current
//! process. Absent and unreadable stay separate facts.
use crate::{
    MachineId, ProcErrorCode, ProcResult, ProcessId, ProcessIdentity, ProcessRead, StartIdentity,
    bootstrap::{
        check,
        windows::{
            broker::{Context, context, in_job},
            fail, handle, last,
        },
    },
    support::native,
};
use std::{
    io,
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr,
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::WAIT_TIMEOUT,
    Storage::FileSystem::SYNCHRONIZE,
    System::{
        JobObjects::IsProcessInJob,
        Threading::{
            GetCurrentProcess, OpenProcess, PROCESS_CREATE_PROCESS, PROCESS_DUP_HANDLE,
            PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
        },
    },
};
pub(crate) struct BrokerScan {
    pub(crate) caller: Context,
    pub(crate) verified: Option<(OwnedHandle, ProcessIdentity)>,
    pub(crate) examined: usize,
    pub(crate) unreadable: usize,
}
/// Verifies same-user detached broker candidates in the shared launch order.
/// The first fully verified candidate wins; absent and unreadable remain
/// separate facts for every caller of the scan.
pub(crate) fn scan(machine: &MachineId, deadline: Instant) -> ProcResult<BrokerScan> {
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
    /// The caller is not contained in any job; a direct launch lands outside
    /// all jobs.
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
/// Classifies the venue with the same broker scan a launch would run; no
/// process is created. Absent and unreadable remain separate facts.
pub fn detached_venue(machine: &MachineId, deadline: Instant) -> ProcResult<DetachedVenue> {
    let mut member = 0;
    // SAFETY: current-process query and writable native membership output; null tests every job.
    if unsafe { IsProcessInJob(GetCurrentProcess(), ptr::null_mut(), &mut member) } == 0 {
        return Err(last("observe current process job membership"));
    }
    if member == 0 {
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
