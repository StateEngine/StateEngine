//! Isolate console attachment in a direct child. The runtime never detaches its
//! own console, and a PID alone cannot authorize a console-wide Ctrl+C.
use super::{Scope, identity::*, security};
use crate::{support::*, *};
use std::{
    ffi::{OsStr, OsString},
    path::Path,
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    System::{
        Console::*,
        JobObjects::*,
        Threading::{GetCurrentProcess, GetProcessId},
    },
};

pub const CONSOLE_INTERRUPT_ENTRY: &str = "__native-console-interrupt";

/// Give a dedicated host a stable console policy before it creates children.
/// The host absorbs interrupts; children inherit normal Ctrl+C processing.
pub fn initialize_host_console_policy() -> ProcResult<()> {
    // SAFETY: the static callback has the native signature and no borrowed state.
    if unsafe { SetConsoleCtrlHandler(Some(host_console_handler), 1) } == 0 {
        return Err(last(
            ProcErrorCode::LaunchFailed,
            "register host console handler",
        ));
    }
    // SAFETY: this changes only the dedicated host's inherited Ctrl+C policy.
    if unsafe { SetConsoleCtrlHandler(None, 0) } == 0 {
        let cause = last(
            ProcErrorCode::LaunchFailed,
            "enable child console interrupts",
        );
        // SAFETY: unregister the same static handler after failed initialization.
        unsafe {
            SetConsoleCtrlHandler(Some(host_console_handler), 0);
        }
        return Err(cause);
    }
    Ok(())
}

unsafe extern "system" fn host_console_handler(event: u32) -> i32 {
    i32::from(matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT))
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub root: ProcessIdentity,
    pub root_handle: u64,
    pub job_handle: u64,
}

impl Scope {
    pub fn interrupt(&mut self, helper: &Path, deadline: Instant) -> ProcResult<StopDispatch> {
        self.verify_limits()?;
        check_stop_deadline(deadline)?;
        if !self.console_interrupt {
            return Err(input(
                "native console cancellation",
                "launch with an independent hidden console before requesting Ctrl+C",
            ));
        }
        let Some(child) = &self.child else {
            return Ok(StopDispatch::NotNeeded);
        };
        if exit_status(&child.pin)?.is_some() {
            return Ok(StopDispatch::NotNeeded);
        }
        let root = child.identity.as_ref().ok_or_else(|| {
            input(
                "native console cancellation",
                "the original root identity is not published",
            )
        })?;
        if !matches!(observe(root, &child.pin)?, ProcessObservation::Live(_)) {
            return Ok(StopDispatch::NotNeeded);
        }
        if !helper.is_absolute() {
            return Err(input(
                "native console cancellation",
                "an absolute installed helper",
            ));
        }
        // Atomic job-list creation retains cleanup custody even if this call
        // times out. A retry joins the original helper instead of creating one.
        if self.interrupt_helper.is_none() {
            self.interrupt_helper = Some(super::spawn::interrupt_helper(
                helper, root, &child.pin, &self.job,
            )?);
        }
        let helper = self
            .interrupt_helper
            .as_ref()
            .ok_or_else(|| input("native console cancellation", "retained helper custody"))?;
        loop {
            match exit_status(&helper.pin)? {
                Some(ExitStatus::Code(0)) => return Ok(StopDispatch::Requested),
                Some(ExitStatus::Code(2)) => return Ok(StopDispatch::NotNeeded),
                Some(status) => {
                    return Err(input(
                        "native console cancellation",
                        &format!(
                            "the isolated helper refused or failed ({status:?}); retain custody and use witnessed forced stop if cancellation remains unproved"
                        ),
                    ));
                }
                None if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                None => {
                    return Err(input(
                        "native console cancellation",
                        "the original helper remains pending; its exact native job retains cleanup custody",
                    ));
                }
            }
        }
    }
}

struct Attached;
impl Drop for Attached {
    fn drop(&mut self) {
        // SAFETY: only the short-lived helper calls this, after its attachment.
        unsafe {
            FreeConsole();
        }
    }
}

fn helper_input(reason: &str) -> ProcError {
    input("console helper", reason)
}
fn stop_fail(api: &str) -> ProcError {
    last(ProcErrorCode::StopDispatchFailed, api)
}

enum InheritedKind {
    Process(u32),
    Job,
}

fn verify_inherited_kind(raw: HANDLE, kind: InheritedKind) -> ProcResult<()> {
    match kind {
        InheritedKind::Process(pid) => {
            // SAFETY: `raw` is a validated open handle; `GetProcessId` returns 0 on non-processes.
            let got = unsafe { GetProcessId(raw) };
            if pid == 0 || got == 0 || got != pid {
                return Err(helper_input("the original inherited process capability"));
            }
        }
        InheritedKind::Job => {
            // SAFETY: `raw` is a validated open handle; `query_limits` rejects non-job handles.
            unsafe { crate::windows_native::job::query_limits(raw, "verify inherited job") }
                .map_err(|_| helper_input("the original inherited job capability"))?;
        }
    }
    Ok(())
}

fn inherited(selector: u64, kind: InheritedKind) -> ProcResult<Handle> {
    let raw = usize::try_from(selector).map_err(|_| helper_input("a native inherited handle"))?
        as *mut std::ffi::c_void;
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(helper_input("a native inherited handle"));
    }
    let mut flags = 0;
    // SAFETY: the kernel validates the untrusted selector; no ownership is claimed.
    if unsafe { GetHandleInformation(raw, &mut flags) } == 0 {
        return Err(stop_fail("inspect inherited console capability"));
    }
    if flags & HANDLE_FLAG_INHERIT == 0 {
        return Err(helper_input(
            "a capability inherited from the native creator",
        ));
    }
    verify_inherited_kind(raw, kind)?;
    let mut dup = ptr::null_mut();
    // SAFETY: `raw` is a validated Process or Job kernel object (not a Winsock socket);
    // duplicating with `bInheritHandle = 0` yields a fresh, exclusively owned handle.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            raw,
            GetCurrentProcess(),
            &mut dup,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(stop_fail("duplicate inherited console capability"));
    }
    // SAFETY: `DuplicateHandle` above transferred sole ownership of the fresh handle `dup`.
    unsafe { Handle::new(dup, "own inherited console capability") }
}

static ENTERED: AtomicBool = AtomicBool::new(false);

/// Private subprocess startup entry invoked once from `main()`.
/// Reads `std::env::args_os()` directly so no public API accepts caller-supplied
/// raw handle selectors; returns `None` outside the private helper process.
pub fn console_interrupt_entry() -> Option<ProcResult<StopDispatch>> {
    let args: Vec<OsString> = std::env::args_os().collect();
    dispatch_startup_entry(&args, &ENTERED)
}

fn dispatch_startup_entry(
    args: &[OsString],
    entered: &AtomicBool,
) -> Option<ProcResult<StopDispatch>> {
    if args.get(1).and_then(|v| v.to_str()) != Some(CONSOLE_INTERRUPT_ENTRY) {
        return None;
    }
    if entered.swap(true, Ordering::AcqRel) {
        return Some(Err(helper_input("startup entry may run only once")));
    }
    if args.len() != 3 {
        return Some(Err(input("native console helper", "one original identity")));
    }
    Some(run_console_interrupt(&args[2]))
}

fn run_console_interrupt(request: &OsStr) -> ProcResult<StopDispatch> {
    let request = request
        .to_str()
        .filter(|value| value.len() <= 8192)
        .ok_or_else(|| helper_input("one bounded UTF-8 identity"))?;
    let request: Request = serde_json::from_str(request)
        .map_err(|_| helper_input("the closed native console request"))?;
    if request.root.pid.0 == 0 || request.root_handle == request.job_handle {
        return Err(helper_input(
            "nonzero pid and distinct inherited capabilities required",
        ));
    }
    let root = inherited(
        request.root_handle,
        InheritedKind::Process(request.root.pid.0),
    )?;
    let job = inherited(request.job_handle, InheritedKind::Job)?;
    // SAFETY: retained duplicated process capability; re-check PID on owned handle.
    let got_pid = unsafe { GetProcessId(root.0) };
    if got_pid == 0 || got_pid != request.root.pid.0 {
        return Err(helper_input("the original inherited process capability"));
    }
    if !matches!(observe(&request.root, &root)?, ProcessObservation::Live(_)) {
        return Ok(StopDispatch::NotNeeded);
    }
    security::verify_job(&job)?;
    // SAFETY: FreeConsole affects only the calling helper process.
    if unsafe { FreeConsole() } == 0 {
        return Err(stop_fail("detach helper console"));
    }
    // SAFETY: original live process object remains pinned against PID reuse.
    if unsafe { AttachConsole(request.root.pid.0) } == 0 {
        return Err(stop_fail("attach original private console"));
    }
    let _attached = Attached;
    // SAFETY: affects only this isolated helper; AttachConsole reset its handlers.
    if unsafe { SetConsoleCtrlHandler(None, 1) } == 0 {
        return Err(stop_fail("protect console helper from Ctrl+C"));
    }
    let mut members = [0u32; 129];
    // SAFETY: writable fixed array and exact element capacity.
    let count = unsafe { GetConsoleProcessList(members.as_mut_ptr(), members.len() as u32) };
    if count == 0 || count as usize > members.len() {
        return Err(helper_input("a complete bounded console membership read"));
    }
    let members = &members[..count as usize];
    if !members.contains(&request.root.pid.0) {
        return Err(helper_input("the original root in its independent console"));
    }
    let mut pins = Vec::new();
    for pid in members
        .iter()
        .copied()
        .filter(|pid| *pid != std::process::id())
    {
        let pin =
            lookup(ProcessId(pid))?.ok_or_else(|| helper_input("stable console membership"))?;
        let mut member = 0;
        // SAFETY: retained query-only process/job handles and writable BOOL.
        if unsafe { IsProcessInJob(pin.0, job.0, &mut member) } == 0 {
            return Err(stop_fail("verify console job membership"));
        }
        if member == 0 {
            return Err(helper_input("no foreign processes in the private console"));
        }
        pins.push(pin);
    }
    if !matches!(observe(&request.root, &root)?, ProcessObservation::Live(_)) {
        return Ok(StopDispatch::NotNeeded);
    }
    // SAFETY: only the verified private console receives Ctrl+C; this helper ignores it.
    if unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) } == 0 {
        return Err(stop_fail("dispatch private console Ctrl+C"));
    }
    Ok(StopDispatch::Requested)
}

#[cfg(test)]
#[path = "../../../tests/support/windows_interrupt_entry.rs"]
mod entry_tests;
