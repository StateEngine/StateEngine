//! Isolate console attachment in a direct child. The runtime never detaches its
//! own console, and a PID alone cannot authorize a console-wide Ctrl+C.
use super::{Scope, identity::*, security};
use crate::{support::*, *};
use std::{
    ffi::OsStr,
    path::Path,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    System::{Console::*, JobObjects::*},
};

pub const CONSOLE_INTERRUPT_ENTRY: &str = "__native-console-interrupt";
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

fn inherited(selector: u64) -> ProcResult<Handle> {
    let selector = usize::try_from(selector)
        .map_err(|_| input("console helper", "a native inherited handle"))?;
    let raw = selector as *mut std::ffi::c_void;
    let mut flags = 0;
    // SAFETY: the kernel validates the untrusted selector; no ownership yet.
    if unsafe { GetHandleInformation(raw, &mut flags) } == 0 {
        return Err(last(
            ProcErrorCode::StopDispatchFailed,
            "inspect inherited console capability",
        ));
    }
    if flags & HANDLE_FLAG_INHERIT == 0 {
        return Err(input(
            "console helper",
            "a capability inherited from the native creator",
        ));
    }
    // SAFETY: this private helper owns the inherited table entry, never a name
    // lookup. It cannot accidentally hand the capability to another child.
    if unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(last(
            ProcErrorCode::StopDispatchFailed,
            "seal inherited console capability",
        ));
    }
    Handle::new(raw, "own inherited console capability")
}

/// Private helper entry. Identity text grants no rights: the native creator
/// passes query-only process/job capabilities through the explicit handle list.
/// Prove every attached process belongs to that exact job before broadcasting.
pub fn console_interrupt_entry(request: &OsStr) -> ProcResult<StopDispatch> {
    let request = request
        .to_str()
        .filter(|value| value.len() <= 8192)
        .ok_or_else(|| input("console helper", "one bounded UTF-8 identity"))?;
    let request: Request = serde_json::from_str(request)
        .map_err(|_| input("console helper", "the closed native console request"))?;
    let root = inherited(request.root_handle)?;
    let job = inherited(request.job_handle)?;
    // SAFETY: retained inherited process capability; the kernel validates kind.
    if unsafe { windows_sys::Win32::System::Threading::GetProcessId(root.0) } != request.root.pid.0
    {
        return Err(input(
            "console helper",
            "the original inherited process capability",
        ));
    }
    if !matches!(observe(&request.root, &root)?, ProcessObservation::Live(_)) {
        return Ok(StopDispatch::NotNeeded);
    }
    security::verify_job(&job)?;
    // The helper was created without a console. Never detach the runtime's or
    // an inherited console to make this work.
    // SAFETY: original live process object remains pinned against PID reuse.
    if unsafe { AttachConsole(request.root.pid.0) } == 0 {
        return Err(last(
            ProcErrorCode::StopDispatchFailed,
            "attach original private console",
        ));
    }
    let _attached = Attached;
    // SAFETY: affects only this isolated helper; AttachConsole reset its handlers.
    if unsafe { SetConsoleCtrlHandler(None, 1) } == 0 {
        return Err(last(
            ProcErrorCode::StopDispatchFailed,
            "protect console helper from Ctrl+C",
        ));
    }
    let mut members = [0u32; 129];
    // SAFETY: writable fixed array and exact element capacity.
    let count = unsafe { GetConsoleProcessList(members.as_mut_ptr(), members.len() as u32) };
    if count == 0 || count as usize > members.len() {
        return Err(input(
            "console helper",
            "a complete bounded console membership read",
        ));
    }
    let members = &members[..count as usize];
    if !members.contains(&request.root.pid.0) {
        return Err(input(
            "console helper",
            "the original root in its independent console",
        ));
    }
    let mut pins = Vec::new();
    for pid in members
        .iter()
        .copied()
        .filter(|pid| *pid != std::process::id())
    {
        let pin = lookup(ProcessId(pid))?
            .ok_or_else(|| input("console helper", "stable console membership"))?;
        let mut member = 0;
        // SAFETY: retained query-only process/job handles and writable BOOL.
        if unsafe { IsProcessInJob(pin.0, job.0, &mut member) } == 0 {
            return Err(last(
                ProcErrorCode::StopDispatchFailed,
                "verify console job membership",
            ));
        }
        if member == 0 {
            return Err(input(
                "console helper",
                "no foreign processes in the private console",
            ));
        }
        pins.push(pin);
    }
    if !matches!(observe(&request.root, &root)?, ProcessObservation::Live(_)) {
        return Ok(StopDispatch::NotNeeded);
    }
    // SAFETY: only the verified private console receives Ctrl+C; this helper
    // ignores it. Dispatch is not evidence that any target has stopped.
    if unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) } == 0 {
        return Err(last(
            ProcErrorCode::StopDispatchFailed,
            "dispatch private console Ctrl+C",
        ));
    }
    Ok(StopDispatch::Requested)
}
