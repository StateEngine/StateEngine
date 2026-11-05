use super::*;
use crate::ScopeIdentity;
use std::{
    collections::BTreeMap,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, OwnedHandle},
    },
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::{FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE, GetFileType},
    System::{Console::*, JobObjects::*, SystemServices::JOB_OBJECT_QUERY, Threading::*},
};

fn last(operation: &'static str) -> OwnerProbeError {
    native(operation, io::Error::last_os_error())
}
fn handle(raw: HANDLE, operation: &'static str) -> Result<OwnedHandle> {
    crate::windows_native::handle(raw, operation).map_err(|e| native(e.operation, e.source))
}
fn owner(process: &OwnedHandle) -> Result<NativeOwner> {
    Ok(NativeOwner::Windows {
        sid: crate::windows_native::process_sid(process.as_raw_handle())
            .map_err(|e| native(e.operation, e.source))?,
    })
}
fn console(which: STD_HANDLE) -> Result<bool> {
    // SAFETY: standard-handle selector is a native constant; no pointers are dereferenced.
    let stream = unsafe { GetStdHandle(which) };
    if stream.is_null() {
        return Ok(false);
    }
    if stream == INVALID_HANDLE_VALUE {
        return Err(last("read standard stream"));
    }
    let mut mode = 0;
    // SAFETY: borrowed standard handle and initialized writable mode output.
    if unsafe { GetConsoleMode(stream, &mut mode) } != 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    // SAFETY: immutable type query on the borrowed standard-stream handle.
    match unsafe { GetFileType(stream) } {
        FILE_TYPE_DISK | FILE_TYPE_PIPE => Ok(false),
        FILE_TYPE_CHAR if error.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32) => Ok(false),
        _ => Err(native("inspect console stream", error)),
    }
}
fn parents() -> Result<BTreeMap<u32, u32>> {
    crate::windows_native::parents().map_err(|e| native(e.operation, e.source))
}
fn snapshot(value: &mut Option<BTreeMap<u32, u32>>) -> Result<&BTreeMap<u32, u32>> {
    if value.is_none() {
        *value = Some(parents()?);
    }
    value
        .as_ref()
        .ok_or_else(|| refuse("read native ancestry", "native snapshot unavailable"))
}
fn parent(
    pid: ProcessId,
    process: &OwnedHandle,
    fallback: &mut Option<BTreeMap<u32, u32>>,
) -> Result<u32> {
    if let Some(value) = crate::windows_native::parent(process.as_raw_handle(), pid.0)
        .map_err(|e| native(e.operation, e.source))?
    {
        return Ok(value);
    }
    snapshot(fallback)?.get(&pid.0).copied().ok_or_else(|| {
        refuse(
            "read native ancestry",
            "live ancestor missing from snapshot",
        )
    })
}
fn open(pid: ProcessId) -> Result<Option<OwnedHandle>> {
    // SAFETY: query/synchronize rights on a numeric ancestor selector; no mutation or inheritance.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid.0,
        )
    };
    // SAFETY: reads the immediately preceding OpenProcess error on this thread.
    if raw.is_null() && unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
        return Ok(None);
    }
    handle(raw, "open native ancestor").map(Some)
}
fn stamp(pid: ProcessId, parent: ProcessId, process: &OwnedHandle) -> Result<ProcessStamp> {
    let creation_filetime = crate::windows_native::process_start(process.as_raw_handle())
        .map_err(|e| native(e.operation, e.source))?;
    Ok(ProcessStamp {
        pid,
        parent,
        group: ProcessId(0),
        session: ProcessId(0),
        boot: BootIdentity::WindowsAbsoluteCreationClock,
        start: StartIdentity::Windows { creation_filetime },
    })
}
pub(super) fn console_presence() -> Result<(bool, bool)> {
    Ok((console(STD_INPUT_HANDLE)?, console(STD_OUTPUT_HANDLE)?))
}
pub(super) fn observe(
    target: ProcessId,
    expected: Option<&StartIdentity>,
    records: &[ProcessRecord],
) -> Result<OwnerTreeObservation> {
    let target_pin =
        open(target)?.ok_or_else(|| refuse("bind observed owner", "target process absent"))?;
    let first = stamp(target, ProcessId(0), &target_pin)?;
    if expected.is_some_and(|expected| expected != &first.start) {
        return Err(refuse(
            "bind observed owner",
            "target process start changed",
        ));
    }
    // SAFETY: retained SYNCHRONIZE process handle; zero timeout does not block.
    if unsafe { WaitForSingleObject(target_pin.as_raw_handle(), 0) } != WAIT_TIMEOUT {
        return Err(refuse(
            "bind observed owner",
            "target is exited or unreadable",
        ));
    }
    let user = owner(&target_pin)?;
    let mut fallback = None;
    let mut pid = target;
    let mut ancestry: Vec<(ProcessStamp, OwnedHandle)> = Vec::new();
    let mut exited_creator: Option<(ProcessStamp, OwnedHandle)> = None;
    let mut ancestry_bound = AncestryBound::Complete;
    while pid.0 != 0 {
        if ancestry.len() >= 4096 {
            return Err(refuse("read native ancestry", "ancestry capacity exceeded"));
        }
        // Windows retains the numeric creator PID after that process exits.
        // A positively absent/reused creator ends the live chain. Job membership
        // remains independently checked, including after a leader has exited.
        let process = match open(pid) {
            Ok(Some(process)) => process,
            Ok(None) => break,
            Err(cause)
                if pid != target
                    && cause.source.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) =>
            {
                // Root queryability is relative to the caller's actual token.
                // A protected SYSTEM creator ends the permitted live walk; keep
                // the actual bound so admission never calls this a full census.
                // Keep following only the snapshot's numeric creators. Those
                // numbers cannot prove outside membership, but a recorded root
                // PID above this bound must conservatively refuse admission.
                let mut unqueried = pid.0;
                let mut seen = std::collections::BTreeSet::new();
                while unqueried != 0 {
                    if seen.len() >= 4096 || !seen.insert(unqueried) {
                        return Err(refuse(
                            "inspect bounded ancestry",
                            "snapshot ancestry cycle or capacity exceeded",
                        ));
                    }
                    if records.iter().any(|record| record.root.pid.0 == unqueried) {
                        return Err(refuse(
                            "inspect bounded ancestry",
                            "unopenable ancestor chain reaches a recorded agent root PID; birth cannot be verified",
                        ));
                    }
                    let Some(parent) = snapshot(&mut fallback)?.get(&unqueried) else {
                        break;
                    };
                    unqueried = *parent;
                }
                ancestry_bound = AncestryBound::UnopenableAncestor {
                    pid,
                    native_code: cause.source.raw_os_error(),
                    reason: format!("ancestor not ours: unopenable ({})", cause.source),
                };
                break;
            }
            Err(cause) => return Err(cause),
        };
        // Toolhelp omits exited objects even while a handle still opens them,
        // and a reused creator may have appeared after the snapshot. Check the
        // actual retained object's birth/liveness before requiring a live row.
        let observed = stamp(pid, ProcessId(0), &process)?;
        if let Some((child, _)) = ancestry.last()
            && let (
                StartIdentity::Windows {
                    creation_filetime: parent,
                },
                StartIdentity::Windows {
                    creation_filetime: child,
                },
            ) = (&observed.start, &child.start)
            && parent > child
        {
            break;
        }
        // A creator PID may now name a younger descendant already pinned in
        // this walk. Its birth ends the chain above; only an older/equal repeated
        // process identity can be an actual cycle.
        if ancestry.iter().any(|(p, _)| p.pid == pid) {
            return Err(refuse("read native ancestry", "ancestry cycle"));
        }
        // SAFETY: retained SYNCHRONIZE process handle; zero timeout observes
        // this exact object's liveness, including an exited retained creator.
        match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => {
                // Keep the immediate exited creator for exact-root admission
                // checks, while ending the live ancestry walk at its exit.
                exited_creator = Some((observed, process));
                break;
            }
            WAIT_TIMEOUT => (),
            _ => return Err(last("inspect native ancestor liveness")),
        }
        let parent = parent(pid, &process, &mut fallback)?;
        let value = stamp(pid, ProcessId(parent), &process)?;
        if let Some((child, _)) = ancestry.last()
            && let (
                StartIdentity::Windows {
                    creation_filetime: a,
                },
                StartIdentity::Windows {
                    creation_filetime: b,
                },
            ) = (&value.start, &child.start)
            && a > b
        {
            break;
        }
        pid = value.parent;
        ancestry.push((value, process));
    }
    let (current, _) = ancestry
        .first()
        .ok_or_else(|| refuse("read native ancestry", "current process absent"))?;
    let mut matches = Vec::new();
    for (record_index, record) in records.iter().enumerate() {
        if record.root.boot != BootIdentity::WindowsAbsoluteCreationClock {
            return Err(refuse(
                "inspect managed job",
                "recorded scope belongs to another platform",
            ));
        }
        let basis = if current.instance_matches(&record.root) {
            Some(AgentTreeBasis::ExactRoot)
        } else if ancestry
            .iter()
            .skip(1)
            .any(|(p, _)| p.instance_matches(&record.root))
            || exited_creator
                .as_ref()
                .is_some_and(|(p, _)| p.instance_matches(&record.root))
        {
            Some(AgentTreeBasis::Ancestor)
        } else {
            let ScopeIdentity::WindowsJob { host, name } = &record.scope else {
                return Err(refuse(
                    "inspect managed job",
                    "unresolved recorded job scope",
                ));
            };
            if host != &record.host || name.is_empty() || name.encode_utf16().any(|c| c == 0) {
                return Err(refuse(
                    "inspect managed job",
                    "inconsistent recorded job identity",
                ));
            }
            let name: Vec<_> = std::ffi::OsStr::new(name)
                .encode_wide()
                .chain(Some(0))
                .collect();
            // SAFETY: bounded terminated recorded job name; query access grants no signal authority.
            let raw = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY, 0, name.as_ptr()) };
            // SAFETY: reads this thread's immediately preceding native error without clearing it.
            if raw.is_null() && unsafe { GetLastError() } == ERROR_FILE_NOT_FOUND {
                None
            } else {
                // Query-only: this never reacquires signal or close authority.
                let job = handle(raw, "open recorded job for membership query")?;
                let mut member = 0;
                // SAFETY: retained query-only job/process handles and initialized membership output.
                if unsafe {
                    IsProcessInJob(target_pin.as_raw_handle(), job.as_raw_handle(), &mut member)
                } == 0
                {
                    return Err(last("query native managed-job membership"));
                }
                if member != 0 {
                    Some(AgentTreeBasis::WindowsJob)
                } else {
                    None
                }
            }
        };
        if let Some(basis) = basis {
            matches.push(AgentTreeMatch {
                record_index,
                basis,
            });
        }
    }
    let mut recheck = None;
    for (expected, process) in &ancestry {
        // A retained handle can still query an exited process. The former
        // Toolhelp recheck excluded those objects; preserve that refusal here.
        // SAFETY: retained SYNCHRONIZE handle and a nonblocking liveness query.
        if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_TIMEOUT
            || parent(expected.pid, process, &mut recheck)? != expected.parent.0
        {
            return Err(refuse(
                "recheck native ancestry",
                "ancestor exited or changed during observation",
            ));
        }
        if stamp(expected.pid, expected.parent, process)? != *expected {
            return Err(refuse(
                "recheck native ancestry",
                "ancestor identity changed",
            ));
        }
    }
    if let Some((expected, process)) = exited_creator {
        // SAFETY: the retained creator handle identifies the same exited object;
        // PID reuse cannot change either this handle or its native birth clock.
        if unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } != WAIT_OBJECT_0
            || stamp(expected.pid, ProcessId(0), &process)?.start != expected.start
        {
            return Err(refuse(
                "recheck native ancestry",
                "exited creator identity changed",
            ));
        }
    }
    // SAFETY: the exact target process remains pinned through the entire walk.
    if unsafe { WaitForSingleObject(target_pin.as_raw_handle(), 0) } != WAIT_TIMEOUT
        || stamp(target, ProcessId(0), &target_pin)?.start != first.start
        || owner(&target_pin)? != user
    {
        return Err(refuse("recheck native owner", "OS owner changed"));
    }
    Ok(OwnerTreeObservation {
        owner: user,
        pid: target,
        start: first.start,
        agent_trees: matches,
        ancestry_bound,
    })
}
