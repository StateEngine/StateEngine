use super::*;
use crate::ScopeIdentity;
use std::{
    collections::BTreeMap,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::ConvertSidToStringSidW, *},
    Storage::FileSystem::{FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE, GetFileType},
    System::{
        Console::*, Diagnostics::ToolHelp::*, JobObjects::*, SystemServices::JOB_OBJECT_QUERY,
        Threading::*,
    },
};

fn last(operation: &'static str) -> OwnerProbeError {
    native(operation, io::Error::last_os_error())
}
fn handle(raw: HANDLE, operation: &'static str) -> Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(last(operation));
    }
    // SAFETY: the successful creation/open call transfers one native reference.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
fn owner(process: &OwnedHandle) -> Result<NativeOwner> {
    let mut raw = ptr::null_mut();
    // SAFETY: retained process query handle and writable owned-token output.
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last("open current OS owner token"));
    }
    let token = handle(raw, "open current OS owner token")?;
    let mut size = 0;
    // SAFETY: documented sizing call with null buffer and writable length output.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut size,
        );
    }
    if size < size_of::<TOKEN_USER>() as u32 || size > 65536 {
        return Err(refuse("read current OS owner", "invalid token user size"));
    }
    let mut data = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    // SAFETY: retained token handle and aligned output buffer with explicit byte capacity.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            data.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(last("read current OS owner"));
    }
    // SAFETY: aligned successful TOKEN_USER buffer remains retained while its embedded SID is read.
    let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
    let mut text = ptr::null_mut();
    // SAFETY: retained valid token SID and writable LocalFree-owned text output.
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(last("encode current OS owner SID"));
    }
    let mut length = 0;
    // SAFETY: native SID conversion returns a terminated UTF-16 allocation retained through this scan.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: length was measured inside the retained native UTF-16 allocation.
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) });
    // SAFETY: text was allocated by the matching LocalFree-family conversion API.
    unsafe {
        LocalFree(text.cast());
    }
    Ok(NativeOwner::Windows {
        sid: sid.map_err(|_| refuse("encode current OS owner SID", "invalid native SID text"))?,
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
    let snapshot = handle(
        // SAFETY: native POD output accepts an all-zero initialization.
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) },
        "snapshot native ancestry",
    )?;
    // SAFETY: native POD output accepts an all-zero initialization.
    let mut entry: PROCESSENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: retained snapshot and initialized PROCESSENTRY32W with its exact native size.
    if unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } == 0 {
        return Err(last("read native ancestry snapshot"));
    }
    let mut result = BTreeMap::new();
    loop {
        if result.len() >= 65536 {
            return Err(refuse(
                "read native ancestry",
                "process snapshot capacity exceeded",
            ));
        }
        if result
            .insert(entry.th32ProcessID, entry.th32ParentProcessID)
            .is_some()
        {
            return Err(refuse(
                "read native ancestry",
                "duplicate PID in process snapshot",
            ));
        }
        // SAFETY: retained snapshot and writable, correctly sized process-entry output.
        if unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } == 0 {
            // SAFETY: reads this thread's immediately preceding native error without clearing it.
            if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
                return Err(last("finish native ancestry snapshot"));
            }
            break;
        }
    }
    Ok(result)
}
fn open(pid: ProcessId) -> Result<Option<OwnedHandle>> {
    // SAFETY: reads this thread's immediately preceding native error without clearing it.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid.0,
        )
    };
    // SAFETY: native POD output accepts an all-zero initialization.
    if raw.is_null() && unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
        return Ok(None);
    }
    handle(raw, "open native ancestor").map(Some)
}
fn stamp(pid: ProcessId, parent: ProcessId, process: &OwnedHandle) -> Result<ProcessStamp> {
    let (mut created, mut exited, mut kernel, mut user): (FILETIME, FILETIME, FILETIME, FILETIME) =
        // SAFETY: native POD output accepts an all-zero initialization.
        unsafe { zeroed() };
    // SAFETY: retained process query handle and four initialized FILETIME outputs.
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(last("read native ancestor start"));
    }
    Ok(ProcessStamp {
        pid,
        parent,
        group: ProcessId(0),
        session: ProcessId(0),
        boot: BootIdentity::WindowsAbsoluteCreationClock,
        start: StartIdentity::Windows {
            creation_filetime: (created.dwHighDateTime as u64) << 32 | created.dwLowDateTime as u64,
        },
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
    let snapshot = parents()?;
    let mut pid = target;
    let mut ancestry: Vec<(ProcessStamp, OwnedHandle)> = Vec::new();
    let mut exited_creator: Option<(ProcessStamp, OwnedHandle)> = None;
    while pid.0 != 0 {
        if ancestry.len() >= 4096 || ancestry.iter().any(|(p, _)| p.pid == pid) {
            return Err(refuse(
                "read native ancestry",
                "ancestry cycle or capacity exceeded",
            ));
        }
        // Windows retains the numeric creator PID after that process exits.
        // A positively absent/reused creator ends the live chain. Job membership
        // remains independently checked, including after a leader has exited.
        let Some(process) = open(pid)? else {
            break;
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
        let Some(parent) = snapshot.get(&pid.0).copied() else {
            return Err(refuse(
                "read native ancestry",
                "live ancestor missing from snapshot",
            ));
        };
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
            // SAFETY: reads this thread's immediately preceding native error without clearing it.
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
    let recheck = parents()?;
    for (expected, process) in &ancestry {
        if recheck.get(&expected.pid.0).copied() != Some(expected.parent.0) {
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
    })
}
