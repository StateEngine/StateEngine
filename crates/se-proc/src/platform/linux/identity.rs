use crate::support::*;
use crate::*;
use std::{
    fs,
    io::{self, Read},
    path::Path,
};

pub(super) struct Stat {
    pub state: NativeState,
    pub parent: ProcessId,
    pub group: ProcessId,
    pub start: u64,
}
pub(super) fn absent(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))
}
pub(super) fn bytes(path: &Path, max: usize) -> ProcResult<Vec<u8>> {
    let f = fs::File::open(path)
        .map_err(|e| native(ProcErrorCode::IdentityUnreadable, "open proc identity", e))?;
    let mut data = Vec::new();
    f.take(max as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| native(ProcErrorCode::IdentityUnreadable, "read proc identity", e))?;
    if data.len() > max {
        return Err(capacity("native identity bytes", max as u64));
    }
    Ok(data)
}
pub(super) fn boot() -> ProcResult<BootIdentity> {
    let data = bytes(Path::new("/proc/sys/kernel/random/boot_id"), 64)?;
    let mut id = [0; 16];
    let digits: Vec<_> = data
        .iter()
        .copied()
        .filter(|b| *b != b'-' && !b.is_ascii_whitespace())
        .collect();
    if digits.len() != 32 {
        return Err(input("boot identity", "malformed kernel UUID"));
    }
    for (i, pair) in digits.chunks_exact(2).enumerate() {
        let digit = |b: u8| match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            _ => Err(input("boot identity", "malformed kernel UUID")),
        };
        id[i] = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    Ok(BootIdentity::Linux { boot_id: id })
}
pub(super) fn stat(pid: ProcessId) -> ProcResult<Option<Stat>> {
    valid_pid(pid)?;
    let path = format!("/proc/{}/stat", pid.0);
    let data = match fs::File::open(&path) {
        Ok(f) => {
            let mut data = Vec::new();
            match f.take(4097).read_to_end(&mut data) {
                Ok(_) => (),
                Err(cause) if absent(&cause) => return Ok(None),
                Err(cause) => {
                    return Err(native(
                        ProcErrorCode::IdentityUnreadable,
                        "read proc stat",
                        cause,
                    ));
                }
            }
            data
        }
        Err(e) if absent(&e) => return Ok(None),
        Err(e) => {
            return Err(native(
                ProcErrorCode::IdentityUnreadable,
                "open proc stat",
                e,
            ));
        }
    };
    if data.len() > 4096 {
        return Err(capacity("proc stat", 4096));
    }
    // comm is arbitrary bytes and can itself contain ')' and spaces.
    let split = data
        .windows(2)
        .rposition(|p| p == b") ")
        .ok_or_else(|| input("proc stat", "missing final comm delimiter"))?;
    let fields: Vec<_> = data[split + 2..]
        .split(u8::is_ascii_whitespace)
        .filter(|f| !f.is_empty())
        .collect();
    let number = |index: usize| -> ProcResult<u64> {
        let value = fields
            .get(index)
            .ok_or_else(|| input("proc stat", "truncated numeric suffix"))?;
        std::str::from_utf8(value)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| input("proc stat", "invalid numeric suffix"))
    };
    let state = match fields.first().copied() {
        Some(b"Z" | b"X" | b"x") => NativeState::ExitedAwaitingReap,
        Some(b"T" | b"t") => NativeState::Stopped,
        Some([_]) => NativeState::Running,
        _ => return Err(input("proc stat", "invalid state")),
    };
    let pid_value = |index| {
        number(index).and_then(|n| {
            u32::try_from(n)
                .map(ProcessId)
                .map_err(|_| input("proc stat", "PID overflow"))
        })
    };
    Ok(Some(Stat {
        state,
        parent: pid_value(1)?,
        group: pid_value(2)?,
        start: number(19)?,
    }))
}
pub(super) fn valid_pid(pid: ProcessId) -> ProcResult<()> {
    if pid.0 == 0 || pid.0 > i32::MAX as u32 {
        return Err(input("pid", "must be a positive native PID"));
    }
    Ok(())
}
/// Exact live identity check without sampling the observation wall clock.
/// Used while the birth-time adapter independently retains a native pidfd.
pub(crate) fn verify_live_identity(expected: &ProcessIdentity) -> ProcResult<()> {
    let boot = boot()?;
    let before = stat(expected.pid)?.ok_or_else(|| changed(expected, None))?;
    let image = fs::read_link(format!("/proc/{}/exe", expected.pid.0)).map_err(|e| {
        native(
            ProcErrorCode::IdentityUnreadable,
            "read birth-time executable",
            e,
        )
    })?;
    let after = stat(expected.pid)?.ok_or_else(|| changed(expected, None))?;
    let final_image = fs::read_link(format!("/proc/{}/exe", expected.pid.0)).map_err(|e| {
        native(
            ProcErrorCode::IdentityUnreadable,
            "recheck birth-time executable",
            e,
        )
    })?;
    let found = ProcessIdentity {
        machine: expected.machine.clone(),
        boot,
        pid: expected.pid,
        start: StartIdentity::Linux {
            start_ticks: before.start,
        },
        image,
    };
    if before.state == NativeState::ExitedAwaitingReap
        || after.state == NativeState::ExitedAwaitingReap
        || before.start != after.start
        || found.image != final_image
        || &found != expected
    {
        return Err(changed(expected, Some(&found)));
    }
    Ok(())
}
pub(crate) fn read_process(machine: MachineId, pid: ProcessId) -> ProcResult<ProcessRead> {
    let boot = boot()?;
    let Some(before) = stat(pid)? else {
        return Ok(ProcessRead::Absent {
            pid,
            observed_at_unix_ns: now()?,
        });
    };
    let start = StartIdentity::Linux {
        start_ticks: before.start,
    };
    if before.state == NativeState::ExitedAwaitingReap {
        return Ok(ProcessRead::ExitedRecord {
            pid,
            boot,
            start,
            state: before.state,
            status: ExitStatus::Unavailable {
                reason: ExitStatusUnavailable::NotOurChild,
            },
            observed_at_unix_ns: now()?,
        });
    }
    let image = fs::read_link(format!("/proc/{}/exe", pid.0));
    let Some(after) = stat(pid)? else {
        return Ok(ProcessRead::Absent {
            pid,
            observed_at_unix_ns: now()?,
        });
    };
    if before.start != after.start {
        return Err(error(
            ProcErrorCode::IdentityChanged,
            ProcErrorDetail::Identity {
                pid,
                expected_start: Some(start),
                found_start: Some(StartIdentity::Linux {
                    start_ticks: after.start,
                }),
                expected: None,
                found: None,
            },
        ));
    }
    if after.state == NativeState::ExitedAwaitingReap {
        return Ok(ProcessRead::ExitedRecord {
            pid,
            boot,
            start,
            state: after.state,
            status: ExitStatus::Unavailable {
                reason: ExitStatusUnavailable::NotOurChild,
            },
            observed_at_unix_ns: now()?,
        });
    }
    let image = match image {
        Ok(image) => image,
        Err(cause) => return executable_failure(machine, pid, before.start, boot, cause),
    };
    let final_image = match fs::read_link(format!("/proc/{}/exe", pid.0)) {
        Ok(image) => image,
        Err(cause) => return executable_failure(machine, pid, before.start, boot, cause),
    };
    let Some(final_stat) = stat(pid)? else {
        return Ok(ProcessRead::Absent {
            pid,
            observed_at_unix_ns: now()?,
        });
    };
    if final_stat.start != before.start {
        return Err(input(
            "process image",
            "native birth changed during final image read",
        ));
    }
    if final_stat.state == NativeState::ExitedAwaitingReap {
        return Ok(ProcessRead::ExitedRecord {
            pid,
            boot,
            start,
            state: final_stat.state,
            status: ExitStatus::Unavailable {
                reason: ExitStatusUnavailable::NotOurChild,
            },
            observed_at_unix_ns: now()?,
        });
    }
    if image != final_image {
        return Err(input(
            "process image",
            "exec changed during identity read; retry observation",
        ));
    }
    Ok(ProcessRead::Present(LiveObservation {
        identity: ProcessIdentity {
            machine,
            boot,
            pid,
            start,
            image,
        },
        state: after.state,
        parent: Some(after.parent),
        observed_at_unix_ns: now()?,
    }))
}
fn executable_failure(
    _machine: MachineId,
    pid: ProcessId,
    start: u64,
    boot: BootIdentity,
    cause: io::Error,
) -> ProcResult<ProcessRead> {
    // ENOENT at /proc/PID/exe can mean the process exited between reads. Only
    // fresh native absence/zombie evidence converts it into an exit fact;
    // a running process without a readable image remains an error.
    if absent(&cause) {
        match stat(pid)? {
            None => {
                return Ok(ProcessRead::Absent {
                    pid,
                    observed_at_unix_ns: now()?,
                });
            }
            Some(found)
                if found.start == start && found.state == NativeState::ExitedAwaitingReap =>
            {
                return Ok(ProcessRead::ExitedRecord {
                    pid,
                    boot,
                    start: StartIdentity::Linux { start_ticks: start },
                    state: found.state,
                    status: ExitStatus::Unavailable {
                        reason: ExitStatusUnavailable::NotOurChild,
                    },
                    observed_at_unix_ns: now()?,
                });
            }
            Some(found) if found.start != start => {
                return Err(input(
                    "process image",
                    "native birth changed while executable became unreadable",
                ));
            }
            _ => (),
        }
    }
    Err(native(
        ProcErrorCode::IdentityUnreadable,
        "read proc executable",
        cause,
    ))
}
pub(super) fn observe(expected: &ProcessIdentity) -> ProcResult<ProcessObservation> {
    match read_process(expected.machine.clone(), expected.pid)? {
        ProcessRead::Absent {
            observed_at_unix_ns,
            ..
        } => Ok(ProcessObservation::Exited {
            expected: expected.clone(),
            evidence: ExitEvidence::Absent,
            status: ExitStatus::Unavailable {
                reason: ExitStatusUnavailable::NotOurChild,
            },
            observed_at_unix_ns,
        }),
        ProcessRead::ExitedRecord {
            boot,
            start,
            state,
            status,
            observed_at_unix_ns,
            ..
        } => {
            if boot != expected.boot || start != expected.start {
                return Err(changed(expected, None));
            }
            Ok(ProcessObservation::Exited {
                expected: expected.clone(),
                evidence: ExitEvidence::NativeExitedRecord { state },
                status,
                observed_at_unix_ns,
            })
        }
        ProcessRead::Present(live) if live.identity == *expected => {
            Ok(ProcessObservation::Live(live))
        }
        ProcessRead::Present(live)
            if live.identity.start != expected.start || live.identity.boot != expected.boot =>
        {
            Ok(ProcessObservation::Exited {
                expected: expected.clone(),
                evidence: ExitEvidence::Replaced {
                    observed: live.identity,
                },
                status: ExitStatus::Unavailable {
                    reason: ExitStatusUnavailable::NotOurChild,
                },
                observed_at_unix_ns: now()?,
            })
        }
        ProcessRead::Present(live) => Err(changed(expected, Some(&live.identity))),
    }
}
