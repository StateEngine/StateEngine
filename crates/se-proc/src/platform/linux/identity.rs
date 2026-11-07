use crate::linux_native::{self, ProcStat, StatError};
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
    pub group: Option<ProcessId>,
    pub start: u64,
}
pub(super) fn absent(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH))
}
pub(super) fn bytes(path: &Path, max: usize) -> ProcResult<Vec<u8>> {
    let f = fs::File::open(path)
        .map_err(|e| native(ProcErrorCode::IdentityUnreadable, "open proc identity", e))?;
    let mut data = Vec::with_capacity(max.saturating_add(1).min(4096));
    f.take(max as u64 + 1)
        .read_to_end(&mut data)
        .map_err(|e| native(ProcErrorCode::IdentityUnreadable, "read proc identity", e))?;
    if data.len() > max {
        return Err(capacity("native identity bytes", max as u64));
    }
    Ok(data)
}
pub(super) fn boot() -> ProcResult<BootIdentity> {
    let data = bytes(
        Path::new("/proc/sys/kernel/random/boot_id"),
        linux_native::BOOT_ID_BYTES,
    )?;
    let boot_id = linux_native::boot_id(&data)
        .ok_or_else(|| input("boot identity", "malformed kernel UUID"))?;
    Ok(BootIdentity::Linux { boot_id })
}
fn stat_error(error: StatError) -> ProcError {
    input(
        "proc stat",
        match error {
            StatError::MissingDelimiter => "missing final comm delimiter",
            StatError::InvalidState => "invalid state",
            StatError::TruncatedNumber => "truncated numeric suffix",
            StatError::InvalidNumber => "invalid numeric suffix",
            StatError::PidOverflow => "PID overflow",
        },
    )
}
pub(super) fn stat(pid: ProcessId) -> ProcResult<Option<Stat>> {
    valid_pid(pid)?;
    let path = format!("/proc/{}/stat", pid.0);
    let data = match fs::File::open(&path) {
        Ok(f) => {
            let mut data = Vec::with_capacity(linux_native::STAT_BYTES + 1);
            match f
                .take(linux_native::STAT_BYTES as u64 + 1)
                .read_to_end(&mut data)
            {
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
    if data.len() > linux_native::STAT_BYTES {
        return Err(capacity("proc stat", linux_native::STAT_BYTES as u64));
    }
    let facts = ProcStat::parse(&data).map_err(stat_error)?;
    let state = match facts.state().map_err(stat_error)? {
        b'Z' | b'X' | b'x' => NativeState::ExitedAwaitingReap,
        b'T' | b't' => NativeState::Stopped,
        _ => NativeState::Running,
    };
    Ok(Some(Stat {
        state,
        parent: ProcessId(facts.parent().map_err(stat_error)?),
        // A task that has lost its sighand can report X with pgrp/sid -1.
        // Its birth still proves which task exited, but it no longer supplies
        // group membership. Never turn that terminal sentinel into a PID.
        group: if state == NativeState::ExitedAwaitingReap {
            None
        } else {
            Some(ProcessId(facts.group().map_err(stat_error)?))
        },
        start: facts.start_ticks().map_err(stat_error)?,
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
    let mut image = match image {
        Ok(image) => image,
        Err(cause) => return executable_failure(machine, pid, before.start, boot, cause),
    };
    // A live group member may exec between image reads. Resample at most three
    // times, retaining the original birth; no cached identity or renewed clock.
    for _ in 0..3 {
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
        if image == final_image {
            return Ok(ProcessRead::Present(LiveObservation {
                identity: ProcessIdentity {
                    machine,
                    boot,
                    pid,
                    start,
                    image,
                },
                state: final_stat.state,
                parent: Some(final_stat.parent),
                observed_at_unix_ns: now()?,
            }));
        }
        image = final_image;
    }
    Err(input(
        "process image",
        "exec changed during identity read; retry observation",
    ))
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
pub(crate) fn read_process_until(
    machine: MachineId,
    pid: ProcessId,
    deadline: std::time::Instant,
) -> ProcResult<ProcessRead> {
    loop {
        let mut original = match read_process(machine.clone(), pid) {
            Ok(observed) => return Ok(observed),
            Err(error)
                if error.code == ProcErrorCode::IdentityUnreadable
                    && error.native.as_ref().is_some_and(|failure| {
                        failure.api == "read proc executable"
                            && matches!(failure.code, Some(code) if code == i64::from(libc::ENOENT) || code == i64::from(libc::ESRCH))
                    }) => error,
            Err(error) => return Err(error),
        };
        // exit_group can remove exe before stat becomes terminal. ENOENT is
        // only a reason to reread: read_process must still prove absence or a
        // native exited record, or return the actual live identity. A genuinely
        // unreadable live task stays unreadable at the caller's original bound.
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            if let ProcErrorDetail::Input { reason, .. } = original.detail.as_mut() {
                reason.push_str("; inconclusive process teardown at original observation deadline");
            }
            return Err(original);
        }
        std::thread::park_timeout(remaining.min(std::time::Duration::from_millis(10)));
    }
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
