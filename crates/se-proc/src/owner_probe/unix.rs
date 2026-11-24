#[cfg(target_os = "linux")]
use super::linux as os;
#[cfg(target_os = "macos")]
use super::macos as os;
use super::*;
use crate::ScopeIdentity;

pub(super) fn console() -> Result<(bool, bool)> {
    let console = |fd| -> Result<bool> {
        // SAFETY: native standard descriptor selector; error remains distinct from non-terminal.
        if unsafe { libc::isatty(fd) } == 1 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENOTTY | libc::EBADF) => Ok(false),
            // Darwin reports EOPNOTSUPP for terminal ioctls on sockets.
            Some(libc::EOPNOTSUPP) if is_socket(fd) => Ok(false),
            _ => Err(native("inspect console stream", error)),
        }
    };
    let stdin = console(libc::STDIN_FILENO)?;
    let stdout = console(libc::STDOUT_FILENO)?;
    Ok((stdin, stdout))
}

fn is_socket(fd: libc::c_int) -> bool {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: fstat writes only to the provided buffer and initializes it on success.
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0 {
        return false;
    }
    // SAFETY: the successful fstat initialized metadata.
    let mode = unsafe { metadata.assume_init() }.st_mode;
    mode & libc::S_IFMT == libc::S_IFSOCK
}

pub(super) fn observe(
    pid: ProcessId,
    expected: Option<&StartIdentity>,
    records: &[ProcessRecord],
) -> Result<OwnerTreeObservation> {
    let boot = os::boot()?;
    let first = os::stamp(pid, &boot)?;
    if expected.is_some_and(|expected| expected != &first.start) {
        return Err(refuse(
            "bind observed owner",
            "target process start changed",
        ));
    }
    let owner = os::owner(pid)?;
    #[cfg(target_os = "macos")]
    let walk = os::ancestry::observe(pid, &boot, records)?;
    #[cfg(target_os = "macos")]
    let ancestry = &walk.verified;
    #[cfg(target_os = "linux")]
    let ancestry = &linux_ancestry(pid, &boot)?;
    let current = ancestry
        .first()
        .ok_or_else(|| refuse("read owner ancestry", "current process absent"))?;
    let mut matches = Vec::new();
    for (record_index, record) in records.iter().enumerate() {
        if let Some(basis) = record_basis(record, pid, current, ancestry, &boot)? {
            matches.push(AgentTreeMatch {
                record_index,
                basis,
            });
        }
    }
    // Re-read every verified ancestor, not just the leaf, so disappearing/reused
    // ancestors or reparenting cannot turn an unreadable chain into Outside.
    for expected in ancestry.iter() {
        if os::stamp(expected.pid, &boot)? != *expected {
            return Err(refuse(
                "recheck owner ancestry",
                "ancestry changed during observation",
            ));
        }
    }
    #[cfg(target_os = "macos")]
    walk.recheck()?;
    if owner != os::owner(pid)? || os::stamp(pid, &boot)? != first {
        return Err(refuse(
            "recheck native owner",
            "target owner or process changed during observation",
        ));
    }
    Ok(OwnerTreeObservation {
        owner,
        pid,
        start: first.start,
        agent_trees: matches,
        #[cfg(target_os = "linux")]
        ancestry_bound: AncestryBound::Complete,
        #[cfg(target_os = "macos")]
        ancestry_bound: walk.bound,
    })
}

/// Walk the parent chain from `pid` to the root, refusing cycles and runaway depth.
#[cfg(target_os = "linux")]
fn linux_ancestry(pid: ProcessId, boot: &BootIdentity) -> Result<Vec<ProcessStamp>> {
    let mut ancestry = Vec::new();
    let mut next = pid;
    while next.0 != 0 {
        if ancestry.len() >= 4096 || ancestry.iter().any(|p: &ProcessStamp| p.pid == next) {
            return Err(refuse(
                "read owner ancestry",
                "ancestry cycle or capacity exceeded",
            ));
        }
        let current = os::stamp(next, boot)?;
        next = current.parent;
        ancestry.push(current);
    }
    Ok(ancestry)
}

/// How this process belongs to one recorded agent tree, if it does. A record
/// from another boot is positive evidence of no containment; an inconsistent or
/// unresolved scope is refused rather than read as Outside.
fn record_basis(
    record: &ProcessRecord,
    pid: ProcessId,
    current: &ProcessStamp,
    ancestry: &[ProcessStamp],
    boot: &BootIdentity,
) -> Result<Option<AgentTreeBasis>> {
    // Only the Linux cgroup scope reads the target's membership directly.
    #[cfg(target_os = "macos")]
    let _ = pid;
    // A boot mismatch is positive evidence that an old native scope cannot
    // contain this process. It is not a missing-record inference.
    if record.root.boot != *boot {
        return Ok(None);
    }
    Ok(if current.instance_matches(&record.root) {
        Some(AgentTreeBasis::ExactRoot)
    } else if ancestry
        .iter()
        .skip(1)
        .any(|p| p.instance_matches(&record.root))
    {
        Some(AgentTreeBasis::Ancestor)
    } else {
        match &record.scope {
            ScopeIdentity::LinuxTracked {
                process_group,
                root,
            } if cfg!(target_os = "linux") => {
                if root != &record.root || process_group.0 == 0 {
                    return Err(refuse(
                        "inspect managed group",
                        "inconsistent recorded group/root",
                    ));
                }
                if current.group == *process_group {
                    Some(AgentTreeBasis::ProcessGroup)
                } else if current.session == root.pid {
                    Some(AgentTreeBasis::Session)
                } else {
                    None
                }
            }
            ScopeIdentity::MacOsTracked {
                process_group,
                root,
            } if cfg!(target_os = "macos") => {
                if root != &record.root || process_group.0 == 0 {
                    return Err(refuse(
                        "inspect managed group",
                        "inconsistent recorded group/root",
                    ));
                }
                if current.session == root.pid {
                    Some(AgentTreeBasis::Session)
                } else if current.group == *process_group {
                    Some(AgentTreeBasis::ProcessGroup)
                } else {
                    None
                }
            }
            #[cfg(target_os = "linux")]
            ScopeIdentity::LinuxCgroup {
                path,
                device,
                inode,
                boot_id,
            } => {
                if (BootIdentity::Linux { boot_id: *boot_id }) != *boot {
                    return Err(refuse("inspect managed cgroup", "inconsistent cgroup boot"));
                }
                if os::in_cgroup(pid, path, *device, *inode)? {
                    Some(AgentTreeBasis::Cgroup)
                } else {
                    None
                }
            }
            _ => {
                return Err(refuse(
                    "inspect managed scope",
                    "unresolved or incompatible recorded scope",
                ));
            }
        }
    })
}
