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
        // A redirected or closed stream is an observed lack of a terminal.
        if matches!(error.raw_os_error(), Some(libc::ENOTTY | libc::EBADF)) {
            Ok(false)
        } else {
            Err(native("inspect console stream", error))
        }
    };
    let stdin = console(libc::STDIN_FILENO)?;
    let stdout = console(libc::STDOUT_FILENO)?;
    Ok((stdin, stdout))
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
    let mut ancestry = Vec::new();
    let mut next = pid;
    while next.0 != 0 {
        if ancestry.len() >= 4096 || ancestry.iter().any(|p: &ProcessStamp| p.pid == next) {
            return Err(refuse(
                "read owner ancestry",
                "ancestry cycle or capacity exceeded",
            ));
        }
        let current = os::stamp(next, &boot)?;
        next = current.parent;
        ancestry.push(current);
    }
    let current = ancestry
        .first()
        .ok_or_else(|| refuse("read owner ancestry", "current process absent"))?;
    let mut matches = Vec::new();
    for (record_index, record) in records.iter().enumerate() {
        // A boot mismatch is positive evidence that an old native scope cannot
        // contain this process. It is not a missing-record inference.
        if record.root.boot != boot {
            continue;
        }
        let basis = if current.instance_matches(&record.root) {
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
                    if (BootIdentity::Linux { boot_id: *boot_id }) != boot {
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
        };
        if let Some(basis) = basis {
            matches.push(AgentTreeMatch {
                record_index,
                basis,
            });
        }
    }
    // Re-read the complete chain, not just its leaf, so disappearing/reused
    // ancestors or reparenting cannot turn an unreadable chain into Outside.
    for expected in &ancestry {
        if os::stamp(expected.pid, &boot)? != *expected {
            return Err(refuse(
                "recheck owner ancestry",
                "ancestry changed during observation",
            ));
        }
    }
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
    })
}
