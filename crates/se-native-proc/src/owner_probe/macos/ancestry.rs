//! Preserve a protected ancestor boundary without treating numeric PIDs as births.
use super::*;

#[derive(Debug, Eq, PartialEq)]
struct Parent {
    pid: ProcessId,
    parent: ProcessId,
    group: ProcessId,
    owner: NativeOwner,
}

fn parent(pid: ProcessId) -> Result<Parent> {
    if pid.0 == 0 || pid.0 > i32::MAX as u32 {
        return Err(refuse("inspect bounded ancestry", "invalid process ID"));
    }
    // SAFETY: native POD output accepts an all-zero initialization.
    let mut info: libc::proc_bsdshortinfo = unsafe { zeroed() };
    let wanted = size_of::<libc::proc_bsdshortinfo>() as i32;
    // SAFETY: positive PID and correctly sized aligned native short-info output.
    let count = unsafe {
        libc::proc_pidinfo(
            pid.0 as i32,
            libc::PROC_PIDT_SHORTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdshortinfo).cast(),
            wanted,
        )
    };
    if count <= 0 {
        return Err(native(
            "inspect bounded ancestry",
            io::Error::last_os_error(),
        ));
    }
    if count != wanted || info.pbsi_pid != pid.0 {
        return Err(refuse(
            "inspect bounded ancestry",
            "short or mismatched native result",
        ));
    }
    Ok(Parent {
        pid,
        parent: ProcessId(info.pbsi_ppid),
        group: ProcessId(info.pbsi_pgid),
        owner: NativeOwner::Unix {
            real_uid: info.pbsi_ruid,
            effective_uid: info.pbsi_uid,
        },
    })
}

pub(in super::super) struct Ancestry {
    pub(in super::super) verified: Vec<ProcessStamp>,
    pub(in super::super) bound: AncestryBound,
    protected: Vec<Parent>,
}
impl Ancestry {
    pub(in super::super) fn recheck(&self) -> Result<()> {
        for expected in &self.protected {
            if parent(expected.pid)? != *expected {
                return Err(refuse(
                    "recheck bounded ancestry",
                    "ancestry changed during observation",
                ));
            }
        }
        Ok(())
    }
}

pub(in super::super) fn observe(
    target: ProcessId,
    boot: &BootIdentity,
    records: &[ProcessRecord],
) -> Result<Ancestry> {
    let mut walk = Ancestry {
        verified: Vec::new(),
        protected: Vec::new(),
        bound: AncestryBound::Complete,
    };
    let mut next = target;
    let mut seen = std::collections::BTreeSet::new();
    while next.0 != 0 {
        if seen.len() >= 4096 || !seen.insert(next.0) {
            return Err(refuse(
                "read owner ancestry",
                "ancestry cycle or capacity exceeded",
            ));
        }
        match stamp(next, boot) {
            Ok(current) => {
                next = current.parent;
                walk.verified.push(current);
            }
            Err(cause)
                if next != target
                    && cause.operation == "read owner ancestry"
                    && cause.source.raw_os_error() == Some(libc::EPERM) =>
            {
                walk.bound = AncestryBound::UnopenableAncestor {
                    pid: next,
                    native_code: cause.source.raw_os_error(),
                    reason: format!("ancestor birth is protected: {}", cause.source),
                };
                // Short BSD info is available across native user boundaries, but
                // has no birth. Never match a managed root with these numbers.
                // Every recorded root PID above the bound therefore refuses.
                loop {
                    if records.iter().any(|record| record.root.pid == next) {
                        return Err(refuse(
                            "inspect bounded ancestry",
                            "protected ancestor chain reaches a recorded agent root PID; birth cannot be verified",
                        ));
                    }
                    let current = parent(next)?;
                    next = current.parent;
                    walk.protected.push(current);
                    if next.0 == 0 {
                        break;
                    }
                    if seen.len() >= 4096 || !seen.insert(next.0) {
                        return Err(refuse(
                            "inspect bounded ancestry",
                            "ancestry cycle or capacity exceeded",
                        ));
                    }
                }
                break;
            }
            Err(cause) => return Err(cause),
        }
    }
    Ok(walk)
}
