//! Read-only Linux ancestry census. Detached descendants still attached to the
//! recorded root are visible; already reparented escapes cannot be attributed.
//! These diagnostic identities never grant signal authority.
use crate::linux_native::ProcStat;
use crate::support::{capacity, changed, input, native};
use crate::{ProcResult, ProcessId, ProcessIdentity, ProcessRead, StartIdentity};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    time::Instant,
};

pub fn read_process_descendants(
    root: &ProcessIdentity,
    deadline: Instant,
) -> ProcResult<Vec<ProcessIdentity>> {
    let verify_root = || match crate::read_process_until(root.machine.clone(), root.pid, deadline)?
    {
        ProcessRead::Present(live) if live.identity == *root => Ok(()),
        ProcessRead::Present(live) => Err(changed(root, Some(&live.identity))),
        _ => Err(input(
            "process ancestry",
            "the original root exited during inspection; retry after reconciling it",
        )),
    };
    verify_root()?;
    let mut facts = BTreeMap::new();
    for entry in std::fs::read_dir("/proc").map_err(|e| {
        native(
            crate::ProcErrorCode::ScopeUnreadable,
            "enumerate process ancestry",
            e,
        )
    })? {
        if Instant::now() >= deadline {
            return Err(input("process ancestry", "inspection deadline elapsed"));
        }
        let entry = entry.map_err(|e| {
            native(
                crate::ProcErrorCode::ScopeUnreadable,
                "read process entry",
                e,
            )
        })?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if facts.len() == 65536 {
            return Err(capacity("process ancestry records", 65536));
        }
        let bytes = std::fs::File::open(entry.path().join("stat")).and_then(|file| {
            let mut bytes = Vec::new();
            file.take(4097).read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(native(
                    crate::ProcErrorCode::ScopeUnreadable,
                    "read process ancestry",
                    e,
                ));
            }
        };
        if bytes.len() > 4096 {
            return Err(capacity("process ancestry stat bytes", 4096));
        }
        let parse = || {
            let stat = ProcStat::parse(&bytes)?;
            Ok::<_, crate::linux_native::StatError>((
                stat.parent()?,
                stat.start_ticks()?,
                stat.state()?,
            ))
        };
        facts.insert(
            pid,
            parse().map_err(|e| {
                input(
                    "process ancestry",
                    &format!("invalid native stat for PID {pid}: {e:?}"),
                )
            })?,
        );
    }
    let Some((_, root_start, _)) = facts.get(&root.pid.0) else {
        return Err(input(
            "process ancestry",
            "root absent from the native snapshot; not an empty job list",
        ));
    };
    if root.start
        != (StartIdentity::Linux {
            start_ticks: *root_start,
        })
    {
        return Err(changed(root, None));
    }
    let mut selected = BTreeSet::from([root.pid.0]);
    loop {
        if Instant::now() >= deadline {
            return Err(input("process ancestry", "selection deadline elapsed"));
        }
        let before = selected.len();
        for (pid, (parent, start, _)) in &facts {
            if selected.contains(parent)
                && facts.get(parent).is_some_and(|(_, born, _)| born <= start)
            {
                selected.insert(*pid);
            }
        }
        if selected.len() == before {
            break;
        }
        if selected.len() > 4096 {
            return Err(capacity("process descendants", 4096));
        }
    }
    let mut result = Vec::new();
    for pid in selected.into_iter().filter(|pid| *pid != root.pid.0) {
        let (parent, start, state) = facts[&pid];
        if matches!(state, b'Z' | b'X' | b'x') {
            continue;
        }
        match crate::read_process_until(root.machine.clone(), ProcessId(pid), deadline)? {
            ProcessRead::Present(live)
                if live.identity.start == (StartIdentity::Linux { start_ticks: start })
                    && live.parent == Some(ProcessId(parent)) =>
            {
                result.push(live.identity)
            }
            ProcessRead::Absent { .. } | ProcessRead::ExitedRecord { .. } => {}
            _ => {
                return Err(input(
                    "process ancestry",
                    "a selected descendant changed identity or parent; retry the inspection",
                ));
            }
        }
    }
    verify_root()?;
    Ok(result)
}
