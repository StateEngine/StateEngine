//! A tracked group is a bounded observation, not an unescapable kernel scope.
use super::*;
use std::{io, mem::size_of, time::Instant};

fn members(group: ProcessId, max: usize, max_bytes: u64) -> ProcResult<Vec<ProcessId>> {
    if group.0 == 0 || group.0 > i32::MAX as u32 {
        return Err(input("process group", "positive native group required"));
    }
    let limit = max
        .saturating_add(1)
        .min((max_bytes / size_of::<libc::pid_t>() as u64) as usize);
    if limit == 0 {
        return Err(capacity("group enumeration bytes", max_bytes));
    }
    let mut count = 32.min(limit);
    loop {
        let mut pids = vec![0 as libc::pid_t; count];
        let size = i32::try_from(pids.len() * size_of::<libc::pid_t>())
            .map_err(|_| capacity("native group buffer", i32::MAX as u64))?;
        // SAFETY: clear thread-local errno so an observed empty group is not a
        // stale native failure and a real failure cannot turn into population zero.
        unsafe {
            *libc::__error() = 0;
        }
        // SAFETY: positive group selector, exact initialized writable PID array.
        let bytes = unsafe {
            libc::proc_listpids(
                2, // PROC_PGRP_ONLY from Darwin sys/proc_info.h.
                group.0,
                pids.as_mut_ptr().cast(),
                size,
            )
        };
        let cause = io::Error::last_os_error();
        if bytes < 0 || (bytes == 0 && cause.raw_os_error() != Some(0)) {
            return Err(native(
                ProcErrorCode::ScopeUnreadable,
                "list Darwin process group",
                cause,
            ));
        }
        if bytes > size || !(bytes as usize).is_multiple_of(size_of::<libc::pid_t>()) {
            return Err(input("native group list", "malformed native byte count"));
        }
        if bytes == size {
            if count == limit {
                return Err(capacity("complete group enumeration", limit as u64));
            }
            count = count.saturating_mul(2).min(limit);
            continue;
        }
        pids.truncate(bytes as usize / size_of::<libc::pid_t>());
        if pids.len() > max {
            return Err(capacity("tracked group members", max as u64));
        }
        let mut result = Vec::with_capacity(pids.len());
        for pid in pids {
            if pid <= 0 || result.contains(&ProcessId(pid as u32)) {
                return Err(input(
                    "native group list",
                    "invalid or duplicate native PID",
                ));
            }
            result.push(ProcessId(pid as u32));
        }
        return Ok(result);
    }
}

fn live_member(
    expected: &ProcessIdentity,
    root: &ProcessIdentity,
) -> ProcResult<Option<LiveObservation>> {
    match crate::read_process(expected.machine.clone(), expected.pid)? {
        ProcessRead::Present(live)
            if live.identity.boot == expected.boot && live.identity.start == expected.start =>
        {
            if expected.pid == root.pid && live.identity.image != root.image {
                return Err(changed(root, Some(&live.identity)));
            }
            Ok(Some(live))
        }
        _ => Ok(None),
    }
}
pub(super) fn in_group(expected: &ProcessIdentity, group: ProcessId) -> ProcResult<bool> {
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    let Some(info) = crate::macos_process::info(expected.pid, deadline)? else {
        return Ok(false);
    };
    if info.pbi_pgid != group.0 || crate::macos_process::start(&info) != expected.start {
        return Ok(false);
    }
    Ok(
        matches!(crate::read_process(expected.machine.clone(), expected.pid)?,
        ProcessRead::Present(live) if live.identity == *expected),
    )
}

impl Scope {
    pub fn observe(&mut self) -> ProcResult<ScopeObservation> {
        self.refresh_exec()?;
        let Some(group) = self.group else {
            if self.child.is_none() {
                return empty(self.scope.clone());
            }
            if self
                .child
                .as_mut()
                .is_some_and(|child| child.status.is_some())
            {
                return empty(self.scope.clone());
            }
            return Err(input(
                "group observation",
                "created helper has no native identity yet",
            ));
        };
        let root = self
            .root_identity()
            .ok_or_else(|| input("group observation", "original root unavailable"))?;
        let mut anchored = false;
        for expected in &self.tracked {
            if let Some(live) = live_member(expected, &root)?
                && in_group(&live.identity, group)?
            {
                anchored = true;
                break;
            }
        }
        let mut live = Vec::new();
        for pid in members(group, self.max_members, self.max_bytes)? {
            let ProcessRead::Present(found) = crate::read_process(root.machine.clone(), pid)?
            else {
                continue;
            };
            if !in_group(&found.identity, group)? {
                continue;
            }
            if found.identity.pid == root.pid && found.identity.image != root.image {
                return Err(changed(&root, Some(&found.identity)));
            }
            if anchored {
                if let Some(previous) = self.tracked.iter_mut().find(|p| {
                    p.pid == pid && p.boot == found.identity.boot && p.start == found.identity.start
                }) {
                    *previous = found.identity.clone();
                } else {
                    if self.tracked.len() == self.max_members {
                        return Err(capacity(
                            "retained tracked identities",
                            self.max_members as u64,
                        ));
                    }
                    self.tracked.push(found.identity.clone());
                }
                self.watch.track(&found.identity)?;
            }
            live.push(found.identity);
        }
        for expected in &self.tracked {
            if let Some(found) = live_member(expected, &root)?
                && !live.contains(&found.identity)
            {
                self.escaped = true;
                if live.len() == self.max_members {
                    return Err(capacity("tracked obligations", self.max_members as u64));
                }
                live.push(found.identity);
            }
        }
        for registration in self
            .registrations
            .iter()
            .skip(usize::from(self.child.is_some()))
        {
            registration.rearm();
        }
        let population = if live.is_empty() {
            Population::Empty
        } else if anchored {
            Population::Populated
        } else {
            Population::Unknown
        };
        let complete = !self.escaped && (anchored || live.is_empty());
        Ok(ScopeObservation {
            scope: self.scope.clone(),
            remaining: RemainingScope {
                population,
                known_live: live,
                extent: if complete {
                    EnumerationExtent::Complete
                } else {
                    EnumerationExtent::Partial {
                    reason: "group continuity or an escaped tracked obligation is unproved; unobserved descendants may remain".into(), omitted: None }
                },
                observed_at_unix_ns: now()?,
            },
            exit_basis: if population == Population::Empty && complete {
                Some(ScopeExitBasis::ObservedEmpty)
            } else {
                None
            },
        })
    }
    pub fn stop(&mut self, deadline: Instant) -> ProcResult<StopDispatch> {
        self.signal(deadline, libc::SIGKILL)
    }
    pub fn terminate(&mut self, deadline: Instant) -> ProcResult<StopDispatch> {
        self.signal(deadline, libc::SIGTERM)
    }
    fn signal(&mut self, deadline: Instant, signal: libc::c_int) -> ProcResult<StopDispatch> {
        check_stop_deadline(deadline)?;
        if let Some(child) = &mut self.child
            && !child.authorized
        {
            child.cancel_paused();
            // EOF cancels a helper that has not received an exec permit. It
            // does not signal an unobserved numeric PID or invent an exit.
            return Ok(StopDispatch::Requested);
        }
        let observed = self.observe()?;
        if observed.remaining.population == Population::Empty {
            return Ok(StopDispatch::NotNeeded);
        }
        let root = self
            .root_identity()
            .ok_or_else(|| input("group stop", "original root unavailable"))?;
        let group = self
            .group
            .ok_or_else(|| input("group stop", "native group unavailable"))?;
        let mut tied = false;
        for expected in &self.tracked {
            if let Some(live) = live_member(expected, &root)?
                && in_group(&live.identity, group)?
            {
                tied = true;
                break;
            }
        }
        if !tied {
            return Err(error(ProcErrorCode::RecoveryUnproved, ProcErrorDetail::Scope {
            lifecycle: None, path: None, reason: "no live original member proves group continuity; retain StopUnproved for owner recovery".into(), }));
        }
        check_stop_deadline(deadline)?;
        // SAFETY: positive native group rechecked against an original live
        // instance, under the serialized scope lock and original stop deadline.
        // Darwin retains its explicit non-atomic check/signal bound.
        if unsafe { libc::kill(-(group.0 as i32), signal) } < 0 {
            let cause = io::Error::last_os_error();
            if cause.raw_os_error() == Some(libc::ESRCH) {
                return Ok(StopDispatch::NotNeeded);
            }
            return Err(native(
                ProcErrorCode::StopDispatchFailed,
                "signal tracked Darwin group",
                cause,
            ));
        }
        Ok(StopDispatch::Requested)
    }
    pub fn release(&mut self, witnessed: bool) -> ProcResult<()> {
        if witnessed
            && let Some(child) = &mut self.child
            && child.peek_status()?.is_none()
        {
            return Err(input(
                "scope release",
                "retained child has no terminal wait status",
            ));
        }
        for registration in &mut self.registrations {
            registration.cancel();
        }
        self.registrations.clear();
        self.child = None;
        Ok(())
    }
}
