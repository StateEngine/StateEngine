//! Identity-bracketed group reads and stops at the explicit uncontained bound.
use super::*;
use std::fs;

// A descendant may legitimately exec in the retained group. Its birth and
// membership supply group continuity; the published root image stays strict.
fn live_member(
    expected: &ProcessIdentity,
    root: &ProcessIdentity,
) -> ProcResult<Option<LiveObservation>> {
    match read_process(expected.machine.clone(), expected.pid)? {
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
fn live_group(live: &LiveObservation) -> ProcResult<Option<ProcessId>> {
    let StartIdentity::Linux { start_ticks } = live.identity.start else {
        return Err(input("group continuity", "native Linux birth required"));
    };
    Ok(identity::stat(live.identity.pid)?
        .filter(|s| s.start == start_ticks && s.state != NativeState::ExitedAwaitingReap)
        .and_then(|s| s.group))
}
fn in_group(live: &LiveObservation, group: ProcessId) -> ProcResult<bool> {
    Ok(live_group(live)? == Some(group))
}

// Linux exposes no process-group member list. Select by the kernel's group
// identity before opening any process metadata; directory names alone grant
// no custody. The full birth/image/membership checks below still bracket every
// selected member, including a PID that changes between this query and open.
fn selected_group(pid: ProcessId, group: ProcessId) -> ProcResult<bool> {
    // SAFETY: getpgid only queries membership and never signals the process.
    let observed = unsafe { libc::getpgid(pid.0 as libc::pid_t) };
    if observed >= 0 {
        return Ok(observed as u32 == group.0);
    }
    let cause = io::Error::last_os_error();
    if cause.raw_os_error() == Some(libc::ESRCH) {
        return Ok(false);
    }
    Err(native(
        ProcErrorCode::ScopeUnreadable,
        "query tracked process-group membership",
        cause,
    ))
}

impl Scope {
    pub fn observe(&mut self) -> ProcResult<ScopeObservation> {
        match self.observe_inner() {
            Err(cause)
                if cause.code == ProcErrorCode::IdentityUnreadable
                    && cause
                        .native
                        .as_ref()
                        .is_some_and(|n| n.code == Some(i64::from(libc::ENOENT))) =>
            {
                // exit_group can remove /proc/PID/exe before stat changes to Z.
                // Keep that native unreadability visible and population unknown;
                // a later read must establish zombie/absence before completion.
                Ok(ScopeObservation {
                    scope: self.scope.clone(),
                    remaining: RemainingScope {
                        population: Population::Unknown,
                        known_live: Vec::new(),
                        extent: EnumerationExtent::Partial {
                            reason: format!("native group observation unreadable: {cause:?}"),
                            omitted: None,
                        },
                        observed_at_unix_ns: now()?,
                    },
                    exit_basis: None,
                })
            }
            other => other,
        }
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    fn observe_inner(&mut self) -> ProcResult<ScopeObservation> {
        let Some(group) = self.group else {
            if let Some(child) = &mut self.child
                && !child.authorized
                && child.peek_status()?.is_some()
            {
                return empty(self.scope.clone());
            }
            return if self.child.is_none() {
                empty(self.scope.clone())
            } else {
                Ok(ScopeObservation {
                    scope: self.scope.clone(),
                    remaining: RemainingScope {
                        population: Population::Unknown,
                        known_live: Vec::new(),
                        extent: EnumerationExtent::Partial {
                            reason: "helper group is not yet observed".into(),
                            omitted: None,
                        },
                        observed_at_unix_ns: now()?,
                    },
                    exit_basis: None,
                })
            };
        };
        let root = self
            .root_identity()
            .ok_or_else(|| input("scope", "missing root"))?;
        let mut anchored = false;
        let mut retained = Vec::with_capacity(self.tracked.len());
        for expected in &self.tracked {
            if let Some(live) = live_member(expected, &root)? {
                anchored |= in_group(&live, group)?;
                retained.push(expected.clone());
            }
        }
        // Reclaim only natively finished instances, before admitting new members.
        // Commit the replacement after every read succeeds: an unreadable member
        // retains the entire previous custody set, including known escapes.
        self.tracked = retained;
        let mut live = Vec::new();
        // Enumerate PID names, then query this exact process group without
        // opening every process on the machine. No executable-name filter;
        // enumeration/membership errors remain errors, never population zero.
        for entry in fs::read_dir("/proc")
            .map_err(|e| native(ProcErrorCode::ScopeUnreadable, "enumerate tracked group", e))?
        {
            let entry =
                entry.map_err(|e| native(ProcErrorCode::ScopeUnreadable, "read proc entry", e))?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
                .map(ProcessId)
            else {
                continue;
            };
            if !selected_group(pid, group)? {
                continue;
            }
            let Some(stat) = identity::stat(pid)? else {
                continue;
            };
            if stat.state == NativeState::ExitedAwaitingReap || stat.group != Some(group) {
                continue;
            }
            if let ProcessRead::Present(member) = read_process(root.machine.clone(), pid)? {
                if member.identity.start
                    != (StartIdentity::Linux {
                        start_ticks: stat.start,
                    })
                    || !in_group(&member, group)?
                {
                    continue;
                }
                if member.identity.pid == root.pid && member.identity.image != root.image {
                    return Err(changed(&root, Some(&member.identity)));
                }
                if live.len() == self.max_members {
                    return Err(capacity("tracked group members", self.max_members as u64));
                }
                if anchored {
                    if let Some(previous) = self.tracked.iter_mut().find(|p| {
                        p.pid == member.identity.pid
                            && p.boot == member.identity.boot
                            && p.start == member.identity.start
                    }) {
                        *previous = member.identity.clone();
                    } else {
                        if self.tracked.len() == self.max_members {
                            return Err(capacity(
                                "retained tracked identities",
                                self.max_members as u64,
                            ));
                        }
                        self.tracked.push(member.identity.clone());
                    }
                }
                live.push(member.identity);
            }
        }
        for tracked in &self.tracked {
            if let Some(member) = live_member(tracked, &root)? {
                let Some(current_group) = live_group(&member)? else {
                    continue;
                };
                // A census miss or an exec within the group is not an escape.
                // Retain escape debt only after a same-birth live membership read.
                if current_group != group {
                    self.escaped = true;
                }
                if let Some(previous) = live.iter_mut().find(|previous| {
                    previous.pid == member.identity.pid
                        && previous.boot == member.identity.boot
                        && previous.start == member.identity.start
                }) {
                    *previous = member.identity;
                    continue;
                }
                if live.len() == self.max_members {
                    return Err(capacity("tracked group members", self.max_members as u64));
                }
                live.push(member.identity);
            }
        }
        let population = if live.is_empty() {
            Population::Empty
        } else if anchored {
            Population::Populated
        } else {
            Population::Unknown
        };
        let incomplete = self.escaped || (!anchored && !live.is_empty());
        Ok(ScopeObservation {
            scope: self.scope.clone(),
            remaining: RemainingScope {
                population,
                known_live: live,
                extent: if incomplete {
                    EnumerationExtent::Partial { reason: "original group continuity or an escaped member is unproved; unobserved descendants may remain".into(), omitted: None }
                } else {
                    EnumerationExtent::Complete
                },
                observed_at_unix_ns: now()?,
            },
            exit_basis: if population == Population::Empty {
                Some(ScopeExitBasis::ObservedEmpty)
            } else {
                None
            },
        })
    }
    pub fn stop(&mut self, deadline: std::time::Instant) -> ProcResult<StopDispatch> {
        self.signal(deadline, libc::SIGKILL)
    }
    pub fn terminate(&mut self, deadline: std::time::Instant) -> ProcResult<StopDispatch> {
        self.signal(deadline, libc::SIGTERM)
    }
    pub fn interrupt(&mut self, deadline: std::time::Instant) -> ProcResult<StopDispatch> {
        self.signal(deadline, libc::SIGINT)
    }
    fn signal(
        &mut self,
        deadline: std::time::Instant,
        signal: libc::c_int,
    ) -> ProcResult<StopDispatch> {
        if let Some(child) = &mut self.child {
            child.authorization = None;
        }
        let Some(group) = self.group else {
            // Before R was read, only our exact unreaped helper can exist.
            let Some(child) = &self.child else {
                return Ok(StopDispatch::NotNeeded);
            };
            let pin = child
                .pin
                .as_ref()
                .ok_or_else(|| input("stop", "helper identity/pin not yet available"))?;
            check_stop_deadline(deadline)?;
            // SAFETY: held pidfd of the exact child, never a selector from caller.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pin.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                )
            };
            if rc < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                    return Ok(StopDispatch::NotNeeded);
                }
                return Err(native(
                    ProcErrorCode::StopDispatchFailed,
                    "pidfd stop helper",
                    io::Error::last_os_error(),
                ));
            }
            return Ok(StopDispatch::Requested);
        };
        let before = self.observe()?;
        if before.remaining.population == Population::Empty {
            return Ok(StopDispatch::NotNeeded);
        }
        let root = self
            .root_identity()
            .ok_or_else(|| input("scope", "missing root"))?;
        let mut tied = false;
        for member in &self.tracked {
            if let Some(live) = live_member(member, &root)?
                && in_group(&live, group)?
            {
                tied = true;
                break;
            }
        }
        if !tied {
            return Err(error(ProcErrorCode::RecoveryUnproved, ProcErrorDetail::Scope { lifecycle: None, path: None,
            reason: "group cannot be tied to a live original tracked member; use owner-human release after StopUnproved".into() }));
        }
        check_stop_deadline(deadline)?;
        // SAFETY: exact native group just bracketed against an original member.
        // Linux tracked groups retain the documented non-atomic check/signal bound.
        if unsafe { libc::kill(-(group.0 as i32), signal) } < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                return Ok(StopDispatch::NotNeeded);
            }
            return Err(native(
                ProcErrorCode::StopDispatchFailed,
                "signal tracked group",
                io::Error::last_os_error(),
            ));
        }
        Ok(StopDispatch::Requested)
    }
    pub fn release(&mut self, witnessed: bool) -> ProcResult<()> {
        for registration in &mut self.registrations {
            registration.cancel();
        }
        self.registrations.clear();
        if witnessed && let Some(child) = &mut self.child {
            child.reap()?;
        }
        self.child = None;
        Ok(())
    }
}
