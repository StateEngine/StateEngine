//! Native stop tokens, custody witnesses and release.
use super::*;

impl NativeProcessRuntime {
    pub(super) fn native_prepare_stop(
        &self,
        process: &OwnedProcess,
        generation: GenerationId,
        deadline: Instant,
    ) -> ProcResult<PreparedStop> {
        if generation != process.key.generation {
            return Err(error(
                ProcErrorCode::GenerationChanged,
                ProcErrorDetail::Generation {
                    expected: generation,
                    current: process.key.generation,
                },
            ));
        }
        let nonce = self.inner.apply(&process.key, true, |s| {
            if !matches!(
                s.phase,
                LifecycleState::Reserved
                    | LifecycleState::Starting
                    | LifecycleState::Running
                    | LifecycleState::LeaderExited
                    | LifecycleState::StopUnproved
                    | LifecycleState::StopRequested
            ) {
                return Err(state(&process.key.lifecycle, s.phase, "prepare_stop"));
            }
            if deadline <= Instant::now() {
                return Err(token_error(&process.key, true, false));
            }
            s.stop_prepared = s
                .stop_prepared
                .checked_add(1)
                .ok_or_else(|| input("stop token", "counter exhausted"))?;
            Ok(s.stop_prepared)
        })?;
        Ok(PreparedStop {
            key: process.key.clone(),
            deadline,
            nonce,
        })
    }
    pub(super) fn native_request_stop(&self, prepared: PreparedStop) -> ProcResult<StopAttempt> {
        self.request_stop_mode(prepared, false)
    }
    /// Linux's graceful signal consumes the same identity/generation-bound
    /// single-use stop token as force, after the host's durable StopRequested.
    /// Scope exit still requires an independent witness; this is not release.
    #[cfg(target_os = "linux")]
    pub fn request_termination(&self, prepared: PreparedStop) -> ProcResult<StopAttempt> {
        self.request_stop_mode(prepared, true)
    }
    fn request_stop_mode(&self, prepared: PreparedStop, graceful: bool) -> ProcResult<StopAttempt> {
        #[cfg(not(target_os = "linux"))]
        let _ = graceful;
        let key = prepared.key;
        let (attempt, dispatch) = self.inner.apply(&key, true, |s| {
            s.set_phase(LifecycleState::StopRequested)?;
            s.stop_attempt = s
                .stop_attempt
                .checked_add(1)
                .ok_or_else(|| input("stop attempt", "counter exhausted"))?;
            let dispatch = if prepared.deadline <= Instant::now() {
                Err(token_error(&key, true, false))
            } else if prepared.nonce <= s.stop_consumed || prepared.nonce != s.stop_prepared {
                Err(token_error(&key, false, true))
            } else {
                s.stop_consumed = prepared.nonce;
                match &mut s.native {
                    #[cfg(target_os = "linux")]
                    Some(native) if graceful => native.terminate(prepared.deadline),
                    Some(native) => native.stop(prepared.deadline),
                    None if !s.launched => Ok(StopDispatch::NotNeeded),
                    None => Err(input("stop", "native child custody is unresolved")),
                }
            };
            if let Err(e) = &dispatch {
                s.set_phase(LifecycleState::StopUnproved)?;
                s.failure = Some(e.clone());
            }
            Ok((s.stop_attempt, dispatch))
        })?;
        Ok(StopAttempt {
            ticket: StopTicket { key, attempt },
            dispatch,
        })
    }
    pub(super) fn native_witness_stop(&self, ticket: &StopTicket) -> ProcResult<StopObservation> {
        self.inner.apply(&ticket.key, true, |s| {
            if ticket.attempt == 0 || ticket.attempt > s.stop_attempt {
                return Err(input("stop ticket", "unknown attempt"));
            }
            witness(s)
        })
    }
    pub(super) fn native_witness_exit(
        &self,
        process: &OwnedProcess,
    ) -> ProcResult<StopObservation> {
        self.inner.apply(&process.key, true, witness)
    }
    pub(super) fn native_release(
        &self,
        process: &OwnedProcess,
        supplied: &StopWitness,
    ) -> ProcResult<()> {
        self.inner.apply(&process.key, true, |s| {
            let StopObservation::Complete(current) = witness(s)? else {
                return Err(input("release", "required scope exit is not proved"));
            };
            if supplied.lifecycle != current.lifecycle
                || supplied.scope != current.scope
                || !same_root_custody(&supplied.root, &current.root)
                || supplied.guarantee != current.guarantee
            {
                return Err(input(
                    "exit witness",
                    "witness differs from retained native custody",
                ));
            }
            #[cfg(windows)]
            if s.stdio.as_ref().is_some_and(|stdio| !stdio.released()) {
                return Err(input(
                    "release",
                    "close/drain provider streams and release every operation and port first",
                ));
            }
            if let Some(native) = &mut s.native {
                native.release(true)?;
            }
            s.released = true;
            s.hub.disable();
            Ok(())
        })?;
        self.inner.remove(&process.key)
    }
    pub(super) fn native_release_uncontained(
        &self,
        process: &OwnedProcess,
        release: &UnwitnessedRelease,
    ) -> ProcResult<ReleasedOwnership> {
        self.inner.apply(&process.key, true, |s| {
            if s.phase != LifecycleState::StopUnproved
                && !(s.record.is_none()
                    && matches!(
                        s.phase,
                        LifecycleState::Reserved | LifecycleState::Starting | LifecycleState::Lost
                    ))
            {
                return Err(state(
                    &process.key.lifecycle,
                    s.phase,
                    "release_uncontained",
                ));
            }
            let scope = if let Some(native) = s.native.as_ref() {
                native.scope.clone()
            } else if let Some(checkpoint) = &s.checkpoint {
                checkpoint.scope.clone()
            } else {
                crate::platform::uncreated_scope(&s.reservation)?.0.scope
            };
            if release.lifecycle != s.reservation.lifecycle
                || release.generation != s.generation
                || scope != release.scope
                || !matches!(
                    scope,
                    ScopeIdentity::LinuxPrepared { .. }
                        | ScopeIdentity::LinuxTracked { .. }
                        | ScopeIdentity::MacOsPrepared { .. }
                        | ScopeIdentity::MacOsTracked { .. }
                )
            {
                return Err(input(
                    "release",
                    "exact uncontained lifecycle, generation and retained scope required",
                ));
            }
            // The host already committed its explicit human-only release CAS.
            // Closing query/readiness custody sends no signal and proves no exit.
            if let Some(native) = s.native.as_mut() {
                native.release(false)?;
            }
            s.set_phase(LifecycleState::StopUnproved)?;
            s.released = true;
            s.hub.disable();
            if let Some(record) = &mut s.record {
                record.ownership_release = Some(release.clone());
            }
            Ok(())
        })?;
        self.inner.remove(&process.key)?;
        Ok(ReleasedOwnership {
            release: release.clone(),
        })
    }
}

fn token_error(key: &super::super::Reference, expired: bool, consumed: bool) -> ProcError {
    error(
        if expired {
            ProcErrorCode::StopTokenExpired
        } else {
            ProcErrorCode::StopTokenConsumed
        },
        ProcErrorDetail::Token {
            lifecycle: key.lifecycle.clone(),
            expired,
            consumed,
        },
    )
}
fn same_root_custody(a: &RootWitness, b: &RootWitness) -> bool {
    match (a, b) {
        (RootWitness::NoChildCreated, RootWitness::NoChildCreated) => true,
        (
            RootWitness::Identified { expected: a, .. },
            RootWitness::Identified { expected: b, .. },
        ) => a == b,
        (
            RootWitness::PinnedUnpublished { pid: a, .. },
            RootWitness::PinnedUnpublished { pid: b, .. },
        ) => a == b,
        _ => false,
    }
}
pub(in crate::runtime) fn witness(s: &mut Slot) -> ProcResult<StopObservation> {
    match witness_inner(s) {
        // Windows can revoke image-query access during teardown before the
        // retained process handle becomes signalled. Only exit observation is
        // retryable here: stateless reads and identity/control checks still
        // return their original unreadable error. No absence or live identity
        // is manufactured while waiting for independent native exit evidence.
        Err(cause)
            if cfg!(windows)
                && cause.code == ProcErrorCode::IdentityUnreadable
                && cause.native.as_ref().is_some_and(|failure| {
                    failure.api == "QueryFullProcessImageNameW" && failure.code == Some(5)
                }) =>
        {
            if s.phase == LifecycleState::StopRequested {
                s.set_phase(LifecycleState::StopUnproved)?;
            }
            Ok(StopObservation::Pending {
                root: None,
                scope: Box::new(ScopeObservation {
                    scope: s.native()?.scope.clone(),
                    remaining: RemainingScope {
                        population: Population::Unknown,
                        known_live: Vec::new(),
                        extent: EnumerationExtent::Partial {
                            reason: format!(
                                "Windows exit remains unproved while image access is unavailable: {cause:?}"
                            ),
                            omitted: None,
                        },
                        observed_at_unix_ns: now()?,
                    },
                    exit_basis: None,
                }),
            })
        }
        result => result,
    }
}
fn witness_inner(s: &mut Slot) -> ProcResult<StopObservation> {
    if s.native.is_none() && !s.launched {
        // Failed preparation cannot have created a vendor. Query the exact
        // vendor-free reservation outside the failed writer before retiring it.
        let (scope_exit, guarantee) = crate::platform::uncreated_scope(&s.reservation)?;
        s.set_phase(LifecycleState::Exited)?;
        return Ok(StopObservation::Complete(Box::new(StopWitness {
            lifecycle: s.reservation.lifecycle.clone(),
            root: RootWitness::NoChildCreated,
            scope: scope_exit.scope.clone(),
            scope_exit,
            guarantee,
            observed_at_unix_ns: now()?,
        })));
    }
    let mut root = match s.native()?.root() {
        Ok(root) => root,
        Err(cause)
            if cfg!(target_os = "linux")
                && cause.code == ProcErrorCode::IdentityUnreadable
                && cause
                    .native
                    .as_ref()
                    .is_some_and(|native| native.code == Some(2)) =>
        {
            return Ok(StopObservation::Pending {
                root: None,
                scope: Box::new(ScopeObservation {
                    scope: s.native()?.scope.clone(),
                    remaining: RemainingScope {
                        population: Population::Unknown,
                        known_live: Vec::new(),
                        extent: EnumerationExtent::Partial {
                            reason: format!("native root exit remains unreadable: {cause:?}"),
                            omitted: None,
                        },
                        observed_at_unix_ns: now()?,
                    },
                    exit_basis: None,
                }),
            });
        }
        Err(cause) => return Err(cause),
    };
    let root_ready = !matches!(root, Some(ProcessObservation::Exited { .. }))
        || s.native()?.root_exit_ready()?;
    if root_ready && matches!(root, Some(ProcessObservation::Exited { .. })) {
        // A pending waitid may have just become readable above. Return its
        // retained status now, before constructing a complete witness.
        root = s.native()?.root()?;
    }
    let scope = s.native()?.observe()?;
    if let Some(ProcessObservation::Exited { status, .. }) = &root
        && let Some(record) = &mut s.record
    {
        record.exit_status = Some(status.clone());
    }
    let root_witness = match &root {
        Some(ProcessObservation::Exited {
            expected,
            evidence,
            status,
            ..
        }) => Some(RootWitness::Identified {
            expected: expected.clone(),
            evidence: Box::new(evidence.clone()),
            status: status.clone(),
        }),
        Some(ProcessObservation::Live(_)) => None,
        None if !s.native()?.child_created() => Some(RootWitness::NoChildCreated),
        None => s
            .native()?
            .unpublished_exit()?
            .map(|(pid, status)| RootWitness::PinnedUnpublished { pid, status }),
    };
    if root_ready
        && scope.remaining.population == Population::Empty
        && scope.exit_basis.is_some()
        && let Some(root) = root_witness
    {
        let witness = Box::new(StopWitness {
            lifecycle: s.reservation.lifecycle.clone(),
            root,
            scope: scope.scope.clone(),
            scope_exit: scope.clone(),
            observed_at_unix_ns: now()?,
            guarantee: s.native()?.guarantee,
        });
        let bounded = !matches!(scope.remaining.extent, EnumerationExtent::Complete);
        s.set_phase(if bounded {
            LifecycleState::StopUnproved
        } else {
            LifecycleState::Exited
        })?;
        return Ok(if bounded {
            StopObservation::Bounded(witness)
        } else {
            StopObservation::Complete(witness)
        });
    }
    if matches!(s.phase, LifecycleState::StopRequested) {
        s.set_phase(LifecycleState::StopUnproved)?;
    }
    Ok(StopObservation::Pending {
        root: root.map(Box::new),
        scope: Box::new(scope),
    })
}
