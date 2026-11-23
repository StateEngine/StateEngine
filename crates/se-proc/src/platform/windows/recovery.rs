//! Cold reconciliation verifies exit with query rights only; cold re-adoption
//! opens a persistent job only after proving the old owner departed, the exact
//! original root is live inside that job, and its DACL and limits are intact.
use super::*;
use windows_sys::Win32::{
    Storage::FileSystem::READ_CONTROL,
    System::SystemServices::{JOB_OBJECT_QUERY, JOB_OBJECT_SET_ATTRIBUTES, JOB_OBJECT_TERMINATE},
};

pub(super) fn job_name(reservation: &LaunchReservation) -> ProcResult<String> {
    let lifecycle = reservation
        .lifecycle
        .as_str()
        .strip_prefix("life_")
        .ok_or_else(|| {
            input(
                "lifecycle",
                "canonical lifecycle ID required for native names",
            )
        })?
        .replace('-', "");
    Ok(format!(
        "Local\\SE-{}-{}-{}",
        se_types::hex_lower(&reservation.host.0),
        lifecycle,
        se_types::hex_lower(&reservation.scope_nonce)
    ))
}
fn departed(expected: &ProcessIdentity) -> ProcResult<RootWitness> {
    let Some(pin) = lookup(expected.pid)? else {
        return Ok(RootWitness::Identified {
            expected: expected.clone(),
            evidence: Box::new(ExitEvidence::Absent),
            status: ExitStatus::Unavailable {
                reason: ExitStatusUnavailable::NotOurChild,
            },
        });
    };
    // Join this retained process object to the original birth before asking
    // for its image. A signalled original object can prove exit even after
    // Windows has made its executable unreadable; an image error alone cannot.
    if birth(&pin)? != expected.start || expected.boot != BootIdentity::WindowsAbsoluteCreationClock
    {
        let actual = identity(expected.machine.clone(), expected.pid, &pin)?;
        return Ok(RootWitness::Identified {
            expected: expected.clone(),
            evidence: Box::new(ExitEvidence::Replaced { observed: actual }),
            status: ExitStatus::Unavailable {
                reason: ExitStatusUnavailable::NotOurChild,
            },
        });
    }
    match observe(expected, &pin)? {
        ProcessObservation::Exited { evidence, status, .. } => Ok(RootWitness::Identified {
            expected: expected.clone(), evidence: Box::new(evidence), status,
        }),
        ProcessObservation::Live(_) => Err(error(ProcErrorCode::RecoveryUnproved,
            ProcErrorDetail::Input { field: "cold Windows recovery".into(),
                reason: "original owner or root is still live; retain its obligation and do not launch a replacement".into() })),
    }
}
fn empty_job(scope: &ScopeIdentity) -> ProcResult<ScopeObservation> {
    let ScopeIdentity::WindowsJob {
        name, persistent, ..
    } = scope
    else {
        return Err(input("cold recovery scope", "Windows job required"));
    };
    let name = wide(std::ffi::OsStr::new(name));
    // SAFETY: bounded terminated recorded name and query/read-control access
    // only. No terminate, assign, duplicate or policy-mutation rights are opened.
    let raw = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY | READ_CONTROL, 0, name.as_ptr()) };
    if raw.is_null() {
        let cause = std::io::Error::last_os_error();
        return if cause.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) {
            // Protected provenance plus outside original-owner/root exit joins
            // disappearance. This is not an arbitrary pathname absence oracle.
            empty(scope.clone())
        } else {
            Err(native(
                ProcErrorCode::RecoveryUnproved,
                "query old job disappearance",
                cause,
            ))
        };
    }
    let job_handle = Handle(raw);
    security::verify_job(&job_handle)?;
    if query_limits(
        &job_handle,
        ProcErrorCode::RecoveryUnproved,
        "query old job policy",
    )? != job::expected_limits(*persistent)
    {
        return Err(input(
            "cold recovery job",
            "recorded job policy changed; preserve the object",
        ));
    }
    // SAFETY: retained query-capable job handle.
    let active = unsafe { job::active_processes(job_handle.0, "read old job population") }
        .map_err(|e| native(ProcErrorCode::RecoveryUnproved, e.operation, e.source))?;
    if active != 0 {
        return Err(error(ProcErrorCode::RecoveryUnproved, ProcErrorDetail::Input {
            field: "cold recovery job".into(), reason: "old job remains populated or another owner retains custody; no replacement or signal is authorized".into() }));
    }
    empty(scope.clone())
}
fn open_persistent_job(name: &str, root_pin: &Handle, access: u32) -> ProcResult<Handle> {
    let wide_name = wide(std::ffi::OsStr::new(name));
    // SAFETY: bounded terminated recorded job name; caller verifies DACL, limits,
    // and original root membership before exercising any control right.
    let raw = unsafe { OpenJobObjectW(access, 0, wide_name.as_ptr()) };
    if raw.is_null() {
        return Err(last(ProcErrorCode::RecoveryUnproved, "open persistent job"));
    }
    let job_handle = Handle(raw);
    security::verify_job(&job_handle)?;
    if query_limits(
        &job_handle,
        ProcErrorCode::RecoveryUnproved,
        "query persistent job policy",
    )? != job::PERSISTENT_LIMITS
    {
        return Err(input(
            "cold recovery job",
            "recorded persistent job policy changed; preserve the object",
        ));
    }
    // SAFETY: retained original root process pin and opened job handle.
    if !unsafe {
        job::is_member(
            root_pin.0,
            job_handle.0,
            "verify persistent root job membership",
        )
    }
    .map_err(|e| native(ProcErrorCode::RecoveryUnproved, e.operation, e.source))?
    {
        return Err(input(
            "cold recovery job",
            "original live root is outside the recorded persistent job",
        ));
    }
    Ok(job_handle)
}
fn inspect_root(expected: &ProcessIdentity) -> ProcResult<Result<Handle, RootWitness>> {
    let Some(pin) = lookup(expected.pid)? else {
        return Ok(Err(RootWitness::Identified {
            expected: expected.clone(),
            evidence: Box::new(ExitEvidence::Absent),
            status: ExitStatus::Unavailable {
                reason: ExitStatusUnavailable::NotOurChild,
            },
        }));
    };
    if birth(&pin)? != expected.start || expected.boot != BootIdentity::WindowsAbsoluteCreationClock
    {
        let actual = identity(expected.machine.clone(), expected.pid, &pin)?;
        return Ok(Err(RootWitness::Identified {
            expected: expected.clone(),
            evidence: Box::new(ExitEvidence::Replaced { observed: actual }),
            status: ExitStatus::Unavailable {
                reason: ExitStatusUnavailable::NotOurChild,
            },
        }));
    }
    match observe(expected, &pin)? {
        ProcessObservation::Live(_) => Ok(Ok(pin)),
        ProcessObservation::Exited {
            evidence, status, ..
        } => Ok(Err(RootWitness::Identified {
            expected: expected.clone(),
            evidence: Box::new(evidence),
            status,
        })),
    }
}
impl Driver {
    pub fn reconcile(&self, source: &RecoverySource) -> ProcResult<StopWitness> {
        reconcile(source)
    }
    /// Query-only check for a persistent Windows job: returns `Ok(Some(witness))`
    /// if the root exited and the job is empty/absent, or `Ok(None)` when the
    /// old owner departed and the exact original root is still live in its job.
    pub fn reconcile_persistent(&self, record: &ProcessRecord) -> ProcResult<Option<StopWitness>> {
        let ScopeIdentity::WindowsJob {
            name,
            persistent: true,
            ..
        } = &record.scope
        else {
            return Err(input(
                "cold Windows recovery",
                "persistent Windows job required",
            ));
        };
        departed(&record.owner)?;
        match inspect_root(&record.root)? {
            Err(root) => {
                let scope_exit = empty_job(&record.scope)?;
                Ok(Some(StopWitness {
                    lifecycle: record.lifecycle.clone(),
                    root,
                    scope: record.scope.clone(),
                    scope_exit,
                    guarantee: record.guarantee,
                    observed_at_unix_ns: now()?,
                }))
            }
            Ok(pin) => {
                open_persistent_job(name, &pin, JOB_OBJECT_QUERY | READ_CONTROL)?;
                Ok(None)
            }
        }
    }
    /// Re-adopt a live persistent Windows job into this host's arena and IOCP.
    pub fn recover(
        &self,
        record: &ProcessRecord,
        host: HostInstanceId,
        limits: ResourceLimits,
        hub: &Arc<Hub>,
    ) -> ProcResult<Scope> {
        let ScopeIdentity::WindowsJob {
            name,
            persistent: true,
            ..
        } = &record.scope
        else {
            return Err(input(
                "cold Windows recovery",
                "persistent Windows job required",
            ));
        };
        departed(&record.owner)?;
        let pin = match inspect_root(&record.root)? {
            Ok(pin) => pin,
            Err(_) => return Err(changed(&record.root, None)),
        };
        const CONTROL_ACCESS: u32 =
            JOB_OBJECT_QUERY | JOB_OBJECT_SET_ATTRIBUTES | JOB_OBJECT_TERMINATE | READ_CONTROL;
        let job_handle = open_persistent_job(name, &pin, CONTROL_ACCESS)?;
        let notification = self.collector.register(hub)?;
        // SAFETY: retained verified job handle and live collector IOCP handle.
        unsafe {
            job::clear_iocp(job_handle.0);
            job::associate_iocp(
                job_handle.0,
                self.collector.handle.0,
                notification.key,
                "reassociate persistent job IOCP",
            )
        }
        .map_err(|e| native(ProcErrorCode::ContainmentUnavailable, e.operation, e.source))?;
        let mut scope = Scope {
            job: job_handle,
            child: Some(spawn::Child {
                pin,
                identity: Some(record.root.clone()),
                pid: record.root.pid,
            }),
            console_host: None,
            window: false,
            persistent: true,
            scope: ScopeIdentity::WindowsJob {
                host,
                name: name.clone(),
                persistent: true,
            },
            guarantee: record.guarantee,
            entry: record.entry,
            max_members: limits.max_diagnostic_members as usize,
            console_interrupt: false,
            interrupt_helper: None,
            _notification: notification,
        };
        // Post-arm reread closes exit/registration races.
        scope.observe()?;
        Ok(scope)
    }
}

/// Query-only cold proof for a protected unpublished Windows scope. The old
/// owner must be gone and the exact private job empty or absent.
/// No process is signalled and no store checkpoint is consumed.
pub fn observe_prepared_scope_exit(checkpoint: &ScopeCheckpoint) -> ProcResult<StopWitness> {
    let source = RecoverySource::Prepared(Box::new(checkpoint.clone()));
    crate::checkpoint::validate_recovery(&source)
        .map_err(|e| input("prepared exit observation", &e.to_string()))?;
    reconcile(&source)
}

fn reconcile(source: &RecoverySource) -> ProcResult<StopWitness> {
    let (lifecycle, owner, scope, guarantee, root) = match source {
        RecoverySource::Record(record) => (
            &record.lifecycle,
            &record.owner,
            record.scope.clone(),
            record.guarantee,
            Some(&record.root),
        ),
        RecoverySource::Reservation(r) => (
            &r.lifecycle,
            &r.owner,
            ScopeIdentity::WindowsJob {
                host: r.host,
                name: job_name(r)?,
                persistent: false,
            },
            ContainmentGuarantee::KernelScope {
                explicit_breakaway: true,
            },
            None,
        ),
        RecoverySource::Prepared(c) => (
            &c.reservation.lifecycle,
            &c.reservation.owner,
            c.scope.clone(),
            c.guarantee,
            None,
        ),
        RecoverySource::RootPrepared(_) => {
            return Err(input(
                "cold Windows recovery",
                "Windows never publishes a pre-exec RootCheckpoint",
            ));
        }
    };
    // The old owner must be outside-proved gone before name-only queries.
    if !matches!(source, RecoverySource::Record(r) if r.state == LifecycleState::Exited) {
        departed(owner)?;
    }
    let root = match root {
        Some(root) => departed(root)?,
        None if matches!(source, RecoverySource::Reservation(_)) => RootWitness::NoChildCreated,
        None => RootWitness::UnpublishedScope,
    };
    let scope_exit = empty_job(&scope)?;
    Ok(StopWitness {
        lifecycle: lifecycle.clone(),
        root,
        scope,
        scope_exit,
        guarantee,
        observed_at_unix_ns: now()?,
    })
}

pub(crate) fn uncreated_scope(
    reservation: &LaunchReservation,
) -> ProcResult<(ScopeObservation, ContainmentGuarantee)> {
    let scope = ScopeIdentity::WindowsJob {
        host: reservation.host,
        name: job_name(reservation)?,
        persistent: false,
    };
    Ok((
        empty_job(&scope)?,
        ContainmentGuarantee::KernelScope {
            explicit_breakaway: true,
        },
    ))
}
