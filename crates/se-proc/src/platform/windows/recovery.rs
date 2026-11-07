//! Cold reconciliation has query rights only. A recorded name never grants
//! signal authority, and an unexpectedly live owner/root/job stays unproved.
use super::*;
use windows_sys::Win32::{
    Storage::FileSystem::READ_CONTROL, System::SystemServices::JOB_OBJECT_QUERY,
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
    let actual = identity(expected.machine.clone(), expected.pid, &pin)?;
    if actual.start != expected.start || actual.boot != expected.boot {
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
    let ScopeIdentity::WindowsJob { name, .. } = scope else {
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
    let job = Handle(raw);
    security::verify_job(&job)?;
    // SAFETY: initialized native POD output tied to this retained query-only job.
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    // SAFETY: exact live query handle, aligned full output and its exact byte size.
    if unsafe {
        QueryInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&limits) as u32,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last(
            ProcErrorCode::RecoveryUnproved,
            "query old job policy",
        ));
    }
    if limits.BasicLimitInformation.LimitFlags != LIMITS {
        return Err(input(
            "cold recovery job",
            "recorded kill-on-close/breakaway policy changed; preserve the object",
        ));
    }
    // SAFETY: initialized native POD accounting output.
    let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
    // SAFETY: retained job, aligned writable accounting structure and exact size.
    if unsafe {
        QueryInformationJobObject(
            job.0,
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of_val(&accounting) as u32,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last(
            ProcErrorCode::RecoveryUnproved,
            "read old job population",
        ));
    }
    if accounting.ActiveProcesses != 0 {
        return Err(error(ProcErrorCode::RecoveryUnproved, ProcErrorDetail::Input {
            field: "cold recovery job".into(), reason: "old job remains populated or another owner retains custody; no replacement or signal is authorized".into() }));
    }
    empty(scope.clone())
}
impl Driver {
    pub fn reconcile(&self, source: &RecoverySource) -> ProcResult<StopWitness> {
        reconcile(source)
    }
}

/// Query-only cold proof for a protected unpublished Windows scope. The old
/// owner must be gone and the exact private kill-on-close job empty or absent.
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
    };
    Ok((
        empty_job(&scope)?,
        ContainmentGuarantee::KernelScope {
            explicit_breakaway: true,
        },
    ))
}
