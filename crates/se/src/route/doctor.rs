//! One diagnosed endpoint repair. The exclusive native lease is never removed or broken.
use super::{admit::Caller, files::Files};
use crate::bootstrap::Bootstrap;
use se_core::ops::inputs::Validate;
use se_core::{
    ops::{AnyOp, AnyOutput, doctor::*},
    scope,
};
use se_types::{Result, SeError};
use sha2::{Digest, Sha256};
use std::{fs::TryLockError, io::Read};
mod installation;
pub(super) mod permissions;

struct Observed {
    diagnosis: Diagnosis,
    endpoint: Option<Vec<u8>>,
}
fn check(id: &str, title: &str, state: CheckState, observed: String, at: &str) -> DiagnosisCheck {
    DiagnosisCheck {
        id: id.into(),
        title: title.into(),
        state,
        measured_at: Some(at.into()),
        observed: Some(observed),
        expected: None,
        reason: None,
        code: None,
        fix: None,
        repairable: false,
    }
}
fn raw_endpoint(files: &Files) -> Result<Option<Vec<u8>>> {
    let Some(file) = files
        .0
        .readback(&files.0.root().join("endpoint.json"))
        .map_err(|error| scope::unreadable("doctor endpoint", &error.to_string()))?
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(se_host::client::wire::MAX_ENDPOINT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            scope::unreadable("doctor endpoint", &error.to_string()).with_cause(error)
        })?;
    if bytes.len() > se_host::client::wire::MAX_ENDPOINT_BYTES {
        return Err(SeError::too_large(
            "doctor endpoint",
            se_host::client::wire::MAX_ENDPOINT_BYTES,
            bytes.len(),
        ));
    }
    Ok(Some(bytes))
}
fn observe(cx: &Bootstrap, files: &Files) -> Result<Observed> {
    let at = se_core::ops::receipt::timestamp(super::execute::now_us()?)?;
    let mut checks = vec![
        check(
            "home.permissions",
            "Protected state home",
            CheckState::Ok,
            "Native owner-only root checks passed".into(),
            &at,
        ),
        check(
            "store.open",
            "Initialized store",
            CheckState::Ok,
            "Protected store and complete owner inventory opened successfully".into(),
            &at,
        ),
    ];
    let permission_checks = permissions::checks(cx, &at)?;
    let loose_file = permission_checks
        .iter()
        .any(|check| check.state == CheckState::Failed);
    checks.extend(permission_checks);
    if loose_file {
        checks.push(check("runtime.endpoint", "Runtime endpoint", CheckState::Unmeasured,
            "Restore the named file protection before inspecting endpoint contents; unreadable bytes are not an absent endpoint".into(), &at));
        checks.extend(installation::checks(cx, &at)?);
        return Ok(Observed {
            diagnosis: Diagnosis::new(
                at,
                DiagnosisScope {
                    home: cx.home.display().to_string(),
                    project: None,
                },
                checks,
            )?,
            endpoint: None,
        });
    }
    let lock = files
        .0
        .readback(&cx.home.join("runtime.lock"))
        .map_err(|error| scope::unreadable("doctor runtime lease", &error.to_string()))?;
    let free = match lock.as_ref() {
        Some(file) => match file.try_lock() {
            Ok(()) => Some(true),
            Err(TryLockError::WouldBlock) => Some(false),
            Err(TryLockError::Error(error)) => {
                return Err(
                    scope::unreadable("doctor runtime lease", &error.to_string()).with_cause(error),
                );
            }
        },
        None => None,
    };
    checks.push(check("runtime.lock","Runtime lease",if free.is_some(){CheckState::Ok}else{CheckState::Failed},match free {Some(true)=>"Exclusive lease is available",Some(false)=>"Lease is held; doctor will not break it",None=>"Initialized runtime.lock is absent; its absence is not permission to create a replacement"}.into(),&at));
    let endpoint = raw_endpoint(files)?;
    let mut endpoint_check = check(
        "runtime.endpoint",
        "Runtime endpoint",
        match (endpoint.is_some(), free) {
            (true, Some(true)) => CheckState::Failed,
            (false, Some(false)) => CheckState::Warning,
            (_, None) => CheckState::Unmeasured,
            _ => CheckState::Ok,
        },
        match (endpoint.is_some(), free) {
            (true, Some(true)) => {
                "Protected endpoint remains while the exclusive runtime lease is available"
            }
            (true, Some(false)) => {
                "Protected endpoint exists while the lease is held; live routing is preserved"
            }
            (false, Some(true)) => "No endpoint; runtime lease is free",
            (false, Some(false)) => {
                "Lease is held without an endpoint; startup or a direct writer may be in progress"
            }
            (_, None) => {
                "Endpoint status cannot establish runtime custody without its initialized lock"
            }
        }
        .into(),
        &at,
    );
    if endpoint.is_some() && free == Some(true) {
        endpoint_check.expected =
            Some("Endpoint absent when no cooperating host holds the runtime lease".into());
        endpoint_check.reason =
            Some("The endpoint is stale; retaining it does not stop or signal any process".into());
        endpoint_check.repairable = true;
        let argv = vec![
            "se".into(),
            "doctor".into(),
            "--fix".into(),
            "runtime.endpoint".into(),
            "--home".into(),
            cx.home.display().to_string(),
        ];
        endpoint_check.fix=Some(CheckFix{text:"Retain only the exact stale endpoint under an exclusive lease, then reopen both names".into(),command:None,argv:Some(argv)});
    }
    checks.push(endpoint_check);
    checks.extend(installation::checks(cx, &at)?);
    drop(lock);
    Ok(Observed {
        diagnosis: Diagnosis::new(
            at,
            DiagnosisScope {
                home: cx.home.display().to_string(),
                project: None,
            },
            checks,
        )?,
        endpoint,
    })
}
pub fn execute(
    cx: &Bootstrap,
    files: &Files,
    caller: &Caller,
    op: AnyOp,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<AnyOutput> {
    se_core::admission::authorize(op.meta(), &caller.admission)?;
    if op.requires_human_terminal()? {
        se_core::admission::require_human_terminal(
            op.meta().name,
            &caller.admission,
            &caller.terminal,
        )?;
    }
    let observed = observe(cx, files)?;
    let AnyOp::DoctorRepair(input) = op else {
        return Ok(observed.diagnosis.into());
    };
    input.validate()?;
    if permissions::is_regular(&input.check_id) {
        return Ok(permissions::repair(cx, files, caller, &input.check_id, diagnostic)?.into());
    }
    observed.diagnosis.repair_check(&input.check_id)?;
    if input.check_id.starts_with("installation.path.") {
        return Ok(installation::repair(cx, caller, &input.check_id, diagnostic)?.into());
    }
    if input.check_id != "runtime.endpoint" {
        return Err(refused(
            &input.check_id,
            "this check has no admitted native repair adapter",
        ));
    }
    let expected = observed
        .endpoint
        .ok_or_else(|| refused(&input.check_id, "endpoint disappeared after diagnosis"))?;
    let digest: [u8; 32] = Sha256::digest(&expected).into();
    let random = se_proc::random_secret()
        .map_err(|error| scope::unreadable("doctor retention identity", &error.to_string()))?;
    let retained = cx.home.join(format!(
        "endpoint.retained-{}.json",
        se_types::hex_lower(&random.expose()[..16])
    ));
    let source = cx.home.join("endpoint.json");
    diagnostic(&format!("Plan: repair runtime.endpoint only; retain {} as {} after exclusive-lease and exact-byte checks; agents ended 0, credentials rotated 0, events lost 0.",source.display(),retained.display()))
        .map_err(|error|scope::unreadable("doctor plan output",&error.to_string()).with_cause(error))?;
    let lock = files
        .0
        .readback(&cx.home.join("runtime.lock"))
        .map_err(|error| scope::unreadable("doctor runtime lease", &error.to_string()))?
        .ok_or_else(|| {
            refused(
                &input.check_id,
                "runtime.lock disappeared; no replacement or lease break is allowed",
            )
        })?;
    lock.try_lock().map_err(|error| {
        refused(
            &input.check_id,
            &format!("exclusive lease could not be acquired; the endpoint was preserved: {error}"),
        )
    })?;
    let mut pin = se_proc::OwnedFile::open(&source)
        .map_err(|error| scope::unreadable("doctor endpoint pin", &error.to_string()))?
        .ok_or_else(|| {
            refused(
                &input.check_id,
                "the diagnosed endpoint disappeared; run doctor again",
            )
        })?;
    if pin
        .read(se_host::client::wire::MAX_ENDPOINT_BYTES)
        .map_err(|error| scope::unreadable("doctor endpoint compare", &error.to_string()))?
        != expected
    {
        return Err(refused(
            &input.check_id,
            "endpoint changed after the plan; the new bytes were preserved",
        ));
    }
    pin.restore_to(&retained, digest)
        .map_err(|error| scope::unreadable("doctor endpoint retention", &error.to_string()))?;
    let reopened = files
        .0
        .readback(&retained)
        .map_err(|error| scope::unreadable("doctor retained endpoint", &error.to_string()))?
        .ok_or_else(|| {
            scope::unreadable(
                "doctor retained endpoint",
                "retained file is absent after the repair",
            )
        })?;
    let mut bytes = Vec::new();
    reopened
        .take(se_host::client::wire::MAX_ENDPOINT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| scope::unreadable("doctor endpoint readback", &error.to_string()))?;
    if bytes != expected || raw_endpoint(files)?.is_some() {
        return Err(scope::unreadable(
            "doctor endpoint readback",
            &format!(
                "Repair verification is incomplete; preserve {} and {}",
                source.display(),
                retained.display()
            ),
        ));
    }
    drop(lock);
    let after = observe(cx, files)?.diagnosis;
    let complete = after
        .checks
        .iter()
        .any(|check| check.id == input.check_id && check.state == CheckState::Ok);
    Ok(RepairOutput {check_id:input.check_id,complete,
        applied:vec![RepairFact{subject:source.display().to_string(),outcome:"retained".into(),detail:retained.display().to_string()}],
        skipped:vec![],readbacks:vec![RepairFact{subject:source.display().to_string(),outcome:"absent".into(),detail:format!("Exact original bytes reopened at {}; exclusive lease held throughout retention and readback",retained.display())}],
        remaining_checks:after.checks.into_iter().filter(|check|!matches!(check.state,CheckState::Ok|CheckState::NotApplicable)).collect(),
    }.into())
}
