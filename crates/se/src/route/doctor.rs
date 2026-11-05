//! One diagnosed endpoint repair. The exclusive native lease is never removed or broken.
use super::{admit::Caller, files::Files};
use crate::bootstrap::Bootstrap;
use se_core::ops::inputs::Validate;
use se_core::{
    ops::{AnyOp, AnyOutput, doctor::*},
    scope,
    store_error::store_error,
};
use se_store::{EventBody, ReadStore, Snapshot, SqliteFactory, StoreFactory, StoreOptions};
use se_types::Result;
use sha2::{Digest, Sha256};
use std::{fs::TryLockError, io::Read, time::Duration};
mod configuration;
mod installation;
mod lifecycle;
pub(super) mod permissions;
mod plan;

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
    Ok(Some(bytes))
}
fn observe<R: se_store::ReadStore>(cx: &Bootstrap, files: &Files, reader: &R, extra: &[DiagnosisCheck]) -> Result<Observed> {
    let at = se_core::ops::receipt::timestamp(super::execute::now_us()?)?;
    // These two checks report measurements already required by dispatch:
    // setup::inspect_phase opens NativeStateFiles and validates the store;
    // admit::observe completes the owner inventory, then dispatch opens and
    // closes its snapshot before calling execute here. Permission recovery
    // and uninitialized diagnosis take their separate, unmeasured paths.
    let home = if cfg!(any(target_os = "linux", windows)) {
        check(
            "home.permissions",
            "Protected state home",
            CheckState::Ok,
            "Native owner-only root checks passed during protected setup admission".into(),
            &at,
        )
    } else {
        permissions::unsupported("home.permissions", "Protected state home", &at)
    };
    let mut checks = vec![
        home,
        check(
            "store.open",
            "Initialized store",
            CheckState::Ok,
            "Protected store and complete owner inventory opened successfully before diagnosis"
                .into(),
            &at,
        ),
    ];
    if !cfg!(any(target_os = "linux", windows)) {
        checks.push(permissions::unsupported(
            "store.permissions",
            "Protected database",
            &at,
        ));
    }
    let permission_checks = permissions::checks(cx, &at)?;
    let loose_file = permission_checks
        .iter()
        .any(|check| check.state == CheckState::Failed);
    checks.extend(permission_checks);
    if loose_file {
        checks.push(check("runtime.endpoint", "Runtime endpoint", CheckState::Unmeasured,
            "Restore the named file protection before inspecting endpoint contents; unreadable bytes are not an absent endpoint".into(), &at));
        checks.extend(extra.iter().cloned());
        checks.extend(installation::checks(cx, &at));
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
    checks.extend(extra.iter().cloned());
    checks.push(configuration::check(cx, &at)?);
    checks.extend(lifecycle::checks(cx, files, reader, &at)?);
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
    checks.push(check("runtime.lock","Runtime lease",if free.is_some(){CheckState::Ok}else{CheckState::Failed},match free {Some(true)=>"Exclusive lease is available",Some(false)=>"Lease is held; doctor will not break it",None=>"The store is initialized, but runtime.lock is absent; its absence is not permission to create a replacement"}.into(),&at));
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
    if let Some(bytes) = &endpoint
        && let Err(error) = super::endpoint_diagnostic::decode(&cx.home, bytes)
    {
        endpoint_check.state = CheckState::Failed;
        endpoint_check.code = Some(error.code().as_str().into());
        endpoint_check.observed = Some(error.body.message());
        endpoint_check.reason = Some("The protected endpoint cannot be decoded; its existence does not prove usable live routing".into());
        endpoint_check.fix = Some(CheckFix {
            text: super::endpoint_diagnostic::repair(&cx.home),
            command: None,
            argv: None,
        });
    }
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
    drop(lock);
    checks.extend(installation::checks(cx, &at));
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
/// Called only after the ordinary setup reader measured store absence. No
/// endpoint observation or permission-repair failure supplies that fact.
/// The registered project root must exist on disk. When it is missing the
/// diagnosis names the remedy: a moved repository re-attaches with
/// `se project move`, which verifies the recorded git identity.
fn project_root_check(
    cx: &Bootstrap,
    admission: &se_store::Admission,
    at: &str,
) -> Result<Option<DiagnosisCheck>> {
    let project = match scope::project(admission) {
        Ok(project) => project,
        Err(_) => return Ok(None),
    };
    let options = StoreOptions {
        state_directory: cx.home.clone(),
        busy_timeout: Duration::from_millis(250),
    };
    let reader = scope::require_present(
        SqliteFactory::open_reader(&options).map_err(|e| store_error(&e))?,
        "doctor store",
        "Restore access to the initialized store in this same data home, then rerun se doctor.",
    )?;
    let mut snapshot = reader
        .snapshot(se_core::admission::read_scope(admission))
        .map_err(|e| store_error(&e))?;
    let record = scope::require_present(
        snapshot
            .project(project.clone())
            .map_err(|e| store_error(&e))?,
        "doctor project metadata",
        "Restore access to the retained project metadata in this data home, then rerun se doctor.",
    )?;
    let roots = match &record.current.body {
        EventBody::ProjectRegistered {
            project: id, roots, ..
        } if project == *id => roots.clone(),
        EventBody::ProjectUpdated {
            project: id, roots, ..
        } if project == *id => roots.clone(),
        EventBody::ProjectMoved {
            project: id, to, ..
        } if project == *id => vec![to.clone()],
        _ => return Ok(None),
    };
    snapshot.close().map_err(|e| store_error(&e))?;
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for root in &roots {
        let path = root
            .path
            .to_local()
            .map_err(|e| scope::unreadable("registered root", &e.to_string()))?;
        if path.exists() {
            present.push(path);
        } else {
            missing.push(path);
        }
    }
    let at = at.to_owned();
    if missing.is_empty() {
        let check = check(
            "project.root",
            "Registered project root",
            CheckState::Ok,
            format!(
                "{} of {} registered roots present on disk",
                present.len(),
                roots.len()
            ),
            &at,
        );
        return Ok(Some(check));
    }
    let mut check = check(
        "project.root",
        "Registered project root",
        CheckState::Failed,
        format!(
            "{} of {} registered roots present; missing: {}",
            present.len(),
            roots.len(),
            missing
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        &at,
    );
    check.reason = Some(
        "Launch and project selection use this root; a moved or renamed repository re-attaches with se project move"
            .into(),
    );
    check.fix = Some(CheckFix {
        text: "If the repository was moved or renamed, run `se project move <new-folder>` (it verifies the recorded git identity); otherwise restore the folder at the recorded path".into(),
        command: None,
        argv: Some(vec![
            "se".into(),
            "--home".into(),
            cx.home.display().to_string(),
            "--project".into(),
            project.to_string(),
            "project".into(),
            "move".into(),
            "<new-folder>".into(),
        ]),
    });
    Ok(Some(check))
}
pub(super) fn uninitialized(cx: &Bootstrap, op: &AnyOp) -> Result<AnyOutput> {
    let owner = super::owner::observe(&[])?;
    owner.authorize(
        op.meta().name,
        owner.os_owner(),
        cx.session.is_some(),
        false,
    )?;
    if matches!(op, AnyOp::DoctorRepair(_)) {
        return Err(super::setup::required(cx));
    }
    let at = se_core::ops::receipt::timestamp(super::execute::now_us()?)?;
    let mut checks = vec![setup_check(cx, &at)];
    match std::fs::symlink_metadata(&cx.home) {
        Ok(_) => checks.extend(installation::checks(cx, &at)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            checks.push(check(
                "home.permissions",
                "Protected state home",
                CheckState::NotApplicable,
                "Absent: se init creates the selected state home; there is no object to repair"
                    .into(),
                &at,
            ));
            checks.push(check("installation.record", "Owned installation record", CheckState::NotApplicable,
                "No installation record can exist in the absent state home; no PATH edits are inferred".into(), &at));
        }
        Err(error) => return Err(scope::unreadable("state home metadata", &error.to_string())),
    }
    Ok(Diagnosis::new(
        at,
        DiagnosisScope {
            home: cx.home.display().to_string(),
            project: None,
        },
        checks,
    )?
    .into())
}
fn setup_check(cx: &Bootstrap, at: &str) -> DiagnosisCheck {
    let mut setup = check(
        "store.open",
        "Initialized store",
        CheckState::Failed,
        "Absent: no initialized store in this state home; run se init".into(),
        at,
    );
    setup.code = Some("setup-required".into());
    setup.fix = Some(CheckFix {
        text: "Run se init to set up this workspace and launch your first agent".into(),
        command: None,
        argv: Some(vec![
            "se".into(),
            "--home".into(),
            cx.home.display().to_string(),
            "init".into(),
            "--repo".into(),
            cx.cwd.display().to_string(),
        ]),
    });
    setup
}
pub fn execute<R: se_store::ReadStore>(
    cx: &Bootstrap,
    files: &Files,
    reader: &R,
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
    let extra = project_root_check(
        cx,
        &caller.admission,
        &se_core::ops::receipt::timestamp(super::execute::now_us()?)?,
    )?
    .into_iter()
    .collect::<Vec<_>>();
    let observed = observe(cx, files, reader, &extra)?;
    let AnyOp::DoctorRepair(input) = op else {
        return Ok(observed.diagnosis.into());
    };
    input.validate()?;
    if permissions::is_regular(&input.check_id) {
        return Ok(
            permissions::repair(cx, files, reader, caller, &input.check_id, diagnostic)?.into(),
        );
    }
    if input.check_id.starts_with("installation.path.") {
        return Ok(installation::repair(cx, caller, &input.check_id, diagnostic)?.into());
    }
    observed.diagnosis.repair_check(&input.check_id)?;
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
    let plan = RepairPlan::RetainEndpoint(EndpointRetentionPlan {
        check_id: input.check_id.clone(),
        target: source.display().to_string(),
        expected_before: EndpointBefore {
            sha256: se_types::hex_lower(&digest),
            bytes: expected.len() as u64,
            exclusive_runtime_lease_required: true,
        },
        expected_after: EndpointAfter {
            original_absent: true,
            retained: retained.display().to_string(),
            sha256: se_types::hex_lower(&digest),
        },
    });
    plan::emit(&plan, cx.json, diagnostic)?;
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
    se_host::retain_endpoint_at(&files.0, &expected, &retained)?;
    drop(lock);
    let after = observe(cx, files, reader, &extra)?.diagnosis;
    let complete = after
        .checks
        .iter()
        .any(|check| check.id == input.check_id && check.state == CheckState::Ok);
    Ok(RepairOutput {check_id:input.check_id,plan,complete,
        applied:vec![RepairFact{subject:source.display().to_string(),outcome:"retained".into(),detail:retained.display().to_string()}],
        skipped:vec![],readbacks:vec![RepairFact{subject:source.display().to_string(),outcome:"absent".into(),detail:format!("Exact original bytes reopened at {}; exclusive lease held throughout retention and readback",retained.display())}],
        remaining_checks:after.checks.into_iter().filter(|check|!matches!(check.state,CheckState::Ok|CheckState::NotApplicable)).collect(),
    }.into())
}
