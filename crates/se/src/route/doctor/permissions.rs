//! Narrow metadata-only recovery before store admission. No custody inventory,
//! store bytes or owner capability is inferred from a permission observation.
use super::{check, refused};
use crate::bootstrap::Bootstrap;
use se_core::{
    ops::{AnyOp, AnyOutput, doctor::*},
    scope,
};
use se_proc::{PermissionKind, PermissionRepairPin};
use se_types::{Result, SeError};
use std::{io::IsTerminal, path::Path};

struct Target {
    pin: PermissionRepairPin,
    check: DiagnosisCheck,
}
fn native(error: se_proc::StateFileError) -> SeError {
    scope::unreadable("doctor permission metadata", &error.to_string())
}
fn target(path: &Path, id: &str, title: &str, kind: PermissionKind, at: &str) -> Result<Target> {
    let pin = PermissionRepairPin::open(path)
        .map_err(native)?
        .ok_or_else(|| {
            refused(
                id,
                "the named installation object is absent; permission repair does not create it",
            )
        })?;
    describe(pin, id, title, kind, at)
}
fn open(path: &Path) -> Result<Option<PermissionRepairPin>> {
    match PermissionRepairPin::open(path) {
        Ok(pin) => Ok(pin),
        Err(error) if error.code == se_proc::StateFileErrorCode::Unsupported => Ok(None),
        Err(error) => Err(native(error)),
    }
}
pub(super) fn unsupported(id: &str, title: &str, at: &str) -> DiagnosisCheck {
    let mut value = check(id, title, CheckState::Unmeasured,
        "Native metadata-only permission repair is unavailable on this platform; other diagnosis checks continue".into(), at);
    value.measured_at = None;
    value.reason = value.observed.clone();
    value
}
fn describe(
    pin: PermissionRepairPin,
    id: &str,
    title: &str,
    kind: PermissionKind,
    at: &str,
) -> Result<Target> {
    let path = pin.path();
    if pin.snapshot().kind != kind {
        return Err(refused(
            id,
            "unexpected native object type; no permission change was attempted",
        ));
    }
    let protected = pin.is_owner_only().map_err(native)?;
    let mut value = check(
        id,
        title,
        if protected {
            CheckState::Ok
        } else {
            CheckState::Failed
        },
        format!("{}: {:?}", path.display(), pin.snapshot().protection),
        at,
    );
    value.expected = Some(
        if kind == PermissionKind::Directory {
            "Current OS owner; exact owner-only directory protection (Unix 0700)"
        } else {
            "Current OS owner; owner-only file protection (Unix 0600, or 0700 retaining existing owner execute access)"
        }
        .into(),
    );
    value.repairable = !protected;
    if !protected {
        value.fix = Some(CheckFix {text: "Tighten only this pinned object; preserve its owner, contents and descendants, then independently reopen its name".into(), command: None,
            argv: Some(vec!["se".into(), "doctor".into(), "--fix".into(), id.into(), "--home".into(), if kind == PermissionKind::Directory { path } else { path.parent().unwrap_or(path) }.display().to_string()])});
    }
    Ok(Target { pin, check: value })
}
const REGULAR: [(&str, &str, &str, bool); 2] = [
    (
        "credential.permissions",
        "Machine credential protection",
        "credential",
        true,
    ),
    (
        "runtime.endpoint.permissions",
        "Runtime endpoint protection",
        "endpoint.json",
        false,
    ),
];
/// These files require the ordinary complete-inventory owner guard. Only
/// metadata is observed; loose credential or endpoint bytes are never read.
pub(super) fn checks(cx: &Bootstrap, at: &str) -> Result<Vec<DiagnosisCheck>> {
    REGULAR.iter().map(|(id, title, leaf, required)| {
        let path = cx.home.join(leaf);
        match PermissionRepairPin::open(&path) {
            Err(error) if error.code == se_proc::StateFileErrorCode::Unsupported => Ok(unsupported(id, title, at)),
            Err(error) => Err(native(error)),
            Ok(Some(pin)) => Ok(describe(pin, id, title, PermissionKind::File, at)?.check),
            Ok(None) => Ok(check(id, title, if *required { CheckState::Failed } else { CheckState::NotApplicable },
                if *required { "The machine credential is absent; permission repair never creates or rotates it" } else { "No endpoint file is present; no permission repair is needed" }.into(), at)),
        }
    }).collect()
}
pub(super) fn is_regular(id: &str) -> bool {
    REGULAR.iter().any(|(name, _, _, _)| *name == id)
}
pub(super) fn repair(
    cx: &Bootstrap,
    files: &super::Files,
    caller: &super::Caller,
    id: &str,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<RepairOutput> {
    let (_, title, leaf, _) = REGULAR
        .iter()
        .find(|(name, _, _, _)| *name == id)
        .ok_or_else(|| refused(id, "unknown file permission check"))?;
    let owner = caller
        .owner
        .as_ref()
        .ok_or_else(|| refused(id, "normal complete-inventory owner admission is required"))?;
    owner.authorize(
        "doctor.repair",
        owner.os_owner(),
        cx.session.is_some(),
        true,
    )?;
    let at = se_core::ops::receipt::timestamp(crate::route::execute::now_us()?)?;
    let mut current = target(&cx.home.join(leaf), id, title, PermissionKind::File, &at)?;
    let (plan, fact, readback, changed) = tighten(&mut current, id, &at, cx.json, diagnostic)?;
    let after = super::observe(cx, files)?.diagnosis;
    let complete = after
        .checks
        .iter()
        .any(|check| check.id == id && check.state == CheckState::Ok);
    Ok(RepairOutput {
        check_id: id.into(),
        plan,
        complete,
        applied: if changed { vec![fact.clone()] } else { vec![] },
        skipped: if changed { vec![] } else { vec![fact] },
        readbacks: vec![readback],
        remaining_checks: after
            .checks
            .into_iter()
            .filter(|check| !matches!(check.state, CheckState::Ok | CheckState::NotApplicable))
            .collect(),
    })
}
fn tighten(
    current: &mut Target,
    id: &str,
    at: &str,
    json_output: bool,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<(RepairPlan, RepairFact, RepairFact, bool)> {
    let before = current.pin.snapshot().clone();
    let path = current.pin.path().to_owned();
    let protection = match &before.protection {
        se_proc::PermissionProtection::UnixMode { mode, group } => PermissionProtection::Unix {
            mode: *mode,
            group: *group,
        },
        se_proc::PermissionProtection::WindowsDacl { sddl, control } => {
            PermissionProtection::Windows {
                sddl: sddl.clone(),
                control: *control,
            }
        }
    };
    let plan = RepairPlan::TightenPermissions(PermissionRepairPlan {
        check_id: id.into(),
        target: path.display().to_string(),
        expected_before: PermissionBefore {
            native_object: se_types::hex_lower(&before.object),
            owner: before.owner.clone(),
            protection,
        },
        expected_after: PermissionAfter {
            same_native_object: true,
            same_owner: true,
            owner_only: true,
            retain_existing_owner_execute: before.kind == PermissionKind::File,
            contents_unchanged: true,
            descendants_unchanged: true,
        },
    });
    super::plan::emit(&plan, json_output, diagnostic)?;
    let witness = current.pin.tighten_owner_only(&before).map_err(native)?;
    let after = target(&path, id, &current.check.title, before.kind, at)?;
    if after.check.state != CheckState::Ok
        || witness.after.object != before.object
        || witness.after.owner != before.owner
    {
        return Err(refused(
            id,
            "independent named metadata readback did not verify the exact original object with owner-only protection",
        ));
    }
    let changed = witness.before != witness.after;
    Ok((plan, RepairFact {
        subject: path.display().to_string(),
        outcome: if changed { "tightened" } else { "already-correct" }.into(),
        detail: serde_json::to_string(&witness).map_err(|error| scope::unreadable("doctor metadata witness", &error.to_string()))?,
    }, RepairFact {
        subject: path.display().to_string(), outcome: "owner-only".into(),
        detail: "Independent no-follow reopen verified the same native identity and owner with exact private protection".into(),
    }, changed))
}
fn unmeasured(at: &str, reason: &str) -> DiagnosisCheck {
    check(
        "store.open",
        "Store and custody admission",
        CheckState::Unmeasured,
        reason.into(),
        at,
    )
}
fn installation(cx: &Bootstrap, owner: &str) -> Result<()> {
    let path = cx.home.join("standalone-install.json");
    let mut pin = se_proc::OwnedFile::open(&path).map_err(native)?
        .ok_or_else(|| refused("home.permissions", "the owned installation record is absent; recovery only applies to an installed state home"))?;
    let bytes = pin.read(1024 * 1024).map_err(native)?;
    let record: crate::runtime::InstallRecord =
        serde_json::from_slice(&bytes).map_err(|error| {
            refused("home.permissions", "the installation record is unreadable").with_cause(error)
        })?;
    if record.schema != "stateengine-install/v1" || record.owner != owner {
        return Err(refused(
            "home.permissions",
            "installation record schema or owner does not match the pinned state root",
        ));
    }
    let installed = crate::runtime::Installation {
        record_path: path,
        record,
    };
    if installed.plan()?.state_home() != cx.home {
        return Err(refused(
            "installation.record",
            "the installation record does not match the selected state root; no further repair was attempted",
        ));
    }
    // No file listed by the record becomes a permission repair target.
    Ok(())
}
/// Some returns a complete bounded diagnosis or exactly one named tightening.
/// None continues ordinary owner-human admission, including the full inventory.
pub(in crate::route) fn recover(
    cx: &Bootstrap,
    op: &AnyOp,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<Option<AnyOutput>> {
    let at = se_core::ops::receipt::timestamp(crate::route::execute::now_us()?)?;
    // A missing ancestor is measured by the ordinary setup reader, which also
    // supplies se init. Do not turn it into a permission mutation target.
    if let Err(error) = std::fs::symlink_metadata(&cx.home)
        && error.kind() == std::io::ErrorKind::NotFound
    {
        return Ok(None);
    }
    let Some(pin) = open(&cx.home)? else {
        return Ok(None);
    };
    let mut root = describe(
        pin,
        "home.permissions",
        "Protected state home",
        PermissionKind::Directory,
        &at,
    )?;
    let selected = match op {
        AnyOp::DoctorRepair(value) => Some(value.check_id.as_str()),
        _ => None,
    };
    let root_loose = root.check.state == CheckState::Failed;
    // Do not walk into an unprotected root just to diagnose another object.
    let mut database = if root_loose {
        None
    } else {
        let Some(pin) = open(&cx.home.join("state.db"))? else {
            return Ok(None);
        };
        Some(describe(
            pin,
            "store.permissions",
            "Protected database",
            PermissionKind::File,
            &at,
        )?)
    };
    let db_loose = database
        .as_ref()
        .is_some_and(|value| value.check.state == CheckState::Failed);
    if !root_loose
        && !db_loose
        && !matches!(selected, Some("home.permissions" | "store.permissions"))
    {
        return Ok(None);
    }
    let mut checks = vec![root.check.clone()];
    if let Some(db) = &database {
        checks.push(db.check.clone());
    }
    checks.push(unmeasured(&at,"Store bytes and custody inventory have not been opened; permission metadata supplies no admission authority"));
    let Some(id) = selected else {
        return Ok(Some(
            Diagnosis::new(
                at,
                DiagnosisScope {
                    home: cx.home.display().to_string(),
                    project: None,
                },
                checks,
            )?
            .into(),
        ));
    };
    if !matches!(id, "home.permissions" | "store.permissions") {
        return Err(refused(
            id,
            "restore the named permission invariant first; other repairs require normal store and custody admission",
        ));
    }
    // This exception grants only permission tightening, never owner admission.
    // Preserve explicit human presence without treating a terminal as an empty
    // custody inventory or as authority for any subsequent operation.
    if cx.session.is_some() || !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(refused(
            id,
            "this explicit recovery needs an interactive terminal and no managed session; no store authority is inferred",
        ));
    }
    if id == "home.permissions" {
        // Use the installer's selection policy, without inspecting anything
        // inside a loose root. A caller-supplied arbitrary --home is not a
        // platform installation and cannot acquire this recovery exception.
        if cx.home != crate::bootstrap::state_home(None)? {
            return Err(refused(
                id,
                "root recovery requires the selected per-user installation home; restore the matching HOME/XDG/SE_HOME selection and retry",
            ));
        }
    } else {
        installation(cx, &root.pin.snapshot().owner)?;
    }
    let current = if id == "home.permissions" {
        &mut root
    } else {
        database.as_mut().ok_or_else(|| {
            refused(
                id,
                "state root protection must be restored before opening the database path",
            )
        })?
    };
    let (plan, fact, readback, changed) = tighten(current, id, &at, cx.json, diagnostic)?;
    if id == "home.permissions" {
        // The regular file reader is usable only after root protection has
        // been independently witnessed. A failed record check leaves the
        // tightening in place but grants no database or store authority.
        installation(cx, &root.pin.snapshot().owner).map_err(|error| {
            refused(
                "installation.record",
                &format!("the state root now has owner-only protection, but its installation record could not be verified; no database or store access was attempted: {error}"),
            )
        })?;
    }
    let mut remaining = Vec::new();
    // Resume the regular protected reader and complete custody guard now. Any
    // failure remains an obligation; it never erases the achieved tightening.
    match super::super::setup::inspect_phase(&cx.home, at.clone()) {
        Ok(super::super::setup::Setup::Present((files, (reader, phase)))) => {
            let admission = super::super::admit::observe(cx, &phase, &files);
            drop(phase);
            drop(reader);
            if let Err(error) = admission {
                remaining.push(unmeasured(&at, &error.to_string()));
            }
        }
        Ok(super::super::setup::Setup::Absent(_)) => remaining.push(super::setup_check(cx, &at)),
        Err(error) => remaining.push(unmeasured(&at, &error.to_string())),
    }
    Ok(Some(
        RepairOutput {
            check_id: id.into(),
            plan,
            complete: remaining.is_empty(),
            applied: if changed { vec![fact.clone()] } else { vec![] },
            skipped: if changed { vec![] } else { vec![fact] },
            readbacks: vec![readback],
            remaining_checks: remaining,
        }
        .into(),
    ))
}
