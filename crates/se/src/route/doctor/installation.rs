//! Compare only the owned installation record and its exact recorded PATH edits.
//! Edited user data is preserved; no guessed executable or profile path is used.
use super::{check, refused};
use crate::{
    bootstrap::Bootstrap,
    runtime::{InstallRecord, Installation},
};
use se_core::ops::doctor::*;
use se_types::{Result, SeError};
use sha2::{Digest, Sha256};
#[cfg(not(windows))]
use std::path::Path;
fn native(error: se_proc::StateFileError) -> SeError {
    se_core::scope::unreadable("doctor installation", &error.to_string())
}
fn record(cx: &Bootstrap) -> Result<Option<Installation>> {
    let path = cx.home.join("standalone-install.json");
    let Some(mut pin) = se_proc::OwnedFile::open(&path).map_err(native)? else {
        return Ok(None);
    };
    let record: InstallRecord = serde_json::from_slice(&pin.read(1024 * 1024).map_err(native)?)
        .map_err(|error| {
            refused(
                "installation.record",
                "the owned record is invalid; preserve it and the matching release archive",
            )
            .with_cause(error)
        })?;
    if record.schema != "stateengine-install/v1" {
        return Err(refused(
            "installation.record",
            "unsupported installation record schema",
        ));
    }
    let installed = Installation {
        record_path: path,
        record,
    };
    installed.plan()?;
    Ok(Some(installed))
}
pub(super) fn checks(cx: &Bootstrap, at: &str) -> Result<Vec<DiagnosisCheck>> {
    let Some(installed) = record(cx)? else {
        return Ok(vec![check("installation.record","Owned installation record",CheckState::NotApplicable,"No standalone installation record in this state home; no installation repair is inferred".into(),at)]);
    };
    let mut checks = vec![check(
        "installation.record",
        "Owned installation record",
        CheckState::Ok,
        "Bounded current-user record decoded and its protected-path exclusions validated".into(),
        at,
    )];
    for (index, edit) in installed.record.path_edits.iter().enumerate() {
        let id = format!("installation.path.{}", index + 1);
        let observed = observe(edit)?;
        let mut item = check(
            &id,
            "Owned PATH integration",
            if observed.present {
                CheckState::Ok
            } else {
                CheckState::Failed
            },
            observed.detail,
            at,
        );
        item.expected =
            Some("Exactly one unchanged recorded StateEngine PATH block or entry".into());
        item.repairable = observed.repairable;
        if observed.repairable {
            item.fix=Some(CheckFix{text:"Restore only the recorded missing PATH entry after comparing the complete original user value; edited values are preserved".into(),command:None,argv:Some(vec!["se".into(),"doctor".into(),"--fix".into(),id,"--home".into(),cx.home.display().to_string()])});
        }
        checks.push(item);
    }
    Ok(checks)
}
struct Observation {
    present: bool,
    repairable: bool,
    detail: String,
}
fn original(current: Option<&str>, edit: &crate::runtime::PathEdit) -> bool {
    match (&edit.before_sha256, current) {
        (Some(expected), Some(current)) => {
            expected.as_bytes() == &<[u8; 32]>::from(Sha256::digest(current.as_bytes()))
        }
        (None, None) | (None, Some("")) => true,
        _ => false,
    }
}
#[cfg(not(windows))]
fn observe(edit: &crate::runtime::PathEdit) -> Result<Observation> {
    let Some(mut pin) = se_proc::OwnedFile::open(Path::new(&edit.target)).map_err(native)? else {
        return Ok(Observation {
            present: false,
            repairable: false,
            detail: format!(
                "{} is absent; restore the recorded shell profile or rerun the matching installer before retrying this check",
                edit.target
            ),
        });
    };
    let bytes = pin.read(1024 * 1024).map_err(native)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| refused("installation.path", "the recorded profile is not UTF-8"))?;
    let count = text.matches(&edit.block).count();
    Ok(Observation {
        present: count == 1,
        repairable: count == 0 && original(Some(text), edit),
        detail: format!(
            "{}: {} exact recorded PATH blocks; other user edits are preserved",
            edit.target, count
        ),
    })
}
#[cfg(windows)]
fn observe(edit: &crate::runtime::PathEdit) -> Result<Observation> {
    let observed = se_proc::NativeUserPath::open()
        .read()
        .map_err(|error| se_core::scope::unreadable("user PATH", &error.to_string()))?;
    let count = observed
        .value()
        .map(|value| {
            value
                .split(';')
                .filter(|part| part.eq_ignore_ascii_case(&edit.block))
                .count()
        })
        .unwrap_or(0);
    Ok(Observation {
        present: count == 1,
        repairable: count == 0 && original(observed.value(), edit),
        detail: format!(
            "Recorded user PATH entry occurs {count} times; no process environment is changed"
        ),
    })
}
pub(super) fn repair(
    cx: &Bootstrap,
    caller: &super::super::admit::Caller,
    id: &str,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<RepairOutput> {
    let installed =
        record(cx)?.ok_or_else(|| refused(id, "the owned installation record is absent"))?;
    caller
        .owner
        .as_ref()
        .ok_or_else(|| refused(id, "normal complete-inventory owner admission is required"))?
        .authorize(
            "doctor.repair",
            &installed.record.owner,
            cx.session.is_some(),
            true,
        )?;
    let index = id
        .strip_prefix("installation.path.")
        .and_then(|value| value.parse::<usize>().ok())
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| refused(id, "unknown PATH check"))?;
    let edit = installed
        .record
        .path_edits
        .get(index)
        .ok_or_else(|| refused(id, "recorded PATH check is absent"))?;
    if !observe(edit)?.repairable {
        return Err(refused(
            id,
            "the current PATH value changed or has no supported exact repair; user edits were preserved",
        ));
    }
    diagnostic(&format!("Plan: repair {id} only; restore the exact recorded StateEngine PATH entry at {}; user work replaced 0, agents stopped 0, credentials changed 0; existing terminals retain their current environment.",edit.target)).map_err(|error|se_core::scope::unreadable("doctor plan output",&error.to_string()))?;
    apply(edit)?;
    let at = se_core::ops::receipt::timestamp(super::super::execute::now_us()?)?;
    let after = checks(cx, &at)?;
    let complete = after
        .iter()
        .any(|value| value.id == id && value.state == CheckState::Ok);
    Ok(RepairOutput {
        check_id: id.into(),
        complete,
        applied: vec![RepairFact {
            subject: edit.target.clone(),
            outcome: "restored-owned-path-entry".into(),
            detail: "Only the exact recorded entry was restored after complete-value comparison"
                .into(),
        }],
        skipped: vec![],
        readbacks: vec![RepairFact {
            subject: edit.target.clone(),
            outcome: if complete {
                "one-exact-entry"
            } else {
                "unresolved"
            }
            .into(),
            detail: "Fresh native readback; open a new login terminal to adopt PATH".into(),
        }],
        remaining_checks: after
            .into_iter()
            .filter(|value| !matches!(value.state, CheckState::Ok | CheckState::NotApplicable))
            .collect(),
    })
}
#[cfg(not(windows))]
fn apply(edit: &crate::runtime::PathEdit) -> Result<()> {
    let mut pin = se_proc::OwnedFile::open(Path::new(&edit.target))
        .map_err(native)?
        .ok_or_else(|| refused("installation.path", "profile disappeared after the plan"))?;
    let mut bytes = pin.read(1024 * 1024).map_err(native)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| refused("installation.path", "profile is no longer UTF-8"))?;
    if !original(Some(text), edit) {
        return Err(refused(
            "installation.path",
            "complete original profile changed after the plan",
        ));
    }
    let expected = Sha256::digest(&bytes).into();
    bytes.extend_from_slice(edit.block.as_bytes());
    pin.replace(expected, &bytes).map_err(native)?;
    if !observe(edit)?.present {
        return Err(refused(
            "installation.path",
            "independent profile reopen did not witness the exact restored entry",
        ));
    }
    Ok(())
}
#[cfg(windows)]
fn apply(edit: &crate::runtime::PathEdit) -> Result<()> {
    let native = se_proc::NativeUserPath::open();
    let before = native
        .read()
        .map_err(|error| se_core::scope::unreadable("user PATH", &error.to_string()))?;
    if !original(before.value(), edit) {
        return Err(refused(
            "installation.path",
            "complete original user PATH changed after the plan",
        ));
    }
    let replacement = match before.value() {
        Some(value) if !value.is_empty() => format!("{value};{}", edit.block),
        _ => edit.block.clone(),
    };
    native
        .compare_and_set(&before, Some(&replacement))
        .map_err(|error| se_core::scope::unreadable("user PATH repair", &error.to_string()))?;
    if !observe(edit)?.present {
        return Err(refused(
            "installation.path",
            "native reopen did not witness the exact restored PATH entry",
        ));
    }
    Ok(())
}
