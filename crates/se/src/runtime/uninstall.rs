//! Execute an admitted exact plan. Every outcome comes from a native readback;
//! unproved custody keeps the installed image and record available for retry.
use super::*;
use crate::{bootstrap::Bootstrap, route};
use se_core::ops::{installation::UninstallEffects, outputs::*};
use se_proc::{DirectoryRemoval, OwnedFile, StateFileError, StateFileErrorCode};
use se_types::Read;
use std::{
    io,
    time::{SystemTime, UNIX_EPOCH},
};
#[path = "uninstall/effects.rs"]
mod effects;
#[path = "uninstall/image.rs"]
mod image;
#[path = "uninstall/path.rs"]
mod path;
use effects::*;
use image::remove_image;
#[path = "uninstall/recovery.rs"]
mod recovery;
use path::reconcile_paths;
use recovery::recover;

pub(super) fn execute(
    cx: &Bootstrap,
    diagnostic: &mut dyn FnMut(&str) -> io::Result<()>,
) -> Result<(UninstallPlan, UninstallEffects)> {
    // Missing runtime endpoints are deliberately not consulted as an empty-process proof.
    match route::setup::inspect(&cx.home, clock())? {
        route::setup::Setup::Absent(_) => (),
        route::setup::Setup::Present(reader) => {
            let files = route::files::Files::open(&cx.home)
                .map_err(|e| se_core::store_error::store_error(&e))?;
            let inventory = route::owner::inventory(&reader, &files)?;
            return Err(se_core::scope::unreadable(
                "uninstall runtime control",
                &format!(
                    "the store has {} unresolved process records; the bounded stop and durable session-revocation consumer must complete before removing installation files",
                    inventory.processes.len()
                ),
            ));
        }
    }
    let owner = route::owner::observe(&[])?; // measured store absence above, never endpoint absence.
    owner.authorize(
        "installation.uninstall",
        owner.os_owner(),
        cx.session.is_some(),
        true,
    )?;
    let mut installation_claim =
        Some(se_proc::NativeInstallationClaim::acquire().map_err(native_error)?);
    #[cfg(windows)]
    super::helper_cleanup::retry(
        &se_proc::NativeStateFiles::open(&cx.home).map_err(native_error)?,
        installation_claim
            .as_ref()
            .ok_or_else(|| invalid("native installation claim missing"))?,
    )?;
    let record_path = cx.home.join("standalone-install.json");
    let mut record = OwnedFile::open(&record_path)
        .map_err(native_error)?
        .ok_or_else(|| invalid("the owned installation record is absent"))?;
    record.claim_installation_record().map_err(native_error)?;
    let record_bytes = record.read(1024 * 1024).map_err(native_error)?;
    let record_digest = record.sha256().map_err(native_error)?;
    if record_digest != <[u8; 32]>::from(Hasher::digest(&record_bytes)) {
        return Err(conflict(&record_path.to_string_lossy()));
    }
    let parsed: InstallRecord = serde_json::from_slice(&record_bytes)
        .map_err(|error| invalid("the held installation record is invalid").with_cause(error))?;
    if parsed.schema != "stateengine-install/v1" {
        return Err(invalid(
            "the held installation record has a different schema or owner",
        ));
    }
    owner.authorize(
        "installation.uninstall",
        &parsed.owner,
        cx.session.is_some(),
        true,
    )?;
    let owned_plan = Installation {
        record_path: record_path.clone(),
        record: parsed,
    }
    .plan()?;
    let plan = &owned_plan;
    let mut record = Some(record);
    let current = std::env::current_exe()
        .map_err(|error| unreadable(Path::new("running executable"), error))?;
    let canonical = std::fs::canonicalize(&current).map_err(|error| unreadable(&current, error))?;
    let mut matches = Vec::new();
    for file in &plan.files {
        match std::fs::canonicalize(&file.path) {
            Ok(path) if path == canonical => matches.push(file.path.clone()),
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(unreadable(Path::new(&file.path), error)),
        }
    }
    if matches.len() != 1 {
        return Err(invalid(
            "the admitted plan must uniquely own the running image",
        ));
    }
    let image = matches.remove(0);

    let mut effects = UninstallEffects {
        install_files: Vec::new(),
        directories: Vec::new(),
        integrations: Vec::new(),
        stops: Vec::new(),
        revocations: Vec::new(),
        path: PathEffect {
            scope: if cfg!(windows) {
                "current user"
            } else {
                "owned shell profiles"
            }
            .into(),
            before_entries: Vec::new(),
            after_entries: Vec::new(),
            witness: witness(
                WitnessState::Unknown,
                "PATH reconciliation has not completed",
                None,
            ),
        },
        path_complete: false,
        preserved: preserved(&cx.home),
        recovery: Vec::new(),
    };
    let parents = plan.recovery_directories()?;
    effects.recovery = scan(plan, &parents);
    // Diagnostics flush before recovery restoration, PATH edits or file removal.
    let mut diagnosis = String::from(
        "Uninstall: runtime store absence measured. Agents ended: 0; credentials revoked: 0; events lost: 0. User repositories, retained history/configuration and provider login are preserved.\n",
    );
    for file in &plan.files {
        diagnosis.push_str(&format!(
            "Remove exact owned file {} at SHA-256 {}\n",
            file.path, file.sha256
        ));
    }
    for directory in &plan.created_directories {
        diagnosis.push_str(&format!("Remove only if empty: {directory}\n"));
    }
    for edit in &plan.path_edits {
        diagnosis.push_str(&format!(
            "Remove only the recorded StateEngine entry from {}\n",
            edit.target
        ));
    }
    diagnosis.push_str("Recovery: restore only a uniquely proved owned backup to an absent planned target in its original directory; preserve every unresolved copy.\n");
    diagnostic(&diagnosis)
        .map_err(|error| se_core::scope::unreadable("uninstall diagnostic", &error.to_string()))?;
    recover(plan, &mut effects.recovery);
    cleanup_temporary(
        plan,
        installation_claim
            .as_ref()
            .ok_or_else(|| invalid("native installation claim missing"))?,
        &mut effects.recovery,
    );
    let clean = effects.recovery.iter().all(recovery::resolved);
    if !clean {
        pending_assets(
            plan,
            &mut effects,
            "recovery inventory is unreadable or contains unresolved copies",
        );
        return Ok((owned_plan, effects));
    }
    let mut safe = true;
    reconcile_paths(plan, &mut effects);
    safe &= effects.path_complete;
    for file in plan.files.iter().filter(|file| file.path != image) {
        let result = remove_file(file);
        safe &= matches!(
            result.outcome,
            FileOutcome::Removed | FileOutcome::AlreadyAbsent
        );
        effects.install_files.push(result);
    }
    effects.recovery = recovery::merge(effects.recovery, scan(plan, &parents));
    safe &= effects.recovery.iter().all(recovery::resolved);
    // Never strand a partially removed installation without its retry entry point.
    let installed = plan
        .files
        .iter()
        .find(|file| file.path == image)
        .ok_or_else(|| invalid("running image disappeared from the plan"))?;
    if safe {
        #[cfg(windows)]
        {
            drop(record.take());
            // The authenticated helper must acquire the same account-wide
            // claim before Ready. If another installer wins, no image
            // authorization is sent and the installed retry entry survives.
            drop(installation_claim.take());
        }
        effects
            .install_files
            .push(remove_image(cx, plan, installed, record_digest)?);
    } else {
        effects.install_files.push(file_effect(
            &installed.path,
            FileOutcome::Pending,
            WitnessState::Unknown,
            "installed image preserved so unresolved effects can be retried",
        ));
    }
    let image_removed = effects.install_files.iter().all(|file| {
        matches!(
            file.outcome,
            FileOutcome::Removed | FileOutcome::AlreadyAbsent
        )
    });
    if safe && image_removed {
        match (|| {
            record
                .take()
                .ok_or_else(|| conflict(&record_path.to_string_lossy()))?
                .remove(record_digest)
                .map_err(native_error)
        })() {
            Ok(()) => effects.integrations.push(IntegrationEffect {
                path: record_path.display().to_string(),
                entry: "owned installation record".into(),
                action: FileOutcome::Removed,
                witness: witness(
                    WitnessState::Witnessed,
                    "native owned record removal and outside absence",
                    None,
                ),
            }),
            Err(error) => effects.integrations.push(IntegrationEffect {
                path: record_path.display().to_string(),
                entry: "owned installation record".into(),
                action: FileOutcome::Unreadable,
                witness: witness(
                    WitnessState::Failed,
                    "owned installation record removal failed",
                    Some(error.to_string()),
                ),
            }),
        }
    }
    let mut directories: Vec<_> = plan.created_directories.iter().collect();
    directories.sort_by_key(|path| std::cmp::Reverse(Path::new(path).components().count()));
    for path in directories {
        let (outcome, state, detail) = if !safe || !image_removed {
            (
                DirectoryOutcome::Pending,
                WitnessState::Unknown,
                Some("installed image or another effect remains unresolved".into()),
            )
        } else {
            match se_proc::remove_empty_directory(Path::new(path)) {
                Ok(DirectoryRemoval::Removed) => {
                    (DirectoryOutcome::Removed, WitnessState::Witnessed, None)
                }
                Ok(DirectoryRemoval::AlreadyAbsent) => (
                    DirectoryOutcome::AlreadyAbsent,
                    WitnessState::Witnessed,
                    None,
                ),
                Ok(DirectoryRemoval::NotEmpty) => (
                    DirectoryOutcome::NotEmptyPreserved,
                    WitnessState::Witnessed,
                    None,
                ),
                Err(error) => (
                    if error.code == StateFileErrorCode::LocationUnsafe {
                        DirectoryOutcome::Unsafe
                    } else {
                        DirectoryOutcome::Unreadable
                    },
                    WitnessState::Failed,
                    Some(error.to_string()),
                ),
            }
        };
        effects.directories.push(DirectoryEffect {
            path: path.clone(),
            outcome,
            witness: witness(
                state,
                "native empty-directory removal and outside readback",
                detail,
            ),
        });
    }
    // Only a successful native removal of a planned ancestor can explain why
    // a directory scanned before effects is now absent. Other failures stay visible.
    for entry in recovery::merge(effects.recovery.clone(), scan(plan, &parents)) {
        let removed = effects.directories.iter().any(|directory| {
            matches!(directory.outcome, DirectoryOutcome::Removed)
                && directory.witness.state == WitnessState::Witnessed
                && Path::new(&entry.directory).starts_with(&directory.path)
        });
        if let Some(before) = effects
            .recovery
            .iter_mut()
            .find(|old| old.directory == entry.directory)
        {
            if removed {
                before.witness = witness(
                    WitnessState::Witnessed,
                    "finite pre-effect inventory followed by native empty-directory removal and absence",
                    None,
                );
            } else {
                *before = entry;
            }
        }
    }
    drop(installation_claim.take());
    Ok((owned_plan, effects))
}
