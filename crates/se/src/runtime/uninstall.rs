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
#[path = "uninstall/shutdown.rs"]
mod shutdown;
use path::reconcile_paths;
use recovery::recover;

pub(super) fn execute(
    cx: &Bootstrap,
    key: &se_types::IdempotencyKey,
    confirmed: bool,
    diagnostic: &mut dyn FnMut(&str) -> io::Result<()>,
) -> Result<(ValidatedUninstallPlan, UninstallEffects)> {
    let (plan, effects, _lease) = execute_inner(cx, key, diagnostic, None, confirmed)?;
    Ok((plan, effects))
}

#[path = "uninstall/reinstall.rs"]
mod reinstall;
pub(crate) use reinstall::remove_for_reinstall;

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
#[cfg_attr(
    windows,
    expect(
        clippy::cognitive_complexity,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )
)]
fn execute_inner(
    cx: &Bootstrap,
    key: &se_types::IdempotencyKey,
    diagnostic: &mut dyn FnMut(&str) -> io::Result<()>,
    reinstall: Option<(&se_proc::NativeInstallationClaim, &Path)>,
    confirmed: bool,
) -> Result<(ValidatedUninstallPlan, UninstallEffects, std::fs::File)> {
    // Store absence and a complete inventory with no unresolved custody are
    // distinct observations. Retained exit history is never live custody;
    // endpoint absence never supplies an empty-process proof.
    let observe = |require_closed: bool| -> Result<_> {
        Ok(match route::setup::inspect(&cx.home, clock())? {
            route::setup::Setup::Absent(_) => (
                route::owner::observe(&[])?,
                "runtime store absence measured",
            ),
            route::setup::Setup::Present(reader) => {
                let files = route::files::Files::open(&cx.home)
                    .map_err(|e| se_core::store_error::store_error(&e))?;
                let inventory = route::owner::inventory(&reader, &files)?;
                if require_closed && let Some(first) = inventory.processes.first() {
                    return Err(SeError::new(Detail::StateConflict(details::StateConflict {
                    subject: "uninstall unresolved process custody".into(),
                    reason: format!("The complete home-wide inventory contains {} unresolved custody records; process {} in project {} {}. Retained completed exit history does not block uninstall.",
                        inventory.processes.len(), first.identity.record, first.project,
                        if first.state == se_store::ProcessState::Exited {
                            "has a durable exit but its session or capture cleanup is unfinished"
                        } else {
                            "has not durably completed or released its native custody"
                        }),
                    next_step: "Run se down with this same --home to finish ordinary stop and session/capture cleanup, then retry se uninstall; if down reports unproved custody, resolve that named process through se stop before retrying. No installation effects were attempted".into(),
                })));
                }
                (
                    route::owner::from_inventory(&inventory)?,
                    if inventory.has_process_records {
                        "initialized store; complete protected home-wide inventory has no unresolved custody; completed process history is retained"
                    } else {
                        "initialized store; complete protected home-wide process inventory is empty"
                    },
                )
            }
        })
    };
    // Standalone installation accepts the native owner without a console. Keep
    // ancestry/session/provider-marker checks. Explicit unattended confirmation
    // waives only the console requirement, never any native owner check.
    let (owner, _) = observe(false)?;
    owner.authorize(
        "installation.uninstall",
        owner.os_owner(),
        cx.session.is_some(),
        reinstall.is_none() && !confirmed,
    )?;
    let installation_claim = if reinstall.is_none() {
        Some(se_proc::NativeInstallationClaim::acquire().map_err(native_error)?)
    } else {
        None
    };
    let claim = reinstall
        .map(|(claim, _)| claim)
        .or(installation_claim.as_ref())
        .ok_or_else(|| invalid("native installation claim missing"))?;
    // Only uninstall takes the account claim, protecting install/PATH effects
    // across homes. Share setup's persistent home lock through every effect,
    // including when no store exists yet, then re-observe under exclusion.
    let files =
        route::files::Files::open(&cx.home).map_err(|e| se_core::store_error::store_error(&e))?;
    let record_path = cx.home.join("standalone-install.json");
    match std::fs::symlink_metadata(&record_path) {
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(invalid("the owned installation record is absent"));
        }
        Err(error) => return Err(unreadable(&record_path, error)),
    }
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
        reinstall.is_none() && !confirmed,
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
    let canonical =
        se_proc::canonicalize_path(&current).map_err(|error| unreadable(&current, error))?;
    let mut matches = Vec::new();
    for file in plan.files() {
        match se_proc::canonicalize_path(&file.path) {
            Ok(path) if path == canonical => matches.push(file.path.clone()),
            Ok(_) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(unreadable(Path::new(&file.path), error)),
        }
    }
    if let Some((_, expected)) = reinstall {
        matches.push(reinstall::image(plan, &matches, expected)?);
    }
    // A quarantined/missing installed image cannot run its own uninstaller.
    // An owner may use a working archive's CLI, but only after native proof
    // that the record's unique Windows image is actually absent, not unreadable.
    #[cfg(windows)]
    let missing_image = if matches.is_empty() {
        let images: Vec<_> = plan
            .files()
            .iter()
            .filter(|file| {
                Path::new(&file.path)
                    .file_name()
                    .is_some_and(|name| name.eq_ignore_ascii_case("se.exe"))
            })
            .collect();
        if images.len() != 1
            || OwnedFile::open(Path::new(&images[0].path))
                .map_err(native_error)?
                .is_some()
        {
            return Err(invalid(
                "the installed image is present or ambiguous; run its se uninstall, or resolve the named security-software refusal before recovery",
            ));
        }
        matches.push(images[0].path.clone());
        true
    } else {
        false
    };
    if matches.len() != 1 {
        return Err(invalid(
            "the admitted plan must uniquely own the running image",
        ));
    }
    let image = matches.remove(0);
    let installed = plan
        .files()
        .iter()
        .find(|file| file.path == image)
        .ok_or_else(|| invalid("running image disappeared from the plan"))?;

    // The account claim and exact installation record stay held across ordinary
    // down. Do not take the home writer lease until down has released it.
    let stops = if reinstall.is_some() {
        Vec::new()
    } else {
        shutdown::execute(cx, key, diagnostic)?
    };
    let runtime_lease = route::files::setup_lock(&files)
        .map_err(|e| se_core::store_error::store_error(&e))?
        .ok_or_else(|| SeError::new(Detail::StateConflict(details::StateConflict {
            subject: "uninstall runtime custody".into(),
            reason: "setup, another writer or a live runtime holds this home's exclusive lease".into(),
            next_step: "Run se down with this same --home, or wait for the named writer to finish, then retry the current installer or se uninstall; no installation effects were attempted".into(),
        })))?;
    let (owner, store_observation) = observe(true)?;
    owner.authorize(
        "installation.uninstall",
        plan.owner(),
        cx.session.is_some(),
        reinstall.is_none() && !confirmed,
    )?;

    #[cfg(windows)]
    super::helper_cleanup::retry(
        &se_proc::NativeStateFiles::open(&cx.home).map_err(native_error)?,
        claim,
    )?;
    let mut effects = UninstallEffects {
        install_files: Vec::new(),
        directories: Vec::new(),
        integrations: Vec::new(),
        stops,
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
    let completion = if reinstall.is_some() {
        None
    } else {
        super::uninstall_completion::request()?
    };
    let parents = plan.recovery_directories();
    effects.recovery = scan(plan, parents);
    // Diagnostics flush before recovery restoration, PATH edits or file removal.
    let mut diagnosis = format!(
        "Uninstall: {store_observation}. Runtime shutdown verified; events and retained credentials are preserved. User repositories, retained history/configuration and provider login are preserved.\n",
    );
    for file in plan.files() {
        diagnosis.push_str(&format!(
            "Remove exact owned file {} at SHA-256 {}\n",
            file.path, file.sha256
        ));
    }
    for directory in plan.created_directories() {
        diagnosis.push_str(&format!("Remove only if empty: {directory}\n"));
    }
    for edit in plan.path_edits() {
        diagnosis.push_str(&format!(
            "Remove only the recorded StateEngine entry from {}\n",
            edit.target
        ));
    }
    diagnosis.push_str("Recovery: restore only a uniquely proved owned backup to an absent planned target in its original directory; preserve every unresolved copy.\n");
    diagnostic(&diagnosis)
        .map_err(|error| se_core::scope::unreadable("uninstall diagnostic", &error.to_string()))?;
    // Preparation must finish before recovery, PATH changes or removal. A policy
    // refusal here preserves every installed payload and the user's PATH.
    #[cfg(windows)]
    let carrier = if missing_image || reinstall.is_some() {
        None
    } else {
        Some(
            se_proc::NativeUninstallCarrier::prepare(
                &se_proc::NativeStateFiles::open(&cx.home).map_err(native_error)?,
                claim,
                record
                    .as_ref()
                    .ok_or_else(|| invalid("installation record custody missing"))?,
                &record_path,
                record_digest,
                plan.created_directories(),
            )
            .map_err(|error| {
                se_core::scope::unreadable(
                    "Windows uninstall carrier preparation",
                    &error.to_string(),
                )
            })?,
        )
    };
    recover(plan, &mut effects.recovery);
    cleanup_temporary(plan, claim, &mut effects.recovery);
    let clean = effects.recovery.iter().all(recovery::resolved);
    if !clean {
        pending_assets(
            plan,
            &mut effects,
            "recovery inventory is unreadable or contains unresolved copies",
        );
        return Ok((owned_plan, effects, runtime_lease));
    }
    let mut safe = true;
    reconcile_paths(plan, &mut effects);
    safe &= effects.path_complete;
    for file in plan.files().iter().filter(|file| file.path != image) {
        let result = remove_file(file);
        safe &= matches!(
            result.outcome,
            FileOutcome::Removed | FileOutcome::AlreadyAbsent
        );
        effects.install_files.push(result);
    }
    effects.recovery = recovery::merge(effects.recovery, scan(plan, parents));
    safe &= effects.recovery.iter().all(recovery::resolved);
    // Never strand a partially removed installation without its retry entry point.
    if safe {
        // Preserve the already achieved native facts and original request key
        // across parent exit. Missing post-exit outcomes remain pending here.
        let achieved =
            se_core::ops::installation::finish_uninstall(plan, key.clone(), effects.clone())?;
        #[cfg(windows)]
        let result = if reinstall.is_some() {
            Ok(remove_file(installed))
        } else {
            remove_image(
                cx,
                plan,
                installed,
                record_digest,
                completion,
                achieved,
                carrier,
            )
        };
        #[cfg(not(windows))]
        let result = remove_image(cx, plan, installed, record_digest, completion, achieved);
        let result = result.unwrap_or_else(|error| {
            file_effect(
                &installed.path,
                FileOutcome::Pending,
                WitnessState::Failed,
                &error.to_string(),
            )
        });
        effects.install_files.push(result);
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
    } else {
        effects.integrations.push(IntegrationEffect {
            path: record_path.display().to_string(),
            entry: "owned installation record".into(),
            action: FileOutcome::Pending,
            witness: witness(
                WitnessState::Unknown,
                "record removal awaits witnessed image and installation effects",
                None,
            ),
        });
    }
    let mut directories: Vec<_> = plan.created_directories().iter().collect();
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
    for entry in recovery::merge(effects.recovery.clone(), scan(plan, parents)) {
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
    Ok((owned_plan, effects, runtime_lease))
}
