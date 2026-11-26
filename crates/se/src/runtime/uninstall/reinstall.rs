use super::*;

/// A current archive can recover an older installed image without asking that
/// image to open newer data. Both native claims survive through reinstallation.
pub(crate) fn remove_for_reinstall(
    cx: &Bootstrap,
    claim: &se_proc::NativeInstallationClaim,
    image: &Path,
    preserve_paths: bool,
    diagnostic: &mut dyn FnMut(&str) -> io::Result<()>,
) -> Result<(std::fs::File, Option<String>)> {
    let key = se_types::IdempotencyKey::new(uuid::Uuid::new_v4().to_string())?;
    let (plan, effects, lease) = execute_inner(
        cx,
        &key,
        diagnostic,
        Some((claim, image, preserve_paths)),
        false,
    )?;
    let report = se_core::ops::installation::finish_uninstall(&plan, key, effects)?;
    if !report.complete {
        return Err(SeError::new(Detail::StateConflict(details::StateConflict {
            subject: "installation replacement".into(),
            reason: format!("Owned installation removal is incomplete: {report:?}"),
            next_step: "Preserve the reported paths, resolve the named refusal, and retry this current archive's installer. Retained data was not removed".into(),
        })));
    }
    let lease = lease.ok_or_else(|| {
        SeError::invalid(
            "installation replacement",
            "the home writer lease held across replacement",
        )
    })?;
    // The replacement child must re-read the owned blocks it was asked to
    // preserve; carrying them by name and bytes keeps its journal honest.
    let inherited = if preserve_paths && !plan.path_edits().is_empty() {
        Some(serde_json::to_string(plan.path_edits()).map_err(|e| {
            se_core::scope::unreadable("inherited PATH custody record", &e.to_string())
        })?)
    } else {
        None
    };
    Ok((lease, inherited))
}

/// Persist `--no-modify-path` replacement custody in the state home before
/// removing the old record, so a kill before the child journal survives retry.
pub(super) fn persist_custody(home: &Path, plan: &ValidatedUninstallPlan) -> Result<()> {
    use std::io::Write;
    let mut inherited_files = Vec::new();
    for file in plan.files() {
        if se_core::ops::installation::is_fish_path_file(&file.path)
            && OwnedFile::open(Path::new(&file.path))
                .map_err(native_error)?
                .is_some()
        {
            inherited_files.push(file.clone());
        }
    }
    let mut inherited_directories = Vec::new();
    for dir in plan.created_directories() {
        let dir_path = Path::new(dir);
        if inherited_files
            .iter()
            .any(|file| Path::new(&file.path).starts_with(dir_path))
        {
            inherited_directories.push(dir.clone());
        }
    }
    let custody = crate::runtime::ReplaceCustody {
        schema: "stateengine-install-replace/v1".into(),
        owner: plan.owner().to_owned(),
        no_modify_path: true,
        inherited_path_edits: plan.path_edits().to_vec(),
        inherited_files,
        inherited_directories,
    };
    let bytes = serde_json::to_vec(&custody)
        .map_err(|e| se_core::scope::unreadable("replacement custody record", &e.to_string()))?;
    let files = se_proc::NativeStateFiles::open(home).map_err(native_error)?;
    let path = home.join("standalone-install.replace.json");
    if let Some(mut existing) = OwnedFile::open(&path).map_err(native_error)? {
        let hash = existing.sha256().map_err(native_error)?;
        existing.replace(hash, &bytes).map_err(native_error)?;
    } else {
        let mut staged = files.create_staging(home).map_err(native_error)?;
        staged
            .file
            .write_all(&bytes)
            .map_err(|e| unreadable(&staged.path, e))?;
        staged
            .file
            .sync_all()
            .map_err(|e| unreadable(&staged.path, e))?;
        drop(staged.file);
        files
            .publish_no_replace(&staged.path, &path)
            .map_err(native_error)?;
    }
    Ok(())
}

// No caller-provided destination: the installer selects this account's native
// program path. Changed or foreign payloads never grant replacement authority.
pub(super) fn image(
    plan: &ValidatedUninstallPlan,
    running: &[String],
    expected: &Path,
) -> Result<String> {
    if !running.is_empty() {
        return Err(invalid(
            "a separate current archive for installation replacement",
        ));
    }
    let expected = expected
        .to_str()
        .ok_or_else(|| invalid("a UTF-8 installed image"))?;
    if plan
        .files()
        .iter()
        .filter(|file| file.path == expected)
        .count()
        != 1
    {
        return Err(invalid(
            "one recorded image at this account's installation destination",
        ));
    }
    for file in plan.files() {
        // Ordinary removal may have finished these exact recorded files before
        // another effect refused. Absence is safe to retry; unreadable or changed
        // bytes are not absence and still refuse before further effects.
        let Some(mut owned) = OwnedFile::open(Path::new(&file.path)).map_err(native_error)? else {
            continue;
        };
        if owned.sha256().map_err(native_error)? != digest_bytes(&file.sha256)? {
            return Err(conflict(&file.path));
        }
    }
    Ok(expected.to_owned())
}
