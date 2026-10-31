//! Associate backups with exact admitted targets before native restoration.
//! Neither a filename prefix nor a newly computed digest is sufficient authority.
use super::*;

pub(super) fn resolved(entry: &RecoveryDirectoryEffect) -> bool {
    entry.witness.state == WitnessState::Witnessed
        && match &entry.temporary_files {
            Read::Absent { .. } => true,
            Read::Present { value } => value.iter().all(|file| {
                matches!(
                    file.outcome,
                    FileOutcome::Removed | FileOutcome::AlreadyAbsent
                ) && file.witness.state == WitnessState::Witnessed
            }),
            _ => false,
        }
        && match &entry.copies {
            Read::Absent { .. } => true,
            Read::Present { value } => value.iter().all(|copy| {
                copy.restored_to.is_some() && copy.witness.state == WitnessState::Witnessed
            }),
            _ => false,
        }
}

struct Candidate {
    copy: String,
    target: String,
    digest: [u8; 32],
}
pub(super) fn recover(plan: &UninstallPlan, inventories: &mut [RecoveryDirectoryEffect]) {
    let mut candidates = Vec::new();
    let mut failed = std::collections::BTreeMap::new();
    for directory in inventories.iter() {
        let Read::Present { value: copies } = &directory.copies else {
            continue;
        };
        for copy in copies {
            match associate(plan, &copy.path) {
                Ok(Some((target, digest))) => candidates.push(Candidate {
                    copy: copy.path.clone(),
                    target,
                    digest,
                }),
                Ok(None) => (),
                Err(error) => {
                    failed.insert(copy.path.clone(), error.to_string());
                }
            }
        }
    }
    for directory in inventories {
        let Read::Present { value: copies } = &mut directory.copies else {
            continue;
        };
        for copy in copies {
            let candidate = candidates
                .iter()
                .find(|candidate| candidate.copy == copy.path);
            let Some(candidate) = candidate else {
                copy.witness = match failed.get(&copy.path) {
                    Some(reason) => witness(
                        WitnessState::Failed,
                        "recovery proof could not be read; existing bytes preserved",
                        Some(reason.clone()),
                    ),
                    None => witness(
                        WitnessState::Unknown,
                        "recovery association unproved; existing bytes preserved",
                        None,
                    ),
                };
                continue;
            };
            if candidates
                .iter()
                .filter(|other| other.target == candidate.target)
                .count()
                != 1
            {
                copy.witness = witness(
                    WitnessState::Unknown,
                    "multiple recovery copies match this target; every copy preserved",
                    None,
                );
                continue;
            }
            let result = (|| {
                let pin = OwnedFile::open(Path::new(&candidate.copy))
                    .map_err(native_error)?
                    .ok_or_else(|| conflict(&candidate.copy))?;
                pin.restore_to(Path::new(&candidate.target), candidate.digest)
                    .map_err(native_error)
            })();
            match result {
                Ok(()) => {
                    copy.restored_to = Some(candidate.target.clone());
                    copy.witness = witness(
                        WitnessState::Witnessed,
                        "unique planned digest/block association, current-user native custody, same-directory no-replace identity/security-preserving restoration and outside readback",
                        None,
                    );
                }
                Err(error) => {
                    copy.witness = witness(
                        WitnessState::Failed,
                        "recovery restoration refused; no target replacement licensed",
                        Some(error.to_string()),
                    )
                }
            }
        }
    }
}
fn associate(plan: &UninstallPlan, source: &str) -> Result<Option<(String, [u8; 32])>> {
    let path = Path::new(source);
    let Some(mut pin) = OwnedFile::open(path).map_err(native_error)? else {
        return Err(conflict(source));
    };
    let digest = pin.sha256().map_err(native_error)?;
    let mut targets = Vec::new();
    for file in &plan.files {
        if Path::new(&file.path).parent() == path.parent() && digest_bytes(&file.sha256)? == digest
        {
            targets.push(file.path.clone());
        }
    }
    #[cfg(not(windows))]
    for edit in &plan.path_edits {
        if Path::new(&edit.target).parent() != path.parent() {
            continue;
        }
        let bytes = pin.read(1024 * 1024).map_err(native_error)?;
        if <[u8; 32]>::from(Hasher::digest(&bytes)) != digest {
            return Err(conflict(source));
        }
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let edit = PathEdit {
            target: edit.target.clone(),
            before_sha256: edit
                .before_sha256
                .as_ref()
                .map(|value| Sha256::parse_hex(value))
                .transpose()?,
            block: edit.block.clone(),
            before_bytes: edit.before_bytes,
        };
        // Only an exact inserted block plus the manifest's recorded prior bytes
        // proves this profile association; later user edits make proof unavailable.
        let Ok(change) = remove_profile_block(&edit.target, Some(text), &edit) else {
            continue;
        };
        let original = match change {
            EntryChange::Replace(value) => Some(value),
            EntryChange::RemoveCreatedTarget => Some(String::new()),
            EntryChange::AlreadyAbsent => None,
        };
        if original
            .as_ref()
            .is_some_and(|value| matches_before(value, edit.before_sha256.as_ref()))
        {
            targets.push(edit.target.clone());
        }
    }
    targets.sort();
    targets.dedup();
    if targets.len() != 1 {
        return Ok(None);
    }
    let target = targets.remove(0);
    drop(pin);
    // The final publication is atomic no-replace too. This observation merely
    // excludes an already-present newer file without touching either version.
    if OwnedFile::open(Path::new(&target))
        .map_err(native_error)?
        .is_some()
    {
        return Ok(None);
    }
    Ok(Some((target, digest)))
}

/// Keep witnessed restoration results alongside the fresh inventory. A newly
/// observed source at the same pathname supersedes the old restoration witness.
pub(super) fn merge(
    before: Vec<RecoveryDirectoryEffect>,
    mut after: Vec<RecoveryDirectoryEffect>,
) -> Vec<RecoveryDirectoryEffect> {
    for directory in &mut after {
        if let Some(old) = before
            .iter()
            .find(|old| old.directory == directory.directory)
            && let Read::Present { value: previous } = &old.temporary_files
            && let Read::Present { value: current } = &mut directory.temporary_files
        {
            for file in previous.iter().filter(|file| {
                matches!(
                    file.outcome,
                    FileOutcome::Removed | FileOutcome::AlreadyAbsent
                ) && file.witness.state == WitnessState::Witnessed
            }) {
                if !current.iter().any(|fresh| fresh.path == file.path) {
                    current.push(file.clone());
                }
            }
        }
        let Read::Present { value: copies } = &mut directory.copies else {
            continue;
        };
        if let Some(old) = before
            .iter()
            .find(|old| old.directory == directory.directory)
            && let Read::Present { value: previous } = &old.copies
        {
            for copy in previous.iter().filter(|copy| {
                copy.restored_to.is_some() && copy.witness.state == WitnessState::Witnessed
            }) {
                if !copies.iter().any(|current| current.path == copy.path) {
                    copies.push(copy.clone());
                }
            }
        }
    }
    after
}
