//! Missing database recovery preserves identities and unclaimed staging bytes.
use super::*;
use se_store::StateFiles;
use se_types::{Detail, SeError, details};

fn conflict(subject: &str, reason: String, next_step: &str) -> SeError {
    SeError::new(Detail::StateConflict(details::StateConflict {
        subject: subject.into(),
        reason,
        next_step: next_step.into(),
    }))
}

/// A name is evidence of an unclaimed file, never authority to delete it.
pub(in crate::route) fn refuse_staging(files: &Files) -> Result<()> {
    let root = files.0.root();
    files
        .readback(&root.join("state.db"))
        .map_err(|e| store_error(&e))?;
    let entries = std::fs::read_dir(root).map_err(|e| {
        se_core::scope::unreadable("initialization staging inventory", &e.to_string())
    })?;
    let mut names = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= 4096 {
            return Err(se_core::scope::unreadable(
                "initialization staging inventory",
                "more than 4096 directory entries; the unclaimed staging inventory is unknown",
            ));
        }
        let entry = entry.map_err(|e| {
            se_core::scope::unreadable("initialization staging entry", &e.to_string())
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(suffix) = name.strip_prefix(".se-stage-") else {
            continue;
        };
        let Some(id) = suffix.get(..32) else { continue };
        if !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || !["", "-journal", "-wal", "-shm"].contains(&&suffix[32..])
        {
            continue;
        }
        // Refuse even an unsafe linked/special file under a reserved name;
        // native readback supplies its exact refusal without following it.
        match files.readback(&entry.path()).map_err(|e| store_error(&e))? {
            Read::Present { .. } => names.push(entry.path()),
            Read::Absent { .. } => continue,
            Read::Unreadable { source, reason, .. } => {
                return Err(se_core::scope::unreadable(&source, &reason));
            }
            Read::Unknown { what } => {
                return Err(se_core::scope::unreadable("initialization staging", &what));
            }
        }
    }
    files
        .readback(&root.join("state.db"))
        .map_err(|e| store_error(&e))?;
    names.sort();
    if !names.is_empty() {
        let shown = names
            .iter()
            .take(8)
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(conflict(
            "unclaimed initialization staging",
            format!(
                "{} staging files remain, including {shown}; no durable claim proves they can be reclaimed",
                names.len()
            ),
            "Preserve the named files. After confirming initialization and the runtime have stopped, move those exact files intact outside this home for inspection, then retry init with the original --key. No staging bytes were deleted.",
        ));
    }
    Ok(())
}

pub(super) fn missing_database(files: &Files) -> Result<()> {
    refuse_staging(files)?;
    let root = files.0.root();
    // runtime.lock and a user-provided config alone do not prove prior setup.
    for name in ["machine.json", "credential", "state.db-wal", "state.db-shm"] {
        match files
            .readback(&root.join(name))
            .map_err(|e| store_error(&e))?
        {
            Read::Present { .. } => {
                return Err(conflict(
                    "recorded state database",
                    format!(
                        "Recorded state is missing: {} is absent while {} survives; initialization may have been interrupted or the database removed",
                        root.join("state.db").display(),
                        root.join(name).display()
                    ),
                    "Preserve this home and stop any runtime. Restore the original database and matching WAL from a retained copy or validated backup. For a deliberate fresh setup, select a different empty --home; do not recreate this database with init.",
                ));
            }
            Read::Absent { .. } => (),
            Read::Unreadable { source, reason, .. } => {
                return Err(se_core::scope::unreadable(&source, &reason));
            }
            Read::Unknown { what } => {
                return Err(se_core::scope::unreadable("recorded state", &what));
            }
        }
    }
    Ok(())
}
