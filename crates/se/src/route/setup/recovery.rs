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
fn staging(files: &Files) -> Result<Vec<std::path::PathBuf>> {
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
    Ok(names)
}

pub(in crate::route) fn quarantine(files: &Files) -> Result<Vec<String>> {
    let names = staging(files)?;
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let stamp =
        se_core::ops::receipt::timestamp(crate::route::execute::now_us()?)?.replace(':', "-");
    let directory = files.0.root().join(format!("init-quarantine-{stamp}"));
    files
        .0
        .prepare_new_directory(&directory)
        .map_err(|e| se_core::scope::unreadable("initialization quarantine", &e.to_string()))?;
    for source in &names {
        let leaf = source
            .file_name()
            .ok_or_else(|| SeError::invalid("staging", "an exact native filename"))?;
        let target = directory.join(leaf);
        files
            .0
            .publish_no_replace(source, &target)
            .map_err(|e| se_core::scope::unreadable("initialization quarantine", &e.to_string()))?;
    }
    let note = format!(
        "Preserved {} interrupted initialization files in {}; no bytes deleted",
        names.len(),
        directory.display()
    );
    eprintln!("{note}");
    Ok(vec![note])
}

pub(super) fn missing_database(files: &Files, init: bool, recovered: bool) -> Result<()> {
    let stages = staging(files)?;
    if !stages.is_empty() && !init {
        return Err(conflict(
            "interrupted initialization",
            format!(
                "Staging files remain: {}",
                stages
                    .iter()
                    .take(8)
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            &format!(
                "Retry the original init command with the same --key and --home {}; init will preserve these files in a dated quarantine and continue.",
                super::quote(&files.0.root().display().to_string())
            ),
        ));
    }
    // A completed default init writes config after DB publication. Historical
    // runtime/backup records likewise prevent staging from disguising DB loss.
    if init && (recovered || !stages.is_empty()) {
        let mut completed = false;
        for name in [
            "config.toml",
            "runtime-info.json",
            "endpoint.json",
            "backups/backup-index.json",
        ] {
            match files
                .readback(&files.0.root().join(name))
                .map_err(|e| store_error(&e))?
            {
                Read::Absent { .. } => (),
                Read::Present { .. } => completed = true,
                Read::Unreadable { source, reason, .. } => {
                    return Err(se_core::scope::unreadable(&source, &reason));
                }
                Read::Unknown { what } => {
                    return Err(se_core::scope::unreadable("prior initialization", &what));
                }
            }
        }
        if !completed {
            return Ok(());
        }
    }
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
                    &remedy(root)?,
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

fn remedy(root: &Path) -> Result<String> {
    let stamp =
        se_core::ops::receipt::timestamp(crate::route::execute::now_us()?)?.replace(':', "-");
    let fresh = root.with_file_name(format!(
        "{}-fresh-{stamp}",
        root.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("stateengine")
    ));
    let preserved = root.join(format!("recovery-sidecars-{stamp}"));
    let q = |p: &Path| super::quote(&p.display().to_string());
    #[cfg(not(windows))]
    let restore = format!(
        "Stop all writers first. Set COPY_DIR to a CLOSED retained copy directory, then run these commands to restore exactly state.db and its matching state.db-wal if present; old WAL/SHM are preserved and SHM is never restored:\nset -eu\n: \"${{COPY_DIR:?Set COPY_DIR to a closed retained copy}}\"\ntest -f \"$COPY_DIR/state.db\"\ntest ! -e {}\nmkdir -m 700 -- {}\nif [ ! -e {} ]; then :; else mv -- {} {}; fi\nif [ ! -e {} ]; then :; else mv -- {} {}; fi\numask 077\ncp -- \"$COPY_DIR/state.db\" {}\nif [ ! -f \"$COPY_DIR/state.db-wal\" ]; then :; else cp -- \"$COPY_DIR/state.db-wal\" {}; fi\nse --home {} status",
        q(&root.join("state.db")),
        q(&preserved),
        q(&root.join("state.db-wal")),
        q(&root.join("state.db-wal")),
        q(&preserved.join("state.db-wal")),
        q(&root.join("state.db-shm")),
        q(&root.join("state.db-shm")),
        q(&preserved.join("state.db-shm")),
        q(&root.join("state.db")),
        q(&root.join("state.db-wal")),
        q(root)
    );
    #[cfg(windows)]
    let restore = format!(
        "Stop all writers first. Set $COPY_DIR to a CLOSED retained copy directory. Restore exactly state.db and its matching state.db-wal if present; preserve old WAL/SHM and never restore SHM:\nNew-Item -ItemType Directory -Path {} -ErrorAction Stop\nforeach ($leaf in @('state.db-wal','state.db-shm')) {{ $old=Join-Path {} $leaf; if (Test-Path -LiteralPath $old) {{ Move-Item -LiteralPath $old -Destination (Join-Path {} $leaf) -ErrorAction Stop }} }}\nCopy-Item -LiteralPath (Join-Path $COPY_DIR 'state.db') -Destination {} -ErrorAction Stop\nif (Test-Path -LiteralPath (Join-Path $COPY_DIR 'state.db-wal')) {{ Copy-Item -LiteralPath (Join-Path $COPY_DIR 'state.db-wal') -Destination {} -ErrorAction Stop }}\nse --home {} status",
        q(&preserved),
        q(root),
        q(&preserved),
        q(&root.join("state.db")),
        q(&root.join("state.db-wal")),
        q(root)
    );
    Ok(format!(
        "{restore}\nNo backup? Keep this home intact and create fresh identities and empty history in a separate home:\nse --home {} init --repo .\nThe recorded human identity cannot be reconstructed from the machine credential alone.",
        q(&fresh)
    ))
}
