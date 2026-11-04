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
            &match se_core::ops::AgentCommand::home_argument(files.0.root())
                .and_then(se_core::ops::AgentCommand::quoted_word)
            {
                Some(home) => format!(
                    "Retry the original init command with the same --key and --home {home}; init will preserve these files in a dated quarantine and continue."
                ),
                None => se_core::ops::AgentCommand::HOME_UNAVAILABLE.into(),
            },
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
    // Installation creates machine.json before the first database. Like a
    // user-provided config or runtime.lock, it cannot prove a prior store.
    // Credentials, database sidecars and published runtime/backup records do.
    for name in [
        "credential",
        "state.db-wal",
        "state.db-shm",
        "runtime-info.json",
        "endpoint.json",
        "backups/backup-index.json",
    ] {
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
                    &remedy(root, false)?,
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

pub(super) fn corrupt_remedy(root: &Path) -> Result<String> {
    remedy(root, true)
}

fn remedy(root: &Path, damaged: bool) -> Result<String> {
    use se_core::ops::AgentCommand;
    if AgentCommand::home_argument(root).is_none() {
        return Ok(AgentCommand::HOME_UNAVAILABLE.into());
    }
    let stamp =
        se_core::ops::receipt::timestamp(crate::route::execute::now_us()?)?.replace(':', "-");
    let fresh = root.with_file_name(format!(
        "{}-fresh-{stamp}",
        root.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("stateengine")
    ));
    let preserved = root.join(format!("recovery-sidecars-{stamp}"));
    let q = |path: &Path| {
        path.to_str()
            .and_then(AgentCommand::quoted_word)
            .ok_or_else(|| SeError::invalid("recovery path", AgentCommand::HOME_UNAVAILABLE))
    };
    #[cfg(not(windows))]
    let database_guard = if damaged {
        format!(
            "test -f {db}\ntest ! -L {db}",
            db = q(&root.join("state.db"))?
        )
    } else {
        format!("test ! -e {}", q(&root.join("state.db"))?)
    };
    #[cfg(not(windows))]
    let preserve_database = if damaged {
        format!(
            "mv -- {} {}\n",
            q(&root.join("state.db"))?,
            q(&preserved.join("state.db"))?
        )
    } else {
        String::new()
    };
    #[cfg(not(windows))]
    let restore = format!(
        r#"set -eu
printf 'Directory of a CLOSED retained copy: '
IFS= read -r COPY_DIR
: "${{COPY_DIR:?A closed retained copy directory is required}}"
test -f "$COPY_DIR/state.db"
{database_guard}
mkdir -m 700 -- {preserved}
{preserve_database}if [ ! -e {wal} ]; then :; else mv -- {wal} {saved_wal}; fi
if [ ! -e {shm} ]; then :; else mv -- {shm} {saved_shm}; fi
umask 077
cp -n -- "$COPY_DIR/state.db" {db}
if [ ! -f "$COPY_DIR/state.db-wal" ]; then :; else cp -n -- "$COPY_DIR/state.db-wal" {wal}; fi
se --home {home} status"#,
        db = q(&root.join("state.db"))?,
        preserved = q(&preserved)?,
        wal = q(&root.join("state.db-wal"))?,
        saved_wal = q(&preserved.join("state.db-wal"))?,
        shm = q(&root.join("state.db-shm"))?,
        saved_shm = q(&preserved.join("state.db-shm"))?,
        home = q(root)?,
    );
    #[cfg(windows)]
    let database_guard = if damaged {
        "if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw 'The damaged state.db is absent; obtain a new recovery command' }\nif ((Get-Item -LiteralPath $target).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'The damaged state.db must not be a link' }"
    } else {
        "if (Test-Path -LiteralPath $target) { throw 'state.db already exists; nothing was restored' }"
    };
    #[cfg(windows)]
    let leaves = if damaged {
        "'state.db','state.db-wal','state.db-shm'"
    } else {
        "'state.db-wal','state.db-shm'"
    };
    #[cfg(windows)]
    let restore = format!(
        r#"$ErrorActionPreference = 'Stop'
$COPY_DIR = Read-Host 'Directory of a CLOSED retained copy'
if ([string]::IsNullOrWhiteSpace($COPY_DIR)) {{ throw 'A closed retained copy directory is required' }}
$source = Join-Path $COPY_DIR 'state.db'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {{ throw 'The copy must contain state.db' }}
$homePath = {home}
$target = Join-Path $homePath 'state.db'
{database_guard}
$preserved = {preserved}
if (Test-Path -LiteralPath $preserved) {{ throw 'The sidecar preservation directory already exists' }}
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
if ($PSVersionTable.PSEdition -eq 'Core') {{
    [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($preserved), $acl)
}} else {{
    [void][System.IO.Directory]::CreateDirectory($preserved, $acl)
}}
foreach ($leaf in @({leaves})) {{
    $old = Join-Path $homePath $leaf
    if (Test-Path -LiteralPath $old) {{ Move-Item -LiteralPath $old -Destination (Join-Path $preserved $leaf) -ErrorAction Stop }}
}}
[System.IO.File]::Copy($source, $target, $false)
$sourceWal = Join-Path $COPY_DIR 'state.db-wal'
if (Test-Path -LiteralPath $sourceWal -PathType Leaf) {{ [System.IO.File]::Copy($sourceWal, (Join-Path $homePath 'state.db-wal'), $false) }}
se --home {home} status"#,
        home = q(root)?,
        preserved = q(&preserved)?,
    );
    Ok(format!(
        "Stop all writers first. Restore exactly state.db and its matching state.db-wal from a CLOSED retained copy; {}old WAL/SHM are preserved and SHM is never restored. Restoring replaces active history with the selected copy, so changes newer than that copy are no longer active. No automatic backup selection or salvage is performed.\nBEGIN SE RESTORE COMMANDS\n{restore}\nEND SE RESTORE COMMANDS\nNo backup? Keep this home intact and create fresh identities and empty history in a separate home:\nBEGIN SE FRESH COMMAND\nse --home {} init --repo .\nEND SE FRESH COMMAND\nThe recorded human identity cannot be reconstructed from the machine credential alone.",
        if damaged {
            "the damaged database and "
        } else {
            ""
        },
        q(&fresh)?
    ))
}
