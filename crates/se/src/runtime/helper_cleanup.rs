//! One bounded, protected cleanup debt survives parent/helper crashes. Native
//! custody, rather than the journal pathname, determines what may be removed.
use super::*;
use se_proc::{
    HelperCleanupOutcome, NativeInstallationClaim, NativeStateFiles, OwnedFile,
    UninstallHelperCleanup,
};
use se_store::StateFiles;
const NAME: &str = "uninstall-helper-cleanup.json";
const MAXIMUM: usize = 256 * 1024;

fn native(error: se_proc::StateFileError) -> SeError {
    se_core::scope::unreadable("uninstall helper cleanup journal", &error.to_string())
        .with_cause(error)
}
struct CleanupRecord {
    file: OwnedFile,
    bytes: Vec<u8>,
    digest: [u8; 32],
}
fn read(files: &NativeStateFiles) -> Result<Option<CleanupRecord>> {
    let path = files.root().join(NAME);
    let protected = files.readback(&path).map_err(native)?;
    let file = OwnedFile::open(&path).map_err(native)?;
    match (protected, file) {
        (None, None) => Ok(None),
        (Some(_), Some(mut file)) => {
            let bytes = file.read(MAXIMUM).map_err(native)?;
            let digest = file.sha256().map_err(native)?;
            if digest != <[u8; 32]>::from(Hasher::digest(&bytes)) {
                return Err(conflict(&path.to_string_lossy()));
            }
            Ok(Some(CleanupRecord {
                file,
                bytes,
                digest,
            }))
        }
        _ => Err(conflict(&path.to_string_lossy())),
    }
}
pub(crate) fn publish(
    home: &Path,
    _claim: &NativeInstallationClaim,
    debt: &UninstallHelperCleanup,
) -> Result<()> {
    let files = NativeStateFiles::open(home).map_err(native)?;
    let bytes = debt
        .encode()
        .map_err(|e| invalid("cannot encode native helper cleanup custody").with_cause(e))?;
    if let Some(previous) = read(&files)? {
        if previous.bytes != bytes {
            return Err(conflict(&home.join(NAME).to_string_lossy()));
        }
    } else {
        crate::route::files::Files(files)
            .replace_owned(&home.join(NAME), None, &bytes)
            .map_err(|e| se_core::store_error::store_error(&e))?;
    }
    verify(home, debt)
}
pub(crate) fn verify(home: &Path, debt: &UninstallHelperCleanup) -> Result<()> {
    let files = NativeStateFiles::open(home).map_err(native)?;
    let expected = debt
        .encode()
        .map_err(|e| invalid("cannot encode native helper cleanup custody").with_cause(e))?;
    if read(&files)?.is_none_or(|record| record.bytes != expected) {
        return Err(conflict(&home.join(NAME).to_string_lossy()));
    }
    Ok(())
}
/// The permanent account claim serializes journal retirement with every new
/// installation. A live helper, replacement or unreadable fact preserves debt.
pub(crate) fn retry(files: &NativeStateFiles, _claim: &NativeInstallationClaim) -> Result<()> {
    let Some(record) = read(files)? else {
        return Ok(());
    };
    let debt = UninstallHelperCleanup::decode(&record.bytes)
        .map_err(|e| invalid("the protected helper cleanup record is unreadable").with_cause(e))?;
    let outcome = debt.cleanup(files).map_err(|e| {
        se_core::scope::unreadable(
            "pending uninstall helper",
            &format!(
                "{}: {e}; preserve this path and retry install or uninstall",
                paths(&debt)
            ),
        )
        .with_cause(e)
    })?;
    if outcome == HelperCleanupOutcome::StillRunning {
        return Err(se_core::scope::unreadable(
            "pending uninstall helper",
            &format!(
                "{} is still running; retry install or uninstall after it exits",
                paths(&debt)
            ),
        ));
    }
    record.file.remove(record.digest).map_err(native)?;
    if files
        .readback(&files.root().join(NAME))
        .map_err(native)?
        .is_some()
    {
        return Err(conflict(&files.root().join(NAME).to_string_lossy()));
    }
    eprintln!(
        "Uninstall helper cleanup {}: {:?} (native outside readback)",
        paths(&debt),
        outcome
    );
    Ok(())
}

fn paths(debt: &UninstallHelperCleanup) -> String {
    match debt.directory_path() {
        Some(directory) => format!(
            "{} (protected directory {}; elevated cleanup may be required)",
            debt.path().display(),
            directory.display()
        ),
        None => debt.path().display().to_string(),
    }
}
