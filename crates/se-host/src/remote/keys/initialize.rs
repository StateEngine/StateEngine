//! One native no-replace initializer shared by purpose-separated key files.
use se_core::scope;
use se_store::StateFiles;
use se_types::{Read, Result};
use sha2::{Digest, Sha256};
use std::{io::Write, path::Path};
pub(super) fn file(
    owner: &super::super::auth::VerifiedLocalOwner,
    files: &dyn StateFiles,
    path: &Path,
) -> Result<()> {
    if owner.deadline <= std::time::Instant::now() {
        return Err(scope::unreadable(
            "remote key initialization",
            "native Owner admission expired",
        ));
    }
    match files
        .readback(path)
        .map_err(|e| se_core::store_error::store_error(&e))?
    {
        Read::Present { .. } => return Ok(()),
        Read::Absent { .. } => (),
        other => {
            return scope::require_present(
                other,
                "machine credential",
                "Restore native key custody; do not replace an unreadable key.",
            )
            .and_then(|_| {
                Err(scope::unreadable(
                    "machine credential",
                    "unreadable key state",
                ))
            });
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| scope::unreadable("machine credential", "key parent absent"))?;
    files
        .prepare_directory(parent)
        .map_err(|e| se_core::store_error::store_error(&e))?;
    let secret = se_proc::random_secret()
        .map_err(|e| scope::unreadable("remote key entropy", &e.to_string()))?;
    let staged = files
        .create_staging(parent)
        .map_err(|e| se_core::store_error::store_error(&e))?;
    let mut file = staged.file;
    file.write_all(secret.expose())
        .and_then(|()| file.sync_all())
        .map_err(|e| scope::unreadable("remote key staging", &e.to_string()))?;
    drop(file);
    match files.publish_no_replace(&staged.path, path) {
        Ok(()) => (),
        Err(e) if e.code == se_store::StoreErrorCode::AlreadyExists => {
            files
                .remove_owned(&staged.path, Sha256::digest(secret.expose()).into())
                .map_err(|e| se_core::store_error::store_error(&e))?;
        }
        Err(e) => return Err(se_core::store_error::store_error(&e)),
    }
    Ok(())
}
