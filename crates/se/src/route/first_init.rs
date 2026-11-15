//! First-creation provenance is retired before the store can acquire history.
use crate::route::{credential, files::Files};
use se_core::{scope, store_error::store_error};
use se_store::{ReadStore, SqliteDirect, StateFiles};
use se_types::{Detail, Read, Result, SeError, Secret, details};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read as _;

const FILE: &str = "init-pending.json";
const MAX_BYTES: usize = 512;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FirstInit {
    version: u32,
    credential_sha256: [u8; 32],
}

fn conflict(reason: &str) -> SeError {
    SeError::new(Detail::StateConflict(details::StateConflict {
        subject: "first initialization".into(),
        reason: reason.into(),
        next_step: "Preserve this home and its original credential. Restore the original credential or retained database before retrying init; do not replace established history.".into(),
    }))
}

fn bytes(files: &Files) -> Result<Option<Vec<u8>>> {
    let path = files.0.root().join(FILE);
    let Some(file) = files
        .0
        .readback(&path)
        .map_err(|e| scope::unreadable("first-init receipt", &e.to_string()))?
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| scope::unreadable("first-init receipt", &e.to_string()))?;
    if bytes.len() > MAX_BYTES {
        return Err(scope::unreadable(
            "first-init receipt",
            "record exceeds the complete read bound",
        ));
    }
    Ok(Some(bytes))
}

fn read(files: &Files) -> Result<Option<(FirstInit, [u8; 32])>> {
    let Some(value) = bytes(files)? else {
        return Ok(None);
    };
    if bytes(files)?.as_ref() != Some(&value) {
        return Err(scope::unreadable(
            "first-init receipt",
            "record changed during independent readback",
        ));
    }
    let record: FirstInit = serde_json::from_slice(&value)
        .map_err(|_| scope::unreadable("first-init receipt", "malformed record"))?;
    if record.version != 1 {
        return Err(scope::unreadable(
            "first-init receipt",
            "unsupported record version",
        ));
    }
    Ok(Some((record, Sha256::digest(value).into())))
}

/// Read-only evidence for the credential-only first-creation gap.
pub(in crate::route) fn resumable(files: &Files) -> Result<bool> {
    let Some((record, _)) = read(files)? else {
        return Ok(false);
    };
    match credential::read(files)? {
        Read::Present { value } => {
            if <[u8; 32]>::from(Sha256::digest(value.expose())) != record.credential_sha256 {
                return Err(conflict(
                    "credential differs from the pending first initialization",
                ));
            }
            Ok(true)
        }
        Read::Absent { .. } => Ok(false),
        _ => Err(scope::unreadable(
            "first-init credential",
            "credential presence remains unknown",
        )),
    }
}

/// Called under the setup lease, before a new credential can become visible.
pub(in crate::route) fn prepare(files: &Files, secret: &Secret) -> Result<()> {
    if !matches!(credential::read(files)?, Read::Absent { .. }) {
        return Err(conflict(
            "a credential appeared before first-creation publication",
        ));
    }
    let old = read(files)?.map(|(_, digest)| digest);
    let value = serde_json::to_vec(&FirstInit {
        version: 1,
        credential_sha256: Sha256::digest(secret.expose()).into(),
    })
    .map_err(|_| scope::unreadable("first-init receipt", "cannot encode record"))?;
    // With no published credential, a prior receipt belongs to an unpublished
    // attempt. Replacing only its exact bytes keeps every crash cut retryable.
    files
        .replace_owned(&files.0.root().join(FILE), old, &value)
        .map_err(|e| store_error(&e))?;
    let expected: [u8; 32] = Sha256::digest(&value).into();
    if read(files)?.map(|(_, digest)| digest) != Some(expected) {
        return Err(scope::unreadable(
            "first-init receipt",
            "published record differs on independent readback",
        ));
    }
    Ok(())
}

/// The receipt can outlive a crash only while the database has no events.
/// Retire it durably before the first owner/project registration is admitted.
pub(in crate::route) fn complete(files: &Files, store: &SqliteDirect) -> Result<()> {
    let Some((_, digest)) = read(files)? else {
        return Ok(());
    };
    if !resumable(files)? {
        return Err(conflict(
            "the pending first initialization has no credential",
        ));
    }
    if store.info().map_err(|e| store_error(&e))?.head.is_some() {
        return Err(conflict(
            "a pending first-init receipt conflicts with recorded history",
        ));
    }
    files
        .remove_owned(&files.0.root().join(FILE), digest)
        .map_err(|e| store_error(&e))
}
