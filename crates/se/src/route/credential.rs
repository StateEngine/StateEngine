//! Protected machine credential bytes. No secret is decoded from JSON, argv or
//! environment, and all read buffers become zeroizing Secret values immediately.
use super::files::Files;
use se_core::{scope, store_error::store_error};
use se_types::{Read, Result, Secret};
use sha2::{Digest, Sha256};
use std::io::{Read as _, Write as _};
const FILE: &str = "credential";

pub fn read(files: &Files) -> Result<Read<Secret>> {
    let path = files.0.root().join(FILE);
    let Some(file) = files
        .0
        .readback(&path)
        .map_err(|error| scope::unreadable("protected machine credential", &error.to_string()))?
    else {
        return Ok(Read::Absent {
            checked: format!("native protected credential absence at {}", path.display()),
        });
    };
    let secret = read_bytes(file)?;
    let again = files
        .0
        .readback(&path)
        .map_err(|error| scope::unreadable("protected machine credential", &error.to_string()))?
        .ok_or_else(|| {
            scope::unreadable(
                "protected machine credential",
                "credential disappeared during readback",
            )
        })?;
    if read_bytes(again)?.expose() != secret.expose() {
        return Err(scope::unreadable(
            "protected machine credential",
            "credential changed during independent readback",
        ));
    }
    Ok(Read::Present { value: secret })
}
fn read_bytes(file: std::fs::File) -> Result<Secret> {
    let mut bytes = Vec::new();
    let result = file.take(33).read_to_end(&mut bytes);
    // Wrap even partial failed reads before branching so every retained secret
    // byte is zeroized on both success and error paths.
    let secret = Secret::new(bytes);
    if let Err(error) = result {
        drop(secret);
        return Err(scope::unreadable(
            "protected machine credential",
            &error.to_string(),
        ));
    }
    let secret = secret.map_err(|_| {
        scope::unreadable(
            "protected machine credential",
            "credential is empty or malformed; explicit rotation is required",
        )
    })?;
    if secret.expose().len() != 32 {
        return Err(scope::unreadable(
            "protected machine credential",
            "credential must contain exactly 32 protected bytes; explicit rotation is required to replace a corrupt credential",
        ));
    }
    Ok(secret)
}
pub fn require(files: &Files) -> Result<Secret> {
    match read(files)? {
        Read::Present { value } => Ok(value),
        Read::Absent { .. } => Err(scope::unreadable(
            "protected machine credential",
            "credential is missing; initialize a new home or use explicit credential recovery/rotation for an existing installation",
        )),
        other => scope::require_present(other, "protected machine credential"),
    }
}
/// Only authorized initial setup calls this after establishing that no initialized
/// owner exists. Startup and ordinary retry paths call `require`, never regenerate.
pub fn initialize(files: &Files) -> Result<Secret> {
    match read(files)? {
        Read::Present { value } => return Ok(value),
        Read::Absent { .. } => (),
        other => return scope::require_present(other, "protected machine credential"),
    }
    // OS RNG failure happens before any staging or permanent credential write.
    let secret = se_proc::random_secret().map_err(|error| {
        se_types::SeError::new(se_types::Detail::SourceUnreadable(
            se_types::details::SourceUnreadable {
                subject: "OS cryptographic random source".into(),
                reason: error.to_string(),
                next_step:
                    "Restore access to the OS random source and retry; no credential was published."
                        .into(),
            },
        ))
        .with_cause(error)
    })?;
    let staged = files
        .0
        .create_staging(files.0.root())
        .map_err(|error| scope::unreadable("credential staging", &error.to_string()))?;
    let mut file = staged.file;
    file.write_all(secret.expose())
        .and_then(|()| file.sync_all())
        .map_err(|error| scope::unreadable("credential staging", &error.to_string()))?;
    drop(file);
    match se_store::StateFiles::publish_no_replace(files, &staged.path, &files.0.root().join(FILE))
    {
        Ok(()) => {
            let actual = require(files)?;
            if actual.expose() != secret.expose() {
                return Err(scope::unreadable(
                    "protected machine credential",
                    "published bytes differ on independent readback",
                ));
            }
            Ok(actual)
        }
        Err(error) if error.code == se_store::StoreErrorCode::AlreadyExists => {
            files
                .retire_staging(&staged.path, Sha256::digest(secret.expose()).into())
                .map_err(|error| store_error(&error))?;
            require(files)
        }
        Err(error) => Err(store_error(&error)),
    }
}
