//! Protected endpoint routing before any connection. A held exclusive home
//! lease proves an old rendezvous record cannot belong to a cooperating host.
use super::endpoint::endpoint_recovery_error;
use crate::{EndpointRecord, IpcEndpoint, client::endpoint as codec};
use se_core::ops::EndpointRecovery;
use se_proc::NativeStateFiles;
use se_types::{Detail, NativePath, Result, SeError, details};
use sha2::{Digest, Sha256};
use std::{fs::TryLockError, io::Read, path::Path};

pub enum EndpointRoute {
    Start { recovery: Option<EndpointRecovery> },
    Live(EndpointRecord),
}
/// The CLI has released its shared direct lease. This port takes the exclusive
/// native lease before retaining a record; a busy lease never grants mutation.
/// Unix callers supply their selected socket address. Windows callers use None:
/// the protected record supplies the per-start name, and authentication still
/// checks its exact native server, epoch, image and generation before use.
pub fn route_endpoint(
    directory: &Path,
    expected_address: Option<&IpcEndpoint>,
) -> Result<EndpointRoute> {
    if cfg!(unix) && expected_address.is_none() {
        return Err(SeError::invalid(
            "runtime socket route",
            "the selected Unix socket address",
        ));
    }
    let files = NativeStateFiles::open(directory).map_err(native_error)?;
    let lock_path = directory.join("runtime.lock");
    let lock = files
        .readback(&lock_path)
        .map_err(native_error)?
        .ok_or_else(|| {
            se_core::scope::unreadable(
                "runtime lock",
                "missing protected runtime.lock; run se init",
            )
        })?;
    match lock.try_lock() {
        Ok(()) => {
            let recovery = match read(&files)? {
                Some((_, bytes)) => Some(retain(&files, &bytes)?),
                None => None,
            };
            // The native child takes its own exclusive lease. The old record
            // remains retained even if a concurrent starter wins that lease.
            drop(lock);
            Ok(EndpointRoute::Start { recovery })
        }
        Err(TryLockError::WouldBlock) => {
            let (record, _) = read(&files)?.ok_or_else(|| {
                busy(
                    directory,
                    "a host or writer holds the lease but no endpoint is published",
                )
            })?;
            let matches = match expected_address {
                Some(expected) => &record.address == expected,
                None => cfg!(windows) && matches!(&record.address, IpcEndpoint::WindowsPipe(_)),
            };
            if !matches {
                return Err(busy(
                    directory,
                    "the lease is held and the protected endpoint names a mismatched address",
                ));
            }
            Ok(EndpointRoute::Live(record))
        }
        Err(TryLockError::Error(error)) => Err(se_core::scope::unreadable(
            "exclusive runtime lease",
            &error.to_string(),
        )
        .with_cause(error)),
    }
}
fn read(files: &NativeStateFiles) -> Result<Option<(EndpointRecord, Vec<u8>)>> {
    let Some(file) = files
        .readback(&files.root().join("endpoint.json"))
        .map_err(native_error)?
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(crate::client::wire::MAX_ENDPOINT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            se_core::scope::unreadable("protected runtime endpoint", &error.to_string())
                .with_cause(error)
        })?;
    Ok(Some((codec::decode_endpoint(&bytes)?, bytes)))
}
/// Both callers retain the real exclusive home lease across pinning, native
/// no-replace rename and independent protected readback. No address is probed.
pub(super) fn retain(files: &NativeStateFiles, bytes: &[u8]) -> Result<EndpointRecovery> {
    let random = se_proc::random_secret().map_err(|error| {
        se_core::scope::unreadable("endpoint retention name allocation", &error.to_string())
            .with_cause(error)
    })?;
    let retained = files.root().join(format!(
        "endpoint.retained-{}.json",
        se_types::hex_lower(&random.expose()[..16])
    ));
    retain_at(files, bytes, &retained)
}
/// The caller retains the exclusive runtime lease through this exact-byte
/// no-replace rename and independent readback. The destination is planned
/// before the effect, inside this same private state home.
pub fn retain_at(
    files: &NativeStateFiles,
    bytes: &[u8],
    retained: &Path,
) -> Result<EndpointRecovery> {
    if retained.parent() != Some(files.root())
        || !retained
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.strip_prefix("endpoint.retained-")
                    .and_then(|name| name.strip_suffix(".json"))
                    .is_some_and(|suffix| {
                        suffix.len() == 32 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
            })
    {
        return Err(endpoint_recovery_error(
            files.root(),
            "retention requires one exact generated endpoint name in the same home",
        ));
    }
    let source = files.root().join("endpoint.json");
    // The private-root read establishes protection; the mutation pin binds the
    // exact same bytes and object, refusing links, replacements and collisions.
    let protected = files
        .readback(&source)
        .map_err(native_error)?
        .ok_or_else(|| {
            endpoint_recovery_error(
                files.root(),
                "endpoint disappeared before protected retention",
            )
        })?;
    drop(protected);
    let mut pin = se_proc::OwnedFile::open(&source)
        .map_err(native_error)?
        .ok_or_else(|| {
            endpoint_recovery_error(files.root(), "endpoint disappeared before native pinning")
        })?;
    let observed = pin
        .read(crate::client::wire::MAX_ENDPOINT_BYTES)
        .map_err(native_error)?;
    if observed != bytes {
        return Err(endpoint_recovery_error(
            files.root(),
            "endpoint changed before retention; the new record was preserved",
        ));
    }
    let verified = (|| -> Result<()> {
        pin.restore_to(retained, Sha256::digest(bytes).into())
            .map_err(native_error)?;
        let actual = files
            .readback(retained)
            .map_err(native_error)?
            .ok_or_else(|| {
                endpoint_recovery_error(
                    files.root(),
                    "retained endpoint is absent on protected readback",
                )
            })?;
        let mut actual_bytes = Vec::new();
        actual
            .take(crate::client::wire::MAX_ENDPOINT_BYTES as u64 + 1)
            .read_to_end(&mut actual_bytes)
            .map_err(|error| {
                se_core::scope::unreadable("retained endpoint readback", &error.to_string())
                    .with_cause(error)
            })?;
        if actual_bytes != bytes || files.readback(&source).map_err(native_error)?.is_some() {
            return Err(endpoint_recovery_error(
                files.root(),
                "endpoint retention could not be confirmed",
            ));
        }
        Ok(())
    })();
    verified.map_err(|error| {
        endpoint_recovery_error(files.root(), &format!(
            "endpoint recovery attempted {} -> {}; verification remains pending, preserve both paths: {error}",
            source.display(), retained.display()
        )).with_cause(error)
    })?;
    Ok(EndpointRecovery {
        original: NativePath::from_local(source)?,
        retained: NativePath::from_local(retained.to_owned())?,
    })
}
/// A later bind/publication/cleanup failure cannot erase an already verified
/// retained record. Keep both the achieved path and original error visible.
pub(super) fn after_retention(
    directory: &Path,
    recovery: Option<&EndpointRecovery>,
    error: SeError,
) -> SeError {
    let Some(recovery) = recovery else {
        return error;
    };
    let retained = match recovery.retained.to_local() {
        Ok(path) => path.display().to_string(),
        Err(path_error) => format!(
            "{:?} (path decoding failed: {path_error})",
            recovery.retained
        ),
    };
    SeError::new(Detail::StateConflict(details::StateConflict {
        subject: directory.display().to_string(),
        reason: format!("Retained stale endpoint {} as {retained}; runtime preparation did not complete: {error}", directory.join("endpoint.json").display()),
        next_step: "Keep the retained endpoint record and retry se up for this same home; if another runtime is running, use se down first.".into(),
    })).with_cause(error)
}
fn busy(directory: &Path, reason: &str) -> SeError {
    SeError::new(Detail::StateConflict(details::StateConflict {
        subject: directory.join("runtime.lock").display().to_string(),
        reason: reason.into(),
        next_step: format!(
            "Run se down for this data home ({}) before retrying se up; the live host's endpoint and files were preserved.",
            directory.display()
        ),
    }))
}
fn native_error(error: se_proc::StateFileError) -> SeError {
    se_core::scope::unreadable("protected runtime endpoint recovery", &error.to_string())
        .with_cause(error)
}
