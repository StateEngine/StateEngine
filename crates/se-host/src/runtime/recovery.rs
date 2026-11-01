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
/// The address is selected by the caller without connecting to the old record.
pub fn route_endpoint(directory: &Path, expected_address: &IpcEndpoint) -> Result<EndpointRoute> {
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
            if &record.address != expected_address {
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
    let random = se_proc::random_secret().map_err(|error| {
        se_core::scope::unreadable("endpoint retention name allocation", &error.to_string())
            .with_cause(error)
    })?;
    let suffix: String = random.expose()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let retained = files
        .root()
        .join(format!("endpoint.retained-{suffix}.json"));
    let verified = (|| -> Result<()> {
        pin.restore_to(&retained, Sha256::digest(bytes).into())
            .map_err(native_error)?;
        let actual = files
            .readback(&retained)
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
        retained: NativePath::from_local(retained)?,
    })
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
