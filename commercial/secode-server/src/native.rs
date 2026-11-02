// SPDX-License-Identifier: LicenseRef-StateEngine-Proprietary
//! Read actual native process facts and the protected initialized machine ID.
use se_core::machine_identity::{self, MachineIdentityPort, Publication};
use se_store::{ReadStore, StateFiles};
use se_types::{
    HostEpoch, HostGeneration, NativePath, ProcessFields, ProcessInstance, Read, Sha256,
};
use sha2::{Digest, Sha256 as Hasher};
use std::{io::Read as _, num::NonZeroU32, path::Path};

pub(super) fn epoch(home: &Path) -> Result<secode_stateengine_api::HostEpoch, String> {
    let files = se_host::state_files::Files::open(home).map_err(|error| error.to_string())?;
    let machine = machine_identity::require_machine_identity(home, &MachineReader(&files))
        .map_err(|error| error.to_string())?;
    let native = se_proc::current_runtime_identity(machine).map_err(|error| error.to_string())?;
    let peer = se_proc::native_ipc::observe_ipc_self().map_err(|error| error.to_string())?;
    let owner = ProcessInstance::from_observation(ProcessFields {
        machine: native.process.machine,
        boot: native.boot_id,
        pid: NonZeroU32::new(peer.pid()).ok_or("native self has a zero PID")?,
        started: peer.started().clone(),
        executable: NativePath::from_local(native.process.image)
            .map_err(|error| error.to_string())?,
        argv_sha256: argv_digest(),
    })
    .map_err(|error| error.to_string())?;
    peer.verify_instance(&owner, peer.image_sha256())
        .map_err(|error| error.to_string())?;
    let epoch = HostEpoch {
        owner,
        generation: HostGeneration::new(next_generation(home)?)
            .map_err(|error| error.to_string())?,
    };
    se_host::linked::host_epoch(&epoch).map_err(|error| error.to_string())
}
fn next_generation(home: &Path) -> Result<u64, String> {
    let options = se_store::StoreOptions {
        state_directory: home.to_owned(),
        busy_timeout: std::time::Duration::from_secs(5),
    };
    let reader = match se_store::SqliteFactory::open_reader_with_capacity(
        &options,
        NonZeroU32::MIN.saturating_add(1),
    )
    .map_err(|error| error.to_string())?
    {
        Read::Present { value } => value,
        Read::Absent { .. } => return Err(
            "StateEngine setup required; initialize this workspace through the trusted setup flow"
                .to_owned(),
        ),
        Read::Unreadable { reason, .. } => {
            return Err(format!("StateEngine store is unreadable: {reason}"));
        }
        Read::Unknown { what } => return Err(format!("StateEngine store is unknown: {what}")),
    };
    match reader.runtime_owner().map_err(|error| error.to_string())? {
        Read::Present { value } => value
            .generation
            .get()
            .checked_add(1)
            .ok_or_else(|| "StateEngine host generation is exhausted".to_owned()),
        Read::Absent { .. } => Ok(1),
        Read::Unreadable { reason, .. } => {
            Err(format!("StateEngine owner is unreadable: {reason}"))
        }
        Read::Unknown { what } => Err(format!("StateEngine owner is unknown: {what}")),
    }
}
fn argv_digest() -> Sha256 {
    let mut digest = Hasher::new();
    for arg in std::env::args_os() {
        #[cfg(unix)]
        let bytes = {
            use std::os::unix::ffi::OsStrExt;
            arg.as_bytes().to_vec()
        };
        #[cfg(windows)]
        let bytes = {
            use std::os::windows::ffi::OsStrExt;
            arg.encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>()
        };
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    Sha256::from_bytes(digest.finalize().into())
}
struct MachineReader<'a>(&'a se_host::state_files::Files);
impl MachineIdentityPort for MachineReader<'_> {
    fn read(&self, home: &Path) -> se_types::Result<Read<Vec<u8>>> {
        if home != self.0.0.root() {
            return Err(se_core::scope::unreadable(
                "native machine identity",
                "state home changed",
            ));
        }
        let path = home.join(machine_identity::MACHINE_IDENTITY_FILE);
        let read = || -> se_types::Result<Read<Vec<u8>>> {
            let file = self
                .0
                .readback(&path)
                .map_err(|error| se_core::store_error::store_error(&error))?;
            match file {
                Read::Present { value } => {
                    let mut bytes = Vec::new();
                    value
                        .take((machine_identity::MACHINE_IDENTITY_MAX_BYTES + 1) as u64)
                        .read_to_end(&mut bytes)
                        .map_err(|error| {
                            se_core::scope::unreadable(
                                "native machine identity",
                                &error.to_string(),
                            )
                        })?;
                    Ok(Read::Present { value: bytes })
                }
                Read::Absent { checked } => Ok(Read::Absent { checked }),
                Read::Unreadable {
                    source,
                    reason,
                    error,
                } => Ok(Read::Unreadable {
                    source,
                    reason,
                    error,
                }),
                Read::Unknown { what } => Ok(Read::Unknown { what }),
            }
        };
        let first = read()?;
        if let Read::Present { value: expected } = &first {
            match read()? {
                Read::Present { value } if &value == expected => {}
                _ => {
                    return Err(se_core::scope::unreadable(
                        "native machine identity",
                        "identity changed during independent readback",
                    ));
                }
            }
        }
        Ok(first)
    }
    fn publish_no_replace(&self, _home: &Path, _bytes: &[u8]) -> se_types::Result<Publication> {
        Err(se_core::scope::unreadable(
            "native machine identity",
            "private startup only reads; initialize through se init",
        ))
    }
}
