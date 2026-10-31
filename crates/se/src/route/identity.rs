//! Native machine-identity custody. The create-once rule is shared in se-core.
use super::files::Files;
use se_core::{
    machine_identity::{
        self, MACHINE_IDENTITY_FILE, MACHINE_IDENTITY_MAX_BYTES, MachineIdentityPort, Publication,
    },
    scope,
};
use se_types::{MachineId, Read, Result};
use sha2::Digest;
use std::{
    io::{Read as _, Write as _},
    path::Path,
};

#[cfg(test)]
#[allow(dead_code)] // Used by the integration test's imported module, not the binary test target.
pub fn machine(files: &Files) -> Result<Read<MachineId>> {
    machine_identity::read_machine_identity(files.0.root(), &Port(files))
}
pub fn require_machine(files: &Files) -> Result<MachineId> {
    machine_identity::require_machine_identity(files.0.root(), &Port(files))
}
/// Called after the installer or init creates and authorizes the data home.
/// This does not create the directory or grant authority to an existing home.
pub fn ensure_machine_identity(home: &Path) -> Result<MachineId> {
    let files = Files::open(home).map_err(|error| se_core::store_error::store_error(&error))?;
    initialize_machine(&files)
}
pub fn initialize_machine(files: &Files) -> Result<MachineId> {
    machine_identity::ensure_machine_identity(files.0.root(), &Port(files), || {
        let random = se_proc::random_secret().map_err(|error| {
            scope::unreadable("machine identity OS random source", &error.to_string())
                .with_cause(error)
        })?;
        let bytes: [u8; 16] = random.expose()[..16].try_into().map_err(|_| {
            scope::unreadable(
                "machine identity OS random source",
                "native allocator did not supply 16 bytes",
            )
        })?;
        MachineId::new(
            uuid::Builder::from_random_bytes(bytes)
                .into_uuid()
                .to_string(),
        )
    })
}
struct Port<'a>(&'a Files);
impl MachineIdentityPort for Port<'_> {
    fn read(&self, home: &Path) -> Result<Read<Vec<u8>>> {
        if home != self.0.0.root() {
            return Err(scope::unreadable(
                "protected machine identity",
                "home differs from retained native custody",
            ));
        }
        let path = home.join(MACHINE_IDENTITY_FILE);
        let Some(file) =
            self.0.0.readback(&path).map_err(|error| {
                scope::unreadable("protected machine identity", &error.to_string())
            })?
        else {
            return Ok(Read::Absent {
                checked: format!("native owner-only file absence at {}", path.display()),
            });
        };
        let mut bytes = Vec::new();
        file.take((MACHINE_IDENTITY_MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| scope::unreadable("protected machine identity", &error.to_string()))?;
        if bytes.len() > MACHINE_IDENTITY_MAX_BYTES {
            return Err(scope::unreadable(
                "protected machine identity",
                "record exceeds 1024 bytes",
            ));
        }
        // Independently reopen through retained root custody and compare all
        // bytes. Changed or newly unsafe names cannot supply startup facts.
        let again = self
            .0
            .0
            .readback(&path)
            .map_err(|error| scope::unreadable("protected machine identity", &error.to_string()))?
            .ok_or_else(|| {
                scope::unreadable(
                    "protected machine identity",
                    "record disappeared during read",
                )
            })?;
        let mut confirmed = Vec::new();
        again
            .take((MACHINE_IDENTITY_MAX_BYTES + 1) as u64)
            .read_to_end(&mut confirmed)
            .map_err(|error| {
                scope::unreadable("protected machine identity readback", &error.to_string())
            })?;
        if confirmed != bytes {
            return Err(scope::unreadable(
                "protected machine identity",
                "record changed during independent readback",
            ));
        }
        Ok(Read::Present { value: bytes })
    }
    fn publish_no_replace(&self, home: &Path, bytes: &[u8]) -> Result<Publication> {
        if home != self.0.0.root() {
            return Err(scope::unreadable(
                "protected machine identity",
                "home differs from retained native custody",
            ));
        }
        let staged =
            self.0.0.create_staging(home).map_err(|error| {
                scope::unreadable("machine identity staging", &error.to_string())
            })?;
        let mut file = staged.file;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| scope::unreadable("machine identity staging", &error.to_string()))?;
        drop(file);
        match se_store::StateFiles::publish_no_replace(
            self.0,
            &staged.path,
            &home.join(MACHINE_IDENTITY_FILE),
        ) {
            Ok(()) => Ok(Publication::Published),
            Err(error) if error.code == se_store::StoreErrorCode::AlreadyExists => {
                self.0
                    .retire_staging(&staged.path, sha2::Sha256::digest(bytes).into())
                    .map_err(|error| se_core::store_error::store_error(&error))?;
                Ok(Publication::AlreadyExists)
            }
            Err(error) => Err(se_core::store_error::store_error(&error)),
        }
    }
}
