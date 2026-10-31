//! One create-once identity rule shared by installer setup and archive-less init.
//! Native custody and random allocation are injected; startup only reads.
use crate::scope;
use se_types::{MachineId, Read, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const MACHINE_IDENTITY_FILE: &str = "machine.json";
pub const MACHINE_IDENTITY_MAX_BYTES: usize = 1024;
const SCHEMA: &str = "stateengine-machine/v1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    machine_id: MachineId,
}
#[derive(Clone, Copy)]
pub enum Publication {
    Published,
    AlreadyExists,
}
/// Complete bounded bytes from owner-only native custody. Publication syncs and
/// uses StateFiles publish_no_replace; a losing initializer retires only its own
/// exact staging object before reporting AlreadyExists.
pub trait MachineIdentityPort {
    fn read(&self, home: &Path) -> Result<Read<Vec<u8>>>;
    fn publish_no_replace(&self, home: &Path, bytes: &[u8]) -> Result<Publication>;
}
pub fn read_machine_identity(
    home: &Path,
    port: &dyn MachineIdentityPort,
) -> Result<Read<MachineId>> {
    match port.read(home)? {
        Read::Present { value } => {
            if value.len() > MACHINE_IDENTITY_MAX_BYTES {
                return Err(scope::unreadable(
                    "protected machine identity",
                    "record exceeds 1024 bytes",
                ));
            }
            let record: Record = serde_json::from_slice(&value).map_err(|error| {
                scope::unreadable("protected machine identity", &error.to_string())
            })?;
            if record.schema != SCHEMA {
                return Err(scope::unreadable(
                    "protected machine identity",
                    "unsupported machine record schema",
                ));
            }
            Ok(Read::Present {
                value: record.machine_id,
            })
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
}
/// Installer/init only, after native data-home creation and owner admission.
/// The random allocator is called only for a measured absent identity.
pub fn ensure_machine_identity(
    home: &Path,
    port: &dyn MachineIdentityPort,
    allocate: impl FnOnce() -> Result<MachineId>,
) -> Result<MachineId> {
    match read_machine_identity(home, port)? {
        Read::Present { value } => return Ok(value),
        Read::Absent { .. } => (),
        other => return scope::require_present(other, "protected machine identity"),
    }
    let id = allocate()?;
    let bytes = serde_json::to_vec(&Record {
        schema: SCHEMA.into(),
        machine_id: id.clone(),
    })
    .map_err(|error| scope::unreadable("machine identity serialization", &error.to_string()))?;
    let outcome = port.publish_no_replace(home, &bytes)?;
    let actual = require_machine_identity(home, port)?;
    if matches!(outcome, Publication::Published) && actual != id {
        return Err(scope::unreadable(
            "protected machine identity",
            "published identity differs on independent readback",
        ));
    }
    Ok(actual)
}
pub fn require_machine_identity(home: &Path, port: &dyn MachineIdentityPort) -> Result<MachineId> {
    match read_machine_identity(home, port)? {
        Read::Present { value } => Ok(value),
        Read::Absent { .. } => Err(scope::unreadable(
            "protected machine identity",
            "machine identity missing; run se init",
        )),
        other => scope::require_present(other, "protected machine identity"),
    }
}
