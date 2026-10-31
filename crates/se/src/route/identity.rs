//! Installation-local native identity, created once during initialized setup.
//! Runtime start only reads this protected record; absence never allocates a new ID.
use super::files::Files;
use se_core::scope;
use se_types::{MachineId, Read, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read as _, Write as _};

const FILE: &str = "machine.json";
const SCHEMA: &str = "stateengine-machine/v1";
const LIMIT: u64 = 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    machine_id: MachineId,
}

pub fn machine(files: &Files) -> Result<Read<MachineId>> {
    let path = files.0.root().join(FILE);
    let Some(file) = files
        .0
        .readback(&path)
        .map_err(|error| scope::unreadable("protected machine identity", &error.to_string()))?
    else {
        return Ok(Read::Absent {
            checked: format!("native owner-only file absence at {}", path.display()),
        });
    };
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| scope::unreadable("protected machine identity", &error.to_string()))?;
    if bytes.len() as u64 > LIMIT {
        return Err(scope::unreadable(
            "protected machine identity",
            "record exceeds 1024 bytes",
        ));
    }
    let record: Record = serde_json::from_slice(&bytes)
        .map_err(|error| scope::unreadable("protected machine identity", &error.to_string()))?;
    if record.schema != SCHEMA {
        return Err(scope::unreadable(
            "protected machine identity",
            "unsupported machine record schema",
        ));
    }
    // Independently reopen through retained root custody and compare the whole
    // bounded record. A concurrently changed record never supplies startup facts.
    let again = files
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
        .take(LIMIT + 1)
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
    Ok(Read::Present {
        value: record.machine_id,
    })
}
/// Only authorized `init` calls this before publishing successful setup. The
/// protected root must already exist; a runtime caller must use `machine` instead.
pub fn initialize_machine(files: &Files) -> Result<MachineId> {
    match machine(files)? {
        Read::Present { value } => return Ok(value),
        Read::Absent { .. } => (),
        other => return scope::require_present(other, "protected machine identity"),
    }
    let id = MachineId::new(uuid::Uuid::new_v4().to_string())?;
    let bytes = serde_json::to_vec(&Record {
        schema: SCHEMA.into(),
        machine_id: id,
    })
    .map_err(|error| scope::unreadable("machine identity serialization", &error.to_string()))?;
    let staged = files
        .0
        .create_staging(files.0.root())
        .map_err(|error| scope::unreadable("machine identity staging", &error.to_string()))?;
    let mut file = staged.file;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| scope::unreadable("machine identity staging", &error.to_string()))?;
    drop(file);
    match files
        .0
        .publish_no_replace(&staged.path, &files.0.root().join(FILE))
    {
        Ok(()) => (),
        Err(error) if error.code == se_proc::StateFileErrorCode::AlreadyExists => {
            // Another init won publication. Retire only our independently pinned
            // exact staging bytes, preserving the permanent winner.
            retire_staging(&staged.path, sha2::Sha256::digest(&bytes).into())?;
        }
        Err(error) => {
            return Err(scope::unreadable(
                "machine identity publication",
                &error.to_string(),
            ));
        }
    }
    scope::require_present(machine(files)?, "initialized protected machine identity")
}
use sha2::Digest;

fn retire_staging(path: &std::path::Path, digest: [u8; 32]) -> Result<()> {
    // The effects pin serializes mutations of the shared parent. Competing init
    // losers can briefly hold it while retiring their own uniquely named files.
    for attempt in 0..50 {
        match se_proc::OwnedFile::open(path) {
            Ok(Some(file)) => {
                return file.remove(digest).map_err(|error| {
                    scope::unreadable("machine identity staging cleanup", &error.to_string())
                });
            }
            Ok(None) => return Ok(()),
            Err(error)
                if error
                    .source
                    .as_ref()
                    .is_some_and(|source| source.kind() == std::io::ErrorKind::WouldBlock)
                    && attempt < 49 =>
            {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            Err(error) => {
                return Err(scope::unreadable(
                    "machine identity staging cleanup",
                    &error.to_string(),
                ));
            }
        }
    }
    Err(scope::unreadable(
        "machine identity staging cleanup",
        "bounded native parent contention did not clear",
    ))
}
