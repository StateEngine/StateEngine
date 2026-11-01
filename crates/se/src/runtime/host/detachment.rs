//! Protected startup observations for a later status reader. This record
//! supplies no liveness or authority: the caller first verifies the live endpoint.
use se_core::{ops::HostDetachment, scope, store_error::store_error};
use se_host::{EndpointRecord, client::lease::Deadline};
use se_store::StateFiles;
use se_types::{Read, Result, Sha256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256 as Hasher};
use std::{io::Read as _, path::Path};

const NAME: &str = "runtime-info.json";
const MAX_BYTES: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetachmentObservation {
    pub detachment: HostDetachment,
    /// Present only for a native SessionOnly observation, never inferred from OS.
    pub inherited_cgroup: Option<bool>,
}
#[derive(Serialize, Deserialize)]
enum Schema {
    #[serde(rename = "se.runtime-info/v1")]
    V1,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: Schema,
    endpoint_sha256: Sha256,
    observation: DetachmentObservation,
}
fn endpoint_digest(endpoint: &EndpointRecord) -> Result<Sha256> {
    Ok(Sha256::from_bytes(
        Hasher::digest(se_host::client::endpoint::encode_endpoint(endpoint)?.as_bytes()).into(),
    ))
}
fn read_bytes(files: &crate::route::files::Files, bound: &Deadline) -> Result<Option<Vec<u8>>> {
    bound.remaining()?;
    let Some(file) = files
        .0
        .readback(&files.0.root().join(NAME))
        .map_err(|error| scope::unreadable("runtime detachment record", &error.to_string()))?
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| scope::unreadable("runtime detachment record", &error.to_string()))?;
    bound.remaining()?;
    if bytes.len() > MAX_BYTES {
        return Err(se_types::SeError::too_large(
            "runtime detachment record",
            MAX_BYTES,
            bytes.len(),
        ));
    }
    Ok(Some(bytes))
}
pub(super) fn publish(
    home: &Path,
    endpoint: &EndpointRecord,
    ready: &se_proc::RuntimeReady,
    bound: &Deadline,
) -> Result<DetachmentObservation> {
    let observation = match ready.detachment {
        se_proc::RuntimeDetachment::WindowsBreakaway => DetachmentObservation {
            detachment: HostDetachment::WindowsBreakaway,
            inherited_cgroup: None,
        },
        se_proc::RuntimeDetachment::UserManagerUnit => DetachmentObservation {
            detachment: HostDetachment::UserManagerUnit,
            inherited_cgroup: None,
        },
        se_proc::RuntimeDetachment::SessionOnly { inherited_cgroup } => DetachmentObservation {
            detachment: HostDetachment::SessionOnly,
            inherited_cgroup: Some(inherited_cgroup),
        },
    };
    let files = crate::route::files::Files::open(home).map_err(|error| store_error(&error))?;
    let prior = read_bytes(&files, bound)?;
    let record = Record {
        schema: Schema::V1,
        endpoint_sha256: endpoint_digest(endpoint)?,
        observation: observation.clone(),
    };
    let bytes = serde_json::to_vec(&record)
        .map_err(|error| scope::unreadable("runtime detachment encoding", &error.to_string()))?;
    bound.remaining()?;
    files
        .replace_owned(
            &home.join(NAME),
            prior.as_ref().map(|bytes| Hasher::digest(bytes).into()),
            &bytes,
        )
        .map_err(|error| store_error(&error))?;
    if read_bytes(&files, bound)?.as_deref() != Some(bytes.as_slice()) {
        return Err(scope::unreadable(
            "runtime detachment publication",
            "record changed during independent protected readback",
        ));
    }
    Ok(observation)
}
/// Read only for an independently verified current endpoint. A missing record
/// is absent, and a stale/damaged record is unreadable; none supplies a mode.
pub fn read_detachment(
    home: &Path,
    endpoint: &EndpointRecord,
    bound: &Deadline,
) -> Result<Read<DetachmentObservation>> {
    let files = crate::route::files::Files::open(home).map_err(|error| store_error(&error))?;
    let Some(bytes) = read_bytes(&files, bound)? else {
        return Ok(Read::Absent {
            checked: "protected runtime-info.json is absent".into(),
        });
    };
    let record: Record = se_host::client::wire::decode_json(&bytes, MAX_BYTES)?;
    if record.endpoint_sha256 != endpoint_digest(endpoint)? {
        return Err(scope::unreadable(
            "runtime detachment record",
            "observation belongs to a different endpoint or host generation",
        ));
    }
    if matches!(record.observation.detachment, HostDetachment::SessionOnly)
        != record.observation.inherited_cgroup.is_some()
    {
        return Err(scope::unreadable(
            "runtime detachment record",
            "inherited cgroup fact disagrees with observed detachment mode",
        ));
    }
    if read_bytes(&files, bound)?.as_deref() != Some(bytes.as_slice()) {
        return Err(scope::unreadable(
            "runtime detachment record",
            "record changed during independent protected readback",
        ));
    }
    Ok(Read::Present {
        value: record.observation,
    })
}
