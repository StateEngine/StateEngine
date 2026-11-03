//! Protected post-transport facts. This record never proves release of the OS lease.
use se_core::{scope, store_error::store_error};
use se_store::StateFiles;
use se_types::{
    AgentId, Generation, HostEpoch, IdempotencyKey, LifecycleId, ProjectId, ProviderSessionId,
    Read, Result, SeError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read as _, path::Path};

const FILE: &str = "runtime-close.json";
const MAX_BYTES: usize = 1_048_576;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentClosure {
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: se_types::SessionId,
    pub conversation: Option<ProviderSessionId>,
    pub lifecycle: LifecycleId,
    pub witness: Option<se_proc::StopWitness>,
    pub reason: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosure {
    pub schema: u16,
    pub epoch: HostEpoch,
    pub generation: Generation,
    pub key: IdempotencyKey,
    pub resources_closed: bool,
    pub stops: Vec<AgentClosure>,
    pub pending: Vec<String>,
}
impl RuntimeClosure {
    pub fn matches(&self, endpoint: &crate::EndpointRecord, key: &IdempotencyKey) -> bool {
        self.epoch == endpoint.epoch && self.generation == endpoint.generation && &self.key == key
    }
}

fn bytes(files: &dyn StateFiles, root: &Path) -> Result<Option<Vec<u8>>> {
    let file = match files
        .readback(&root.join(FILE))
        .map_err(|e| store_error(&e))?
    {
        Read::Absent { .. } => return Ok(None),
        value => scope::require_present(
            value,
            "runtime close receipt",
            "Preserve this data home and restore access to its protected close receipt.",
        )?,
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| scope::unreadable("runtime close receipt", &e.to_string()).with_cause(e))?;
    if bytes.len() > MAX_BYTES {
        return Err(SeError::too_large(
            "runtime close receipt",
            MAX_BYTES,
            bytes.len(),
        ));
    }
    Ok(Some(bytes))
}
fn decode(bytes: &[u8]) -> Result<RuntimeClosure> {
    let record: RuntimeClosure = serde_json::from_slice(bytes)
        .map_err(|e| scope::unreadable("runtime close receipt", &e.to_string()))?;
    if record.schema != 1 {
        return Err(scope::unreadable(
            "runtime close receipt",
            "unsupported schema; preserve the original receipt",
        ));
    }
    Ok(record)
}
/// Read under native owner-only, no-follow file custody. Absence is not completion.
pub fn read(files: &dyn StateFiles, root: &Path) -> Result<Option<RuntimeClosure>> {
    bytes(files, root)?.map(|v| decode(&v)).transpose()
}
pub(crate) fn publish(files: &dyn StateFiles, root: &Path, record: &RuntimeClosure) -> Result<()> {
    let bytes = serde_json::to_vec(record)
        .map_err(|e| scope::unreadable("runtime close receipt codec", &e.to_string()))?;
    if bytes.len() > MAX_BYTES {
        return Err(SeError::too_large(
            "runtime close receipt",
            MAX_BYTES,
            bytes.len(),
        ));
    }
    let old = self::bytes(files, root)?;
    if let Some(old) = &old {
        let previous = decode(old)?;
        if previous.generation >= record.generation && old != &bytes {
            return Err(scope::unreadable(
                "runtime close receipt",
                "an equal or newer generation already published different facts; its receipt was preserved",
            ));
        }
        if old == &bytes {
            return Ok(());
        }
    }
    let expected = old.as_ref().map(|v| Sha256::digest(v).into());
    files
        .replace_owned(&root.join(FILE), expected, &bytes)
        .map_err(|e| store_error(&e))?;
    if self::bytes(files, root)?.as_deref() != Some(bytes.as_slice()) {
        return Err(scope::unreadable(
            "runtime close receipt",
            "protected publication readback differs from the completed stages",
        ));
    }
    Ok(())
}
