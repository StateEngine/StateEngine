//! Explicit owner migration, never part of init or a model-facing tool.
use super::inputs::{Validate, bounded};
use schemars::JsonSchema;
use se_types::{HumanId, IdempotencyKey, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HumanMapping {
    pub source: HumanId,
    pub target: HumanId,
}
impl HumanMapping {
    pub fn parse(text: &str) -> Result<Self> {
        let (source, target) = text.split_once('=').ok_or_else(|| {
            se_types::SeError::invalid("--map-human", "SOURCE_HUMAN_ID=EXISTING_TARGET_HUMAN_ID")
        })?;
        Ok(Self {
            source: HumanId::from_legacy(source)?,
            target: HumanId::from_legacy(target)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportNode {
    pub from_node: String,
    /// Explicit source human adopted by this owner; other historical humans stay data.
    #[serde(default)]
    pub source_owner: Option<HumanId>,
    /// Explicit historical identity correspondence; never creates a home owner.
    #[serde(default)]
    pub human_mappings: Vec<HumanMapping>,
    pub idempotency_key: IdempotencyKey,
}
impl ImportNode {
    pub fn mappings(&self) -> Result<BTreeMap<HumanId, HumanId>> {
        if self.human_mappings.len() > 256 {
            return Err(se_types::SeError::invalid(
                "--map-human",
                "at most 256 explicit correspondences",
            ));
        }
        let mut mappings = BTreeMap::new();
        for pair in &self.human_mappings {
            if mappings
                .insert(pair.source.clone(), pair.target.clone())
                .is_some()
            {
                return Err(se_types::SeError::invalid(
                    "--map-human",
                    "each source human ID exactly once",
                ));
            }
        }
        mappings.retain(|source, target| source != target);
        Ok(mappings)
    }
}
impl Validate for ImportNode {
    fn validate(&self) -> Result<()> {
        self.mappings()?;
        bounded("Node state source", &self.from_node, 32768, false)?;
        if self.from_node.contains('\0') {
            return Err(se_types::SeError::invalid(
                "Node state source",
                "a path without NUL bytes",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ImportFamilyReceipt {
    pub family: String,
    pub source: String,
    /// present, absent or unreadable; zero rows is only meaningful for present.
    pub state: String,
    pub read: u64,
    pub imported: u64,
    pub duplicate: u64,
    pub unreadable: u64,
    pub dropped_by_policy: u64,
    pub deferred: u64,
    pub reason: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ImportReceipt {
    pub import_id: String,
    pub source: String,
    pub complete: bool,
    pub originals_retained: bool,
    pub families: Vec<ImportFamilyReceipt>,
    pub resume: Vec<ImportResume>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ImportResume {
    pub session: String,
    pub agent: String,
    pub provider: String,
    pub native_reference: Option<String>,
    pub state: String,
}

/// Bind the caller's explicit key to this retained source path using the
/// common request fingerprint before any source cursor moves.
pub fn bind<R: se_store::Snapshot>(
    kernel: &crate::dispatch::Kernel,
    input: &ImportNode,
    run: se_store::RecordId,
    source: se_store::SourceEvidence,
    cx: &crate::commit::Cx<'_, R>,
) -> Result<se_store::AtomicBatch> {
    use se_store::{Door, EventBody, ImportFamily, import::LegacyTarget};
    use sha2::{Digest, Sha256};
    input.validate()?;
    let key = se_types::hex_lower(&Sha256::digest(input.idempotency_key.as_str().as_bytes()));
    let mut event = kernel.event(
        EventBody::LegacyRetained {
            import: run,
            family: ImportFamily::Projects,
            format_version: 1,
            legacy_id: format!("request:{key}"),
            mapped_id: LegacyTarget::Record(run),
            source,
            bytes: None,
            retained_from: None,
        },
        cx,
    )?;
    event.header.door = Door::Import;
    let mut intent =
        serde_json::json!({"from_node":input.from_node,"source_owner":input.source_owner});
    let mappings = input.mappings()?;
    // Preserve the established request fingerprint for imports without mappings.
    if !mappings.is_empty() {
        intent["human_mappings"] = serde_json::to_value(mappings).map_err(|_| {
            se_types::SeError::invalid("human correspondence", "serializable exact human IDs")
        })?;
    }
    kernel.batch(
        "store.import_node",
        input.idempotency_key.clone(),
        intent,
        event,
        cx,
    )
}
