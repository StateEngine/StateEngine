//! Owner-only history recovery from the newest verified automatic backup. The
//! live store is preserved, never repaired; without confirmation it only plans.
use super::inputs::Validate;
use schemars::JsonSchema;
use se_types::{IdempotencyKey, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoreRestore {
    /// Confirms the printed plan, including the events it loses.
    #[serde(default)]
    pub yes: bool,
    pub idempotency_key: IdempotencyKey,
}
impl Validate for StoreRestore {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RestoreBackup {
    pub id: String,
    pub path: String,
    pub through_sequence: u64,
    pub bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RestoreNext {
    pub text: String,
    pub argv: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RestoreResult {
    pub idempotency_key: IdempotencyKey,
    /// `planned`, `restored` or `refused`.
    pub outcome: String,
    pub backup: Option<RestoreBackup>,
    /// Committed events after the backup that the restore loses; None when the
    /// live store cannot say.
    pub events_lost: Option<u64>,
    /// Where the replaced store was preserved, once restored.
    pub preserved: Option<String>,
    /// Agents whose live sessions block the restore.
    pub blocking_agents: Vec<String>,
    /// The original receipt JSON, verbatim, once restored.
    pub receipt: Option<String>,
    pub reason: Option<String>,
    pub next: Option<RestoreNext>,
}
/// The command that confirms this plan.
pub fn confirm(input: &StoreRestore) -> RestoreNext {
    RestoreNext {
        text: "Review the plan, then confirm to restore this backup".into(),
        argv: vec![
            "se".into(),
            "restore".into(),
            "--key".into(),
            input.idempotency_key.as_str().into(),
            "--yes".into(),
        ],
    }
}
