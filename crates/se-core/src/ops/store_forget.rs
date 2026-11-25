//! Owner-only erasure of message bodies and captured turns: the explicit privacy
//! exception to append-only history. Without confirmation it only plans.
use super::inputs::Validate;
use schemars::JsonSchema;
use se_types::{EventId, IdempotencyKey, Result, SeError};
use serde::{Deserialize, Serialize};

pub const MAX_EVENTS: usize = 60;

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoreForget {
    /// Exact message or captured-turn event IDs from one project.
    pub events: Vec<EventId>,
    /// Confirms the printed plan, including the copies it cannot erase.
    #[serde(default)]
    pub yes: bool,
    /// The digest printed with that plan: `yes` erases only a plan that still matches it.
    #[serde(default)]
    pub plan: Option<String>,
    pub idempotency_key: IdempotencyKey,
}
impl Validate for StoreForget {
    fn validate(&self) -> Result<()> {
        if self.events.is_empty() || self.events.len() > MAX_EVENTS {
            return Err(SeError::invalid("--event", "between 1 and 60 event IDs"));
        }
        for (index, event) in self.events.iter().enumerate() {
            if self.events[..index].contains(event) {
                return Err(SeError::invalid("--event", "each event ID once"));
            }
        }
        if self
            .plan
            .as_ref()
            .is_some_and(|plan| plan.len() != 64 || !plan.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(SeError::invalid(
                "--plan",
                "the 64-character digest printed with the plan",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ForgetTarget {
    pub event: EventId,
    pub revision: u64,
}
/// A copy StateEngine does not control, named instead of claimed as erased.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ForgetResidual {
    pub custodian: String,
    pub location: String,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ForgetNext {
    pub text: String,
    pub argv: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ErasureReceipt {
    pub idempotency_key: IdempotencyKey,
    /// `planned`, `forgotten` or `incomplete`.
    pub outcome: String,
    pub erasure: String,
    pub targets: Vec<ForgetTarget>,
    /// Automatic backups taken before the erasure; each is replaced by a new one.
    pub backups_replaced: usize,
    /// Free space the database rewrite and backup replacement need.
    pub required_bytes: u64,
    /// The copies StateEngine knows of; `unlisted` says what it cannot know.
    pub residuals: Vec<ForgetResidual>,
    pub unlisted: String,
    /// Digest of the targets and residual copies shown; `--yes --plan` must repeat it.
    pub plan: String,
    /// The retained, content-free audit fact once cleanup is complete.
    pub completed_event: Option<EventId>,
    pub next: Option<ForgetNext>,
}
impl ErasureReceipt {
    pub fn complete(&self) -> bool {
        self.outcome == "forgotten"
    }
}
/// What no residual list can cover, stated on every plan and receipt.
pub const UNLISTED: &str = "Text already shown or relayed elsewhere, such as a phone channel, a remote device or a provider's own records, is not listed and cannot be erased here.";
/// What a confirmation binds: each target revision and every copy that will remain.
pub fn plan_digest(targets: &[ForgetTarget], residuals: &[ForgetResidual]) -> String {
    use sha2::{Digest, Sha256};
    let mut copies: Vec<_> = residuals
        .iter()
        .map(|r| (&r.custodian, &r.location, &r.reason))
        .collect();
    copies.sort();
    let mut hash = Sha256::new();
    for target in targets {
        hash.update(format!(
            "target\0{}\0{}\0",
            target.event.as_str(),
            target.revision
        ));
    }
    for (custodian, location, reason) in copies {
        hash.update(format!("copy\0{custodian}\0{location}\0{reason}\0"));
    }
    se_types::hex_lower(&hash.finalize())
}
/// The command that confirms this exact plan.
pub fn confirm(input: &StoreForget, plan: &str) -> ForgetNext {
    let mut argv = vec!["se".to_string(), "forget".to_string()];
    for event in &input.events {
        argv.extend(["--event".to_string(), event.as_str().to_string()]);
    }
    argv.extend([
        "--key".to_string(),
        input.idempotency_key.as_str().to_string(),
        "--plan".to_string(),
        plan.to_string(),
        "--yes".to_string(),
    ]);
    ForgetNext {
        text: "Review the plan, then confirm to erase these bodies permanently".into(),
        argv,
    }
}
