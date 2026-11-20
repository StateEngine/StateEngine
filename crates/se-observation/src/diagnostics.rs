//! Extensible same-call observations, separate from immutable receipts.
use super::host_phases::HostPhaseTimings;
use schemars::JsonSchema;
use se_types::EventId;
use serde::{Deserialize, Serialize};

/// Host measurements for the exact completed request, outside its immutable
/// semantic receipt. There is no diagnostics object on a direct write.
/// Readers ignore future top-level observations; required measurements and
/// nested timing/capture records retain their existing closed validation.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OutputDiagnostics {
    pub write_timings: ReceiptWriteTimings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_phases: Option<HostPhaseTimings>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capture_commits: Vec<CaptureCommitDiagnostics>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureCommitDiagnostics {
    pub event_id: EventId,
    pub write_timings: ReceiptWriteTimings,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiptWriteTimings {
    pub queue_ms: f64,
    pub transaction_ms: f64,
    pub commit_call_ms: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_ms: Option<f64>,
    pub durability: WriteDurability,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WriteDurability {
    Full,
    Normal,
}
impl ReceiptWriteTimings {
    pub fn validate(&self) -> se_types::Result<()> {
        if [self.queue_ms, self.transaction_ms, self.commit_call_ms]
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
            || self
                .checkpoint_ms
                .is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            return Err(se_types::SeError::invalid(
                "write timings",
                "three finite non-negative measured millisecond values and an optional measured checkpoint",
            ));
        }
        Ok(())
    }
    pub fn from_store(timings: &se_store::WriteTimings) -> Self {
        Self {
            queue_ms: timings.queue.as_secs_f64() * 1000.0,
            transaction_ms: timings.transaction.as_secs_f64() * 1000.0,
            commit_call_ms: timings.commit_sync.as_secs_f64() * 1000.0,
            checkpoint_ms: timings.checkpoint.map(|value| value.as_secs_f64() * 1000.0),
            durability: match timings.durability {
                se_store::CommitDurability::Full => WriteDurability::Full,
                se_store::CommitDurability::Normal => WriteDurability::Normal,
            },
        }
    }
}
