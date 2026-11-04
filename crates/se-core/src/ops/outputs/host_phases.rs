//! Transient, same-call host observations; never part of a durable receipt.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;

/// Success-path wall spans in microseconds. Each blocking span separates
/// admission/scheduling, actual worker time and return-to-executor scheduling.
/// Repeated capture/plan jobs are summed within this exact signal, not globally.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostPhaseTimings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<HostPhaseSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_read: Option<HostPhaseSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub planning: Option<HostPhaseSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission: Option<HostPhaseSpan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_wait_us: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation: Option<HostPhaseSpan>,
    /// Decoded request admission to pre-encoding; excludes wire read, encoding
    /// and reply write. Store measurements overlap these spans: do not add them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_to_encode_us: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostPhaseSpan {
    pub jobs: NonZeroU32,
    pub queue_us: u64,
    pub work_us: u64,
    pub resume_us: u64,
}
impl HostPhaseTimings {
    /// Accumulate observed fragments of this same signal; None stays unmeasured.
    pub fn merge(&mut self, other: Self) {
        for (target, source) in [
            (&mut self.admission, other.admission),
            (&mut self.capture_read, other.capture_read),
            (&mut self.planning, other.planning),
            (&mut self.submission, other.submission),
            (&mut self.continuation, other.continuation),
        ] {
            if let Some(source) = source {
                match target {
                    Some(value) => {
                        value.jobs = value.jobs.saturating_add(source.jobs.get());
                        value.queue_us = value.queue_us.saturating_add(source.queue_us);
                        value.work_us = value.work_us.saturating_add(source.work_us);
                        value.resume_us = value.resume_us.saturating_add(source.resume_us);
                    }
                    None => *target = Some(source),
                }
            }
        }
        if let Some(wait) = other.completion_wait_us {
            self.completion_wait_us =
                Some(self.completion_wait_us.unwrap_or(0).saturating_add(wait));
        }
    }
}
