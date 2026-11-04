//! Queued provider input is evidence with native provenance, never a claim
//! that removal means cancellation or that queueing means model delivery.
use super::transcript::Position;
use schemars::JsonSchema;
use se_types::{Body, Result, SeError};
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Unresolved,
    Dequeued,
    Removed,
    Delivered,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Delivery {
    Unresolved,
    NativeReason,
    UserRecord,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueuedInput {
    pub enqueue: Position,
    pub outcome: Outcome,
    pub reason: Option<String>,
    pub delivery: Delivery,
    pub outcome_position: Option<Position>,
    /// Original text is preserved on enqueue. Later rows link to that evidence.
    pub text: Option<String>,
}
impl QueuedInput {
    pub fn validate(&self) -> Result<()> {
        let position = |p: &Position| p.length > 0 && p.offset.checked_add(p.length).is_some();
        let reason_delivered = matches!(
            self.reason.as_deref(),
            Some("absorbed_mid_turn" | "delivered_to_agent")
        );
        if !position(&self.enqueue)
            || self
                .reason
                .as_ref()
                .is_some_and(|s| s.len() > 4096 || s.contains('\0'))
            || match self.outcome {
                Outcome::Unresolved => {
                    self.outcome_position.is_some()
                        || self.reason.is_some()
                        || self.delivery != Delivery::Unresolved
                        || self.text.as_ref().is_none_or(|s| {
                            s.is_empty() || s.len() > Body::MAX_BYTES || s.contains('\0')
                        })
                }
                Outcome::Dequeued | Outcome::Removed | Outcome::Delivered => {
                    self.text.is_some()
                        || self
                            .outcome_position
                            .as_ref()
                            .is_none_or(|p| !position(p) || p.offset < self.enqueue.offset)
                        || match self.outcome {
                            Outcome::Delivered => {
                                self.delivery != Delivery::UserRecord || self.reason.is_some()
                            }
                            Outcome::Dequeued => {
                                self.delivery != Delivery::Unresolved || self.reason.is_some()
                            }
                            Outcome::Removed => {
                                (self.delivery == Delivery::NativeReason) != reason_delivered
                                    || self.delivery == Delivery::UserRecord
                            }
                            _ => false,
                        }
                }
            }
        {
            return Err(SeError::invalid(
                "queued input provenance",
                "original enqueue text, observed native operations/reasons, and separately witnessed delivery",
            ));
        }
        Ok(())
    }
}
