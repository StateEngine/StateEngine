//! Receive observation belongs to this host run, never to provider retention.
//! Restart loses observation history and explicitly exposes that unknown span.
#[cfg(feature = "listener")]
use super::ConnectionHealth;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiveCoverage {
    pub observed_since_us: Option<i64>,
    pub last_successful_poll_at_us: Option<i64>,
    /// Possible loss of unsaved input, never a missing-message count or receipt.
    pub possible_gap: ReceiveGap,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiveGap {
    /// None means the earlier bound is unknown, including after host restart.
    pub from_us: Option<i64>,
    pub through_us: i64,
    pub reason: ReceiveGapReason,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiveGapReason {
    UnobservedBeforeThisRun,
    ReceiverUnavailable,
    ReceiverStopped,
}
#[cfg(feature = "listener")]
impl ReceiveCoverage {
    pub(super) fn unobserved(at: i64) -> Self {
        Self {
            observed_since_us: None,
            last_successful_poll_at_us: None,
            possible_gap: ReceiveGap {
                from_us: None,
                through_us: at,
                reason: ReceiveGapReason::UnobservedBeforeThisRun,
            },
        }
    }
    pub(super) fn stopped(mut self, at: i64) -> Self {
        self.possible_gap = ReceiveGap {
            from_us: self.last_successful_poll_at_us,
            through_us: at,
            reason: ReceiveGapReason::ReceiverStopped,
        };
        self
    }
}
#[cfg(feature = "listener")]
#[derive(Clone)]
pub(super) struct ReceiverObservation {
    pub health: ConnectionHealth,
    pub coverage: ReceiveCoverage,
}
#[cfg(feature = "listener")]
impl ReceiverObservation {
    pub fn observe(&mut self, health: ConnectionHealth, at: i64) {
        let recovering = !matches!(self.health, ConnectionHealth::Connected { .. });
        self.coverage.observed_since_us.get_or_insert(at);
        match &health {
            ConnectionHealth::Connected {
                last_poll_at_us: Some(success),
            } => {
                if recovering || self.coverage.last_successful_poll_at_us.is_none() {
                    self.coverage.possible_gap.through_us = *success;
                }
                self.coverage.last_successful_poll_at_us = Some(*success);
            }
            _ => {
                if !recovering
                    || self.coverage.possible_gap.reason != ReceiveGapReason::ReceiverUnavailable
                {
                    self.coverage.possible_gap.from_us = self.coverage.last_successful_poll_at_us;
                }
                self.coverage.possible_gap.through_us = at;
                self.coverage.possible_gap.reason = ReceiveGapReason::ReceiverUnavailable;
            }
        }
        self.health = health;
    }
}

#[cfg(all(test, feature = "listener"))]
#[path = "coverage_tests.rs"]
mod tests;
