use crate::{Cursor, ErrorBody, EventId, IdempotencyKey, Result, SeError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EventRef {
    pub id: EventId,
    pub position: Cursor,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EffectStatus {
    NotRequired,
    Pending,
    Witnessed { witness: EventRef },
    Failed { error: Box<ErrorBody> },
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Commit<T> {
    pub event_id: EventId,
    pub position: Cursor,
    pub idempotency_key: IdempotencyKey,
    pub value: T,
    pub effects: EffectStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PendingReason {
    Queued,
    AwaitingWitness,
    Recovering,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    try_from = "ReceiptWire<T>",
    bound(deserialize = "T: Deserialize<'de>")
)]
pub enum Receipt<T> {
    Committed {
        #[serde(flatten)]
        commit: Commit<T>,
    },
    Replayed {
        #[serde(flatten)]
        original: Commit<T>,
    },
    Refused {
        error: Box<ErrorBody>,
    },
    Pending {
        cause: PendingReason,
        event_id: Option<EventId>,
        idempotency_key: IdempotencyKey,
    },
}
impl<T> Receipt<T> {
    pub fn committed_value(&self) -> Option<&T> {
        match self {
            Self::Committed { commit } | Self::Replayed { original: commit } => Some(&commit.value),
            _ => None,
        }
    }
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Committed { commit } | Self::Replayed { original: commit } => {
                // The store proves ordering in the authorized cursor scope;
                // opaque cursor spellings have no chronological ordering here.
                if let EffectStatus::Witnessed { witness } = &commit.effects
                    && (witness.id == commit.event_id || witness.position == commit.position)
                {
                    return Err(SeError::invalid(
                        "effect witness",
                        "an outside event after the commit",
                    ));
                }
            }
            Self::Pending { .. } | Self::Refused { .. } => (),
        }
        Ok(())
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ReceiptWire<T> {
    Committed {
        #[serde(flatten)]
        commit: Commit<T>,
    },
    Replayed {
        #[serde(flatten)]
        original: Commit<T>,
    },
    Refused {
        error: Box<ErrorBody>,
    },
    Pending {
        cause: PendingReason,
        event_id: Option<EventId>,
        idempotency_key: IdempotencyKey,
    },
}
impl<T> TryFrom<ReceiptWire<T>> for Receipt<T> {
    type Error = SeError;
    fn try_from(value: ReceiptWire<T>) -> Result<Self> {
        let receipt = match value {
            ReceiptWire::Committed { commit } => Self::Committed { commit },
            ReceiptWire::Replayed { original } => Self::Replayed { original },
            ReceiptWire::Refused { error } => Self::Refused { error },
            ReceiptWire::Pending {
                cause,
                event_id,
                idempotency_key,
            } => Self::Pending {
                cause,
                event_id,
                idempotency_key,
            },
        };
        receipt.validate()?;
        Ok(receipt)
    }
}
