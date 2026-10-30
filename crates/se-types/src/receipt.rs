use crate::{EventId, IdempotencyKey, Result, SeError, Sequence};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRef {
    pub id: EventId,
    pub sequence: Sequence,
}
#[derive(Debug)]
pub enum EffectStatus {
    NotRequired,
    Pending,
    Witnessed { witness: EventRef },
    Failed { error: SeError },
}
#[derive(Debug)]
pub struct Commit<T> {
    pub event: EventRef,
    pub idempotency_key: IdempotencyKey,
    pub value: T,
    pub effects: EffectStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingReason {
    Queued,
    AwaitingWitness,
    Recovering,
}
#[derive(Debug)]
pub enum Receipt<T> {
    Committed {
        commit: Commit<T>,
    },
    Replayed {
        original: Commit<T>,
    },
    Refused {
        error: SeError,
    },
    Pending {
        cause: PendingReason,
        event: Option<EventRef>,
        idempotency_key: IdempotencyKey,
    },
}
pub trait ReceiptValue<T> {
    fn committed_value(&self) -> Option<&T>;
    fn validate(&self) -> Result<()>;
}
