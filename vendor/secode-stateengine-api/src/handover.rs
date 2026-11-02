// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    Cancellation, EventRef, Generation, HoldReceipt, HostEpoch, HostEventRef, HostFuture,
    IdempotencyKey, Read, Sha256, TransferId,
};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoverDestination {
    Standalone,
    EmbeddedSecode { epoch: HostEpoch },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoverRequest {
    pub source: HostEpoch,
    pub destination: HandoverDestination,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoverPlan {
    pub transfer: TransferId,
    pub source: HostEpoch,
    pub destination: HandoverDestination,
    pub successor: HostEpoch,
    pub source_generation: Generation,
    pub successor_generation: Generation,
    pub idempotency_key: IdempotencyKey,
}
#[derive(Clone, Debug)]
pub struct HandoverOptions {
    pub timeout: Duration,
    pub cancellation: Arc<dyn Cancellation>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeQueueId(pub String);
/// Receipt for SE Code's own protected queue, never its input bodies or a second queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeQueueCheckpoint {
    pub plan: HandoverPlan,
    pub owner: HostEpoch,
    pub queue: NativeQueueId,
    pub committed: HostEventRef,
    pub sha256: Sha256,
    pub pending: u64,
    pub held: Vec<HoldReceipt>,
    pub quiescence_witnessed: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandoverResolution {
    Finished { ownership: EventRef },
    Aborted { ownership: EventRef },
    Recovered { ownership: EventRef },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeQueueSettlement {
    pub checkpoint: NativeQueueCheckpoint,
    pub resolution: HandoverResolution,
    pub committed: HostEventRef,
    pub settled_by: HostEpoch,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeQueueHandoverState {
    Frozen(Box<NativeQueueCheckpoint>),
    Settled(Box<NativeQueueSettlement>),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandoverReport {
    pub plan: HandoverPlan,
    pub queue: NativeQueueSettlement,
}
/// Native queue control retained independently of ordinary generation callbacks.
/// A fresh epoch may recover the same queue's transfer-keyed fence; ownership
/// phase verification belongs to the factory, not this permissive adapter.
pub trait HandoverServices: Send + Sync {
    /// Non-blocking snapshots of this adapter's actual epoch and queue incarnation.
    fn epoch(&self) -> HostEpoch;
    fn queue(&self) -> NativeQueueId;
    fn freeze_queue<'a>(
        &'a self,
        plan: &'a HandoverPlan,
        options: HandoverOptions,
    ) -> HostFuture<'a, NativeQueueCheckpoint>;
    /// Indexed lookup recovers the original plan even before Prepared exists.
    fn queue_state_for_request<'a>(
        &'a self,
        key: &'a IdempotencyKey,
        options: HandoverOptions,
    ) -> HostFuture<'a, Read<NativeQueueHandoverState>>;
    fn queue_state<'a>(
        &'a self,
        transfer: &'a TransferId,
        options: HandoverOptions,
    ) -> HostFuture<'a, Read<NativeQueueHandoverState>>;
    fn settle_queue<'a>(
        &'a self,
        checkpoint: &'a NativeQueueCheckpoint,
        resolution: HandoverResolution,
        options: HandoverOptions,
    ) -> HostFuture<'a, NativeQueueSettlement>;
}
