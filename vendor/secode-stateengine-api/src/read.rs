// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{ApiError, Cursor, EventId, HostEpoch, IdempotencyKey, ProjectId, StoreId};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Source {
    Store {
        store: StoreId,
        project: Option<ProjectId>,
    },
    Host {
        epoch: HostEpoch,
    },
    Configuration {
        location: String,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Read<T> {
    Present {
        value: T,
    },
    Absent {
        checked: String,
    },
    Unreadable {
        source: String,
        reason: String,
        error: Option<ApiError>,
    },
    Unknown {
        what: String,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OmissionReason {
    Limit,
    Budget,
    Unreadable,
    SourceIncomplete,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Omission {
    None,
    Known { count: u64, reason: OmissionReason },
    Unknown { reason: OmissionReason },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopReason {
    Exhausted,
    ItemLimit,
    ByteLimit,
    Unreadable,
    Cancelled,
    Deadline,
    Unsupported,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Window {
    pub source: Source,
    pub start_cursor: Option<Cursor>,
    pub end_cursor: Option<Cursor>,
    pub returned: u64,
    pub limit: u32,
    pub bytes: u64,
    pub max_bytes: u32,
    pub omitted_before: Omission,
    pub omitted_after: Omission,
    pub unreadable: u64,
    pub stop_reason: StopReason,
    pub complete: bool,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub window: Window,
    pub next: Option<Cursor>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageRequest {
    pub after: Option<Cursor>,
    pub limit: u32,
    pub max_bytes: u32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventRef {
    pub id: EventId,
    pub position: Cursor,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectStatus {
    NotRequired,
    Pending,
    Witnessed { witness: EventRef },
    Failed { error: ApiError },
}
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Receipt<T> {
    Committed {
        commit: Commit<T>,
    },
    Replayed {
        original: Commit<T>,
    },
    Refused {
        error: ApiError,
    },
    Pending {
        cause: PendingReason,
        event_id: Option<EventId>,
        idempotency_key: IdempotencyKey,
    },
}
