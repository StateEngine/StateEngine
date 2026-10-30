use crate::{
    Cursor, Generation, HostEpoch, ProjectId, Result, SeError, Sequence, StoreId, UnixMillis,
};
use std::num::{NonZeroU32, NonZeroU64};

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
pub struct Checked {
    pub source: Source,
    pub snapshot_to: Option<Sequence>,
    pub observed_at: UnixMillis,
}
#[derive(Debug)]
pub enum Read<T> {
    Present { value: T },
    Absent { checked: Checked },
    Unreadable { source: Source, error: SeError },
    Unknown { what: String },
}
pub enum ReadRef<'a, T> {
    Present {
        value: &'a T,
    },
    Absent {
        checked: &'a Checked,
    },
    Unreadable {
        source: &'a Source,
        error: &'a SeError,
    },
    Unknown {
        what: &'a str,
    },
}
pub trait ReadValue<T> {
    fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Read<U>;
    fn as_ref(&self) -> ReadRef<'_, T>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OmissionReason {
    Limit,
    Bytes,
    BeforeCursor,
    Unreadable,
    Unsupported,
    Cancelled,
    Deadline,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Omission {
    None,
    Known {
        count: NonZeroU64,
        reason: OmissionReason,
    },
    Unknown {
        reason: OmissionReason,
    },
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
pub struct WindowFields {
    pub source: Source,
    pub from: Sequence,
    pub to: Sequence,
    pub returned: u64,
    pub limit: NonZeroU32,
    pub bytes: u64,
    pub omitted_before: Omission,
    pub omitted_after: Omission,
    pub unreadable: u64,
    pub stop_reason: StopReason,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Window {
    fields: WindowFields,
    complete: bool,
}
pub trait WindowValue: Sized {
    fn new(fields: WindowFields) -> Result<Self>;
    fn fields(&self) -> &WindowFields;
    fn complete(&self) -> bool;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    items: Vec<T>,
    window: Window,
    next: Option<Cursor>,
}
pub trait PageValue<T>: Sized {
    fn new(items: Vec<T>, window: Window, next: Option<Cursor>) -> Result<Self>;
    fn items(&self) -> &[T];
    fn window(&self) -> &Window;
    fn next(&self) -> Option<&Cursor>;
    fn into_items(self) -> Vec<T>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageRequest {
    pub after: Option<Cursor>,
    pub limit: NonZeroU32,
    pub max_bytes: NonZeroU32,
}
/// Durable cursor origin and audience, decoded only inside the store codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CursorScope {
    pub store: StoreId,
    pub project: ProjectId,
    pub audience: crate::AgentId,
    pub generation: Option<Generation>,
    pub query_sha256: crate::Sha256,
}
