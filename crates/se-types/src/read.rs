use crate::{
    AtlasRootId, Cursor, ErrorBody, HostEpoch, IndexEpochId, ProjectId, Result, SeError, Sequence,
    StoreId, UnixMicros,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::num::{NonZeroU32, NonZeroU64};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    Store {
        store: StoreId,
        project: Option<ProjectId>,
    },
    Host {
        epoch: HostEpoch,
    },
    /// Rebuildable code cache, never the authority for history.
    Atlas {
        project: ProjectId,
        root: AtlasRootId,
        epoch: Option<IndexEpochId>,
    },
    Configuration {
        location: String,
    },
}
impl Source {
    pub fn describe(&self) -> String {
        match self {
            Self::Store { store, project } => format!(
                "store {store}, project {}",
                project
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "all".into())
            ),
            Self::Host { epoch } => format!(
                "host pid {}, epoch {}",
                epoch.owner.fields().pid,
                epoch.generation.get()
            ),
            Self::Configuration { location } => location.clone(),
            Self::Atlas {
                project,
                root,
                epoch,
            } => format!(
                "atlas.db project {project}, root {root}, epoch {}",
                epoch
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unverified".into())
            ),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Checked {
    pub source: Source,
    pub snapshot_to: Option<Cursor>,
    pub observed_at: UnixMicros,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<Box<ErrorBody>>,
    },
    Unknown {
        what: String,
    },
}
impl<T> Read<T> {
    pub fn absent(checked: Checked) -> Self {
        Self::Absent {
            checked: format!(
                "{} at {}, snapshot {}",
                checked.source.describe(),
                checked.observed_at,
                checked
                    .snapshot_to
                    .map(|position| position.to_string())
                    .unwrap_or_else(|| "unverified".into())
            ),
        }
    }
    pub fn unreadable(source: Source, error: ErrorBody) -> Self {
        Self::Unreadable {
            source: source.describe(),
            reason: error.message(),
            error: Some(Box::new(error)),
        }
    }
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> Read<U> {
        match self {
            Self::Present { value } => Read::Present { value: f(value) },
            Self::Absent { checked } => Read::Absent { checked },
            Self::Unreadable {
                source,
                reason,
                error,
            } => Read::Unreadable {
                source,
                reason,
                error,
            },
            Self::Unknown { what } => Read::Unknown { what },
        }
    }
    pub fn as_ref(&self) -> Read<&T> {
        match self {
            Self::Present { value } => Read::Present { value },
            Self::Absent { checked } => Read::Absent {
                checked: checked.clone(),
            },
            Self::Unreadable {
                source,
                reason,
                error,
            } => Read::Unreadable {
                source: source.clone(),
                reason: reason.clone(),
                error: error.clone(),
            },
            Self::Unknown { what } => Read::Unknown { what: what.clone() },
        }
    }
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Present { .. } | Self::Absent { .. } => 0,
            Self::Unreadable { .. } => 3,
            Self::Unknown { .. } => 4,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OmissionReason {
    Limit,
    Budget,
    Unreadable,
    SourceIncomplete,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Omitted {
    pub count: Option<u64>,
    pub reason: Option<OmissionReason>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
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
/// Store snapshot bounds are (from, to]: exclusive from, inclusive to.
/// bytes is producer accounting; foundation does not serialize items to recount it.
/// Internal accounting only; public Window serialization uses opaque cursors.
pub struct WindowFields {
    pub source: Source,
    pub from: Sequence,
    pub to: Sequence,
    pub start_cursor: Option<Cursor>,
    pub end_cursor: Option<Cursor>,
    pub returned: u64,
    pub limit: NonZeroU32,
    pub bytes: u64,
    pub max_bytes: NonZeroU32,
    pub omitted_before: Omission,
    pub omitted_after: Omission,
    pub unreadable: u64,
    pub stop_reason: StopReason,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "WindowWire", into = "WindowWire")]
pub struct Window {
    fields: Option<WindowFields>,
    from: Option<Cursor>,
    to: Option<Cursor>,
    limit: NonZeroU32,
    complete: bool,
    omitted: Omitted,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
struct WindowWire {
    from: Option<Cursor>,
    to: Option<Cursor>,
    limit: u32,
    complete: bool,
    omitted: Omitted,
}
fn omission_rank(reason: OmissionReason) -> u8 {
    match reason {
        OmissionReason::Limit => 0,
        OmissionReason::Budget => 1,
        OmissionReason::SourceIncomplete => 2,
        OmissionReason::Unreadable => 3,
    }
}
fn combine(before: &Omission, after: &Omission) -> Result<Omitted> {
    let mut count = Some(0u64);
    let mut reason = None;
    for omission in [before, after] {
        let (n, r) = match omission {
            Omission::None => continue,
            Omission::Known { count, reason } => (Some(count.get()), *reason),
            Omission::Unknown { reason } => (None, *reason),
        };
        count = match (count, n) {
            (Some(a), Some(b)) => Some(
                a.checked_add(b)
                    .ok_or_else(|| SeError::invalid("omitted", "a nonoverflowing count"))?,
            ),
            _ => None,
        };
        if reason.is_none_or(|current| omission_rank(r) > omission_rank(current)) {
            reason = Some(r);
        }
    }
    Ok(Omitted { count, reason })
}
impl Window {
    pub fn new(fields: WindowFields) -> Result<Self> {
        if fields.from > fields.to
            || fields.returned > u64::from(fields.limit.get())
            || fields.bytes > u64::from(fields.max_bytes.get())
            || (fields.from == fields.to && fields.returned != 0)
        {
            return Err(SeError::invalid(
                "window",
                "ordered snapshot bounds, item and byte limits",
            ));
        }
        let mut omitted = combine(&fields.omitted_before, &fields.omitted_after)?;
        if fields.unreadable > 0 {
            omitted.count = if omitted.count == Some(0) {
                Some(fields.unreadable)
            } else {
                None
            };
            omitted.reason = Some(OmissionReason::Unreadable);
        }
        if fields.stop_reason != StopReason::Exhausted && omitted.reason.is_none() {
            return Err(SeError::invalid(
                "window omitted",
                "a stated omission for a non-exhausted read",
            ));
        }
        let complete = omitted.reason.is_none()
            && fields.unreadable == 0
            && fields.stop_reason == StopReason::Exhausted;
        Ok(Self {
            from: fields.start_cursor.clone(),
            to: fields.end_cursor.clone(),
            limit: fields.limit,
            fields: Some(fields),
            complete,
            omitted,
        })
    }
    /// Detailed producer accounting is absent in a minimal public wire Window.
    pub fn fields(&self) -> Option<&WindowFields> {
        self.fields.as_ref()
    }
    pub const fn complete(&self) -> bool {
        self.complete
    }
    pub fn omitted(&self) -> &Omitted {
        &self.omitted
    }
    pub fn exit_code(&self, require_all: bool) -> u8 {
        if (require_all && !self.complete)
            || matches!(
                self.omitted.reason,
                Some(OmissionReason::Unreadable | OmissionReason::SourceIncomplete)
            )
        {
            2
        } else {
            0
        }
    }
}
impl From<Window> for WindowWire {
    fn from(value: Window) -> Self {
        Self {
            from: value.from,
            to: value.to,
            limit: value.limit.get(),
            complete: value.complete,
            omitted: value.omitted,
        }
    }
}
impl TryFrom<WindowWire> for Window {
    type Error = SeError;
    fn try_from(value: WindowWire) -> Result<Self> {
        let limit = NonZeroU32::new(value.limit)
            .ok_or_else(|| SeError::invalid("window limit", "nonzero"))?;
        if (value.complete && (value.omitted.count != Some(0) || value.omitted.reason.is_some()))
            || (!value.complete
                && (value.omitted.reason.is_none() || value.omitted.count == Some(0)))
        {
            return Err(SeError::invalid(
                "window omitted",
                "consistent complete/count/reason",
            ));
        }
        Ok(Self {
            fields: None,
            from: value.from,
            to: value.to,
            limit,
            complete: value.complete,
            omitted: value.omitted,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "PageWire<T>", bound(deserialize = "T: Deserialize<'de>"))]
pub struct Page<T> {
    items: Vec<T>,
    window: Window,
    next: Option<Cursor>,
}
#[derive(Deserialize, JsonSchema)]
struct PageWire<T> {
    items: Vec<T>,
    window: Window,
    next: Option<Cursor>,
}
impl<T> Page<T> {
    pub fn new(items: Vec<T>, window: Window, next: Option<Cursor>) -> Result<Self> {
        let needs_continuation = window.fields.as_ref().is_some_and(|fields| {
            matches!(
                fields.omitted_after,
                Omission::Known { .. }
                    | Omission::Unknown {
                        reason: OmissionReason::Limit | OmissionReason::Budget
                    }
            )
        });
        let wire_more = window.fields.is_none()
            && matches!(
                window.omitted.reason,
                Some(OmissionReason::Limit | OmissionReason::Budget)
            );
        if items.len() > window.limit.get() as usize
            || window
                .fields
                .as_ref()
                .is_some_and(|fields| items.len() as u64 != fields.returned)
            || (window.complete && next.is_some())
            || (next.is_none() && (needs_continuation || wire_more))
            || (next.is_some() && next == window.from)
        {
            return Err(SeError::invalid(
                "page",
                "matching count and a progressing continuation for remaining rows",
            ));
        }
        Ok(Self {
            items,
            window,
            next,
        })
    }
}
impl<T> Page<T> {
    pub fn items(&self) -> &[T] {
        &self.items
    }
    pub fn window(&self) -> &Window {
        &self.window
    }
    pub fn next(&self) -> Option<&Cursor> {
        self.next.as_ref()
    }
    pub fn into_items(self) -> Vec<T> {
        self.items
    }
}
impl<T> TryFrom<PageWire<T>> for Page<T> {
    type Error = SeError;
    fn try_from(value: PageWire<T>) -> Result<Self> {
        Self::new(value.items, value.window, value.next)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PageRequest {
    pub after: Option<Cursor>,
    pub limit: NonZeroU32,
    pub max_bytes: NonZeroU32,
}
