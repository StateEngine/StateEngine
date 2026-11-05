//! Read-only, scoped cache queries. No query starts indexing or repairs a cache.
mod body;
mod candidate_sql;
mod candidates;
pub mod changes;
pub mod cursor;
pub mod find;
pub mod hooks;
pub mod impact;
mod impact_edges;
mod impact_files;
mod impact_records;
mod linked;
mod modes;
pub mod outline;
pub mod refs;
mod related;
pub mod resume;
mod rows;
mod source_metadata;
mod target;
mod text;
mod text_files;
mod text_metadata;
mod text_modes;
mod text_rank;
use crate::{
    cache::connection::{CacheConnection, SqlView},
    errors::{AtlasResult, cache_error, capacity},
    model::*,
};
use cursor::{Key, PositionCursor};
use rows::*;
use se_types::code::*;
use se_types::{
    Cursor, Omission, OmissionReason, Page, Read, Sequence, Source, StopReason, Window,
    WindowFields,
};
use serde::Serialize;
use std::{
    num::NonZeroU32,
    time::{Duration, Instant},
};

/// Supplied by core for this verified viewer. Every record and derived count is
/// rechecked against its authoritative event; cached audiences are only hints.
pub trait RecordReader {
    fn read(
        &self,
        project: &se_types::ProjectId,
        viewer: &AtlasPrincipal,
        pointer: &RecordPointer,
        query: Option<&QueryText>,
    ) -> AtlasResult<Read<RecordHit>>;
    fn literal_read(
        &self,
        project: &se_types::ProjectId,
        viewer: &AtlasPrincipal,
        pointer: &RecordPointer,
        query: &QueryText,
    ) -> AtlasResult<Read<RecordHit>>;
    fn body(
        &self,
        project: &se_types::ProjectId,
        viewer: &AtlasPrincipal,
        pointer: &RecordPointer,
        query: Option<&QueryText>,
    ) -> AtlasResult<Read<HitBody>>;
}
pub trait LiveSource: crate::lifecycle::AtlasSource {
    fn open_stream(
        &self,
        path: &RelativePath,
    ) -> AtlasResult<Option<Box<dyn crate::source::SourceFile + '_>>>;
}
impl<A: crate::source::SourceAccess> LiveSource for crate::source::RegisteredSource<A> {
    fn open_stream(
        &self,
        path: &RelativePath,
    ) -> AtlasResult<Option<Box<dyn crate::source::SourceFile + '_>>> {
        self.open(path)
    }
}
pub struct ReaderContext<'a> {
    pub memory: Option<MemoryBudget>,
    pub viewer: AtlasPrincipal,
    pub records: &'a dyn RecordReader,
    pub source: Option<&'a dyn LiveSource>,
    pub hostless: bool,
    pub epoch_retired: bool,
    pub now_unix_ms: Option<i64>,
    /// True only when host maintenance has consumed every relevant committed
    /// record through this read's authoritative snapshot. A new commit clears
    /// it before a reader can observe that commit; hostless/unknown is false.
    pub record_feed_current: bool,
}
#[derive(Clone)]
pub struct QueryReader<'a> {
    pub(crate) compact: Option<(usize, bool)>,
    pub(crate) memory: Option<MemoryBudget>,
    pub(crate) cache: &'a CacheConnection<'a>,
    pub(crate) viewer: AtlasPrincipal,
    pub(crate) records: &'a dyn RecordReader,
    pub(crate) hostless: bool,
    pub(crate) epoch_retired: bool,
    pub(crate) source: Option<&'a dyn LiveSource>,
    pub(crate) now_unix_ms: Option<i64>,
    pub(crate) record_feed_current: bool,
}
impl<'a> QueryReader<'a> {
    pub fn new(cache: &'a CacheConnection<'a>, context: ReaderContext<'a>) -> Self {
        let ReaderContext {
            memory,
            viewer,
            records,
            source,
            hostless,
            epoch_retired,
            now_unix_ms,
            record_feed_current,
        } = context;
        Self {
            compact: None,
            memory,
            cache,
            viewer,
            records,
            hostless,
            epoch_retired,
            source,
            now_unix_ms,
            record_feed_current,
        }
    }
    pub fn summary(&self) -> AtlasResult<IndexSummary> {
        self.cache
            .read(Instant::now() + Duration::from_millis(25), |sql| {
                Ok(self.snapshot(sql)?.index)
            })
    }
    fn snapshot(&self, sql: &SqlView<'_>) -> AtlasResult<Snapshot> {
        let mut stmt = sql.prepare("SELECT index_generation,published_generation,retention_floor,coverage_json,state_json,EXISTS(SELECT 1 FROM records WHERE body_truncated=1) FROM meta WHERE singleton=1")?;
        let mut rows = stmt.query([]).map_err(cache_error)?;
        let row = rows
            .next()
            .map_err(cache_error)?
            .ok_or_else(|| cache_error("missing cache summary"))?;
        let identity = self.cache.identity();
        let mut index = IndexSummary {
            memory: self.memory.clone(),
            project: identity.scope.registration.project.clone(),
            root: identity.scope.registration.root.clone(),
            epoch: Some(identity.epoch.clone()),
            generation: Some(Generation(number(row, 0)?)),
            coverage: json(&get::<String>(row, 3)?)?,
            state: json(&get::<String>(row, 4)?)?,
        };
        let record_body_limited = get::<bool>(row, 5)?;
        for (limited, reason) in [
            (
                self.hostless || self.epoch_retired,
                CoverageReason::StaleSnapshot,
            ),
            (!self.record_feed_current, CoverageReason::RecordFeedLag),
            (record_body_limited, CoverageReason::RecordBodyLimit),
        ] {
            if limited {
                if matches!(index.state, IndexState::Current) {
                    index.state = IndexState::VerificationNeeded { reason };
                }
                if !index.coverage.reasons.contains(&reason) {
                    index.coverage.reasons.push(reason);
                }
            }
        }
        if let Some(reason) = crate::history::limitation(sql)? {
            if matches!(index.state, IndexState::Current) {
                index.state = IndexState::VerificationNeeded { reason };
            }
            if !index.coverage.reasons.contains(&reason) {
                index.coverage.reasons.push(reason);
            }
        }
        Ok(Snapshot {
            index,
            published: Generation(number(row, 1)?),
            floor: Generation(number(row, 2)?),
            epoch_retired: self.epoch_retired,
        })
    }
}
struct Snapshot {
    index: IndexSummary,
    published: Generation,
    floor: Generation,
    epoch_retired: bool,
}
impl Snapshot {
    fn negative_complete(&self) -> bool {
        let c = &self.index.coverage;
        matches!(self.index.state, IndexState::Current)
            && c.discovery_complete
            && c.partial_files == 0
            && c.stale_files == 0
            && c.failed_files == 0
            && c.deferred_files == 0
    }
    fn answer<T>(&self, data: Read<T>, snapshot_advanced: bool) -> Answer<Read<T>> {
        Answer {
            index: self.index.clone(),
            snapshot_advanced,
            epoch_retired: self.epoch_retired,
            data,
        }
    }
    fn unknown<T>(&self, what: &str) -> Answer<Read<T>> {
        self.answer(Read::Unknown { what: what.into() }, false)
    }
}
fn deadline(budget: QueryBudget) -> AtlasResult<Instant> {
    if budget.max_results == 0
        || budget.max_results > 50
        || budget.max_bytes == 0
        || budget.max_bytes > 32768
        || budget.work.is_zero()
        || budget.work > Duration::from_millis(40)
    {
        return Err(se_types::SeError::invalid(
            "Atlas query budget",
            "1..50 results, 1..32768 bytes, 1..40 ms",
        ));
    }
    Ok(Instant::now() + budget.work)
}
fn size(value: &impl Serialize) -> AtlasResult<usize> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value).map_err(cache_error)?;
    Ok(counter.0)
}
fn wire_cursor(cursor: &AtlasCursor) -> AtlasResult<Cursor> {
    Cursor::new(cursor.as_str())
}
fn page<T>(
    snapshot: &Snapshot,
    items: Vec<T>,
    budget: QueryBudget,
    next: Option<AtlasCursor>,
    partial: bool,
    bytes: usize,
    after: Option<&AtlasCursor>,
) -> AtlasResult<Page<T>> {
    let omission = if next.is_some() {
        Omission::Unknown {
            reason: OmissionReason::Limit,
        }
    } else if partial {
        Omission::Unknown {
            reason: OmissionReason::SourceIncomplete,
        }
    } else {
        Omission::None
    };
    let window = Window::new(WindowFields {
        source: Source::Atlas {
            project: snapshot.index.project.clone(),
            root: snapshot.index.root.clone(),
            epoch: snapshot.index.epoch.clone(),
        },
        from: Sequence::ZERO,
        to: Sequence::new(snapshot.index.generation.map_or(1, |g| g.0.max(1)))?,
        start_cursor: after.map(wire_cursor).transpose()?,
        end_cursor: next.as_ref().map(wire_cursor).transpose()?,
        returned: items.len() as u64,
        limit: NonZeroU32::new(u32::from(budget.max_results))
            .ok_or_else(|| cache_error("zero limit"))?,
        bytes: bytes as u64,
        max_bytes: NonZeroU32::new(budget.max_bytes)
            .ok_or_else(|| cache_error("zero byte limit"))?,
        omitted_before: Omission::None,
        omitted_after: omission,
        unreadable: 0,
        stop_reason: if next.is_some() {
            StopReason::ItemLimit
        } else if partial {
            StopReason::Unsupported
        } else {
            StopReason::Exhausted
        },
    })?;
    Page::new(items, window, next.as_ref().map(wire_cursor).transpose()?)
}
fn check_output<T: Serialize>(answer: T, budget: QueryBudget) -> AtlasResult<T> {
    let bytes = size(&answer)?;
    if bytes > budget.max_bytes as usize {
        return Err(capacity(
            "Atlas response bytes",
            bytes as u64,
            u64::from(budget.max_bytes),
        ));
    }
    Ok(answer)
}

impl crate::queries::AtlasQueries for QueryReader<'_> {
    fn find(&self, query: &FindQuery) -> AtlasResult<Answer<Read<SearchResults>>> {
        QueryReader::find(self, query)
    }
    fn refs(&self, query: &RefsQuery) -> AtlasResult<Answer<Read<Page<ReferenceHit>>>> {
        QueryReader::refs(self, query)
    }
    fn impact(&self, query: &ImpactQuery) -> AtlasResult<Answer<Read<Impact>>> {
        QueryReader::impact(self, query)
    }
    fn changes(&self, query: &ChangesQuery) -> AtlasResult<Answer<Read<Page<CodeChange>>>> {
        QueryReader::changes(self, query)
    }
    fn outline(&self, query: &OutlineQuery) -> AtlasResult<Answer<Read<Outline>>> {
        QueryReader::outline(self, query)
    }
    fn resume_code(&self, request: &ResumeRequest) -> AtlasResult<ResumeCode> {
        QueryReader::resume_code(self, request)
    }
    fn status(&self) -> AtlasResult<IndexSummary> {
        self.summary()
    }
}
