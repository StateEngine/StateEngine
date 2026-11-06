//! A real retained source file delayed across the scan allowance must remain
//! reachable from the public query continuation, before the SQL deadline.
use super::*;
use se_atlas::{
    errors::AtlasResult,
    lifecycle::{CaseMode, FileIdentity, SourceChunk, SourceSnapshot, SourceVerification},
    query::{LiveSource, RecordReader},
    source::SourceFile,
};
use std::{
    cell::Cell,
    io::{self, Read, Seek, SeekFrom},
};
struct Delayed<'a> {
    native: &'a dyn LiveSource,
    until: Instant,
    delayed: Cell<bool>,
}
impl AtlasSource for Delayed<'_> {
    fn case_mode(&self) -> CaseMode {
        AtlasSource::case_mode(self.native)
    }
    fn read(&self, path: &RelativePath, budget: ParseBudget) -> AtlasResult<SourceRead> {
        AtlasSource::read(self.native, path, budget)
    }
    fn verify(&self, value: &SourceSnapshot) -> AtlasResult<SourceVerification> {
        self.native.verify(value)
    }
    fn read_chunk(
        &self,
        path: &RelativePath,
        offset: u64,
        max: u32,
    ) -> AtlasResult<Option<SourceChunk>> {
        self.native.read_chunk(path, offset, max)
    }
}
impl LiveSource for Delayed<'_> {
    fn open_stream(&self, path: &RelativePath) -> AtlasResult<Option<Box<dyn SourceFile + '_>>> {
        let Some(inner) = self.native.open_stream(path)? else {
            return Ok(None);
        };
        if path.as_str() != "consumer.rs" {
            return Ok(Some(inner));
        }
        Ok(Some(Box::new(DelayedFile {
            inner,
            until: self.until,
            first: true,
            observed: &self.delayed,
        })))
    }
}
struct DelayedFile<'a> {
    inner: Box<dyn SourceFile + 'a>,
    until: Instant,
    first: bool,
    observed: &'a Cell<bool>,
}
impl Read for DelayedFile<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.first {
            self.first = false;
            self.observed.set(true);
            std::thread::sleep(self.until.saturating_duration_since(Instant::now()));
        }
        self.inner.read(bytes)
    }
}
impl Seek for DelayedFile<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}
impl SourceFile for DelayedFile<'_> {
    fn identity(&self) -> AtlasResult<FileIdentity> {
        self.inner.identity()
    }
    fn validate_path(&self) -> AtlasResult<bool> {
        self.inner.validate_path()
    }
}
pub(super) fn check(
    cache: &CacheConnection<'_>,
    source: &dyn LiveSource,
    records: &dyn RecordReader,
    viewer: &AtlasPrincipal,
    query: &FindQuery,
    regular: &QueryReader<'_>,
) -> Check {
    let delayed = Delayed {
        native: source,
        until: Instant::now() + Duration::from_millis(960),
        delayed: Cell::new(false),
    };
    let reader = QueryReader::new(
        cache,
        ReaderContext {
            memory: None,
            viewer: viewer.clone(),
            records,
            source: Some(&delayed),
            hostless: false,
            epoch_retired: false,
            now_unix_ms: Some(1),
            record_feed_current: true,
        },
    );
    let mut query = query.clone();
    query.kind = SearchKind::Text;
    query.mode = Some(SearchMode::Literal);
    query.scope.paths = vec![
        RelativePath::new("alpha.rs")?,
        RelativePath::new("consumer.rs")?,
    ];
    query.budget = Validate.query_budget(10, 16384)?;
    let answer = reader.find(&query)?;
    assert!(delayed.delayed.get(), "slow native file was not read");
    let page = present(answer.data)?;
    assert!(!page.page.window().complete());
    let next = page
        .page
        .next()
        .ok_or("unfinished source file lost its continuation")?;
    assert!(page.page.items().iter().all(|hit| matches!(&hit.target, HitTarget::Code(code) if code.pointer.path.as_str() == "alpha.rs")));
    query.next = Some(AtlasCursor::new(next.as_str())?);
    let resumed = present(regular.find(&query)?.data)?;
    assert!(resumed.page.items().iter().any(|hit| matches!(&hit.target, HitTarget::Code(code) if code.pointer.path.as_str() == "consumer.rs")), "continuation skipped unfinished file");
    assert!(resumed.page.items().iter().all(|hit| matches!(&hit.target, HitTarget::Code(code) if code.pointer.path.as_str() != "alpha.rs")), "continuation repeated committed file");
    Ok(())
}
