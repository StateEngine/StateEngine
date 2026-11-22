//! Live-source scans keep their invariants across read chunks, shared searcher
//! state, 256-row file batches, and the per-match ranking statements.
use super::*;
use se_atlas::{
    errors::AtlasResult,
    lifecycle::{CaseMode, FileIdentity, SourceChunk, SourceSnapshot, SourceVerification},
    query::{LiveSource, RecordReader},
    source::SourceFile,
};
use std::io::{self, Read, Seek, SeekFrom};
type Source = se_atlas::source::RegisteredSource<NativeAtlasSource>;
/// Hands the searcher tiny reads so multi-byte characters straddle chunks.
struct Chunked<'a> {
    native: &'a dyn LiveSource,
}
impl AtlasSource for Chunked<'_> {
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
impl LiveSource for Chunked<'_> {
    fn open_stream(&self, path: &RelativePath) -> AtlasResult<Option<Box<dyn SourceFile + '_>>> {
        let Some(inner) = self.native.open_stream(path)? else {
            return Ok(None);
        };
        let name = path.as_str().rsplit('/').next().unwrap_or_default();
        let limit = if name.starts_with("a_") { 1 } else { 7 };
        Ok(Some(Box::new(ChunkedFile { inner, limit })))
    }
}
struct ChunkedFile<'a> {
    inner: Box<dyn SourceFile + 'a>,
    limit: usize,
}
impl Read for ChunkedFile<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let limit = bytes.len().min(self.limit);
        self.inner.read(&mut bytes[..limit])
    }
}
impl Seek for ChunkedFile<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}
impl SourceFile for ChunkedFile<'_> {
    fn identity(&self) -> AtlasResult<FileIdentity> {
        self.inner.identity()
    }
    fn validate_path(&self) -> AtlasResult<bool> {
        self.inner.validate_path()
    }
}
fn key<const N: usize>(row: i64) -> [u8; N] {
    let mut key = [0u8; N];
    key[..8].copy_from_slice(&row.to_be_bytes());
    key
}
/// Writes each file and registers it as an unparsed text row.
fn register(
    cache: &mut CacheConnection<'_>,
    root: &std::path::Path,
    files: &[(i64, String, Vec<u8>)],
) -> Check {
    for (_, path, bytes) in files {
        fs::write(root.join(path), bytes)?;
    }
    let deferred = serde_json::to_string(&FileCoverage::Deferred {
        reason: CoverageReason::SourceBytesLimit,
    })?;
    cache.write(4_000_000, end(), |sql| {
        for (row, path, bytes) in files {
            sql.prepare("INSERT INTO files(id,key,path,path_key,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?3,?3,?4,x'01',?5,1,0,0)")?
                .execute((row, key::<16>(*row).as_slice(), path, bytes.len() as i64, &deferred))
                .map_err(fail)?;
        }
        Ok(())
    })?;
    Ok(())
}
fn paths(results: &SearchResults) -> Vec<String> {
    results
        .page
        .items()
        .iter()
        .filter_map(|hit| match &hit.target {
            HitTarget::Code(code) => Some(code.pointer.path.as_str().to_owned()),
            _ => None,
        })
        .collect()
}
fn text_query(
    query: &FindQuery,
    needle: &str,
    scope: &str,
) -> Result<FindQuery, Box<dyn std::error::Error>> {
    let mut query = query.clone();
    query.kind = SearchKind::Text;
    query.mode = Some(SearchMode::Literal);
    query.query = QueryText::new(needle)?;
    query.scope.paths = vec![RelativePath::new(scope)?];
    query.budget = Validate.query_budget(10, 16384)?;
    query.next = None;
    Ok(query)
}
/// Split and invalid UTF-8 are told apart, and a binary, non-UTF-8, or
/// line-limited file never leaves the shared searcher unable to match the next file.
pub(super) fn encodings(
    cache: &mut CacheConnection<'_>,
    viewer: &AtlasPrincipal,
    records: &dyn RecordReader,
    source: &Source,
    query: &FindQuery,
) -> Check {
    let root = &source.scope.registration.canonical_source_root;
    fs::create_dir(root.join("utf8"))?;
    let valid = "é€😀 utf8_needle 😀€é\n".repeat(3) + "ß😀€\n";
    let long = format!("{} utf8_needle\n", "x".repeat(40_000));
    let files: Vec<(i64, String, Vec<u8>)> = [
        ("a_valid.txt", valid.into_bytes()),
        ("b_invalid.txt", b"\xe2\x82 utf8_needle \xff\n".to_vec()),
        ("c_after_invalid.txt", "€ utf8_needle 😀\n".into()),
        ("d_truncated.txt", b"utf8_needle \xf0\x9f\x98".to_vec()),
        ("e_after_truncated.txt", "utf8_needle é\n".into()),
        ("f_binary.txt", b"utf8_needle\0\n".to_vec()),
        ("g_after_binary.txt", "😀utf8_needle\n".into()),
        ("h_long_line.txt", long.into_bytes()),
        ("i_after_long_line.txt", "utf8_needle€\n".into()),
    ]
    .into_iter()
    .enumerate()
    .map(|(id, (name, bytes))| (2_000 + id as i64, format!("utf8/{name}"), bytes))
    .collect();
    register(cache, root, &files)?;
    let chunked = Chunked { native: source };
    let mut reader = QueryReader::new(
        cache,
        ReaderContext {
            memory: None,
            viewer: viewer.clone(),
            records,
            source: Some(&chunked),
            hostless: false,
            epoch_retired: false,
            now_unix_ms: Some(1),
            record_feed_current: true,
        },
    );
    let results = present(
        reader
            .find(&text_query(query, "utf8_needle", "utf8")?)?
            .data,
    )?;
    let mut found = paths(&results);
    found.sort();
    found.dedup();
    assert_eq!(
        found,
        [
            "utf8/a_valid.txt",
            "utf8/c_after_invalid.txt",
            "utf8/e_after_truncated.txt",
            "utf8/g_after_binary.txt",
            "utf8/i_after_long_line.txt",
        ],
        "split UTF-8 was rejected, invalid UTF-8 matched, or a reused searcher lost a file"
    );
    let stats = results.text.as_ref().ok_or("missing text scan counts")?;
    assert_eq!(stats.scanned_files, 9);
    assert_eq!(
        stats.non_utf8_files, 2,
        "a character split across reads was counted as invalid, or invalid bytes were accepted"
    );
    assert_eq!(stats.binary_files, 1);
    assert_eq!(stats.line_limited_files, 1);
    assert_eq!(stats.matching_files, 5);
    Ok(())
}
/// The path walk crosses its 256-row SQL batch without losing or repeating
/// a file, both inside one scan and through cursor resumes.
pub(super) fn batches(
    cache: &mut CacheConnection<'_>,
    viewer: &AtlasPrincipal,
    records: &dyn RecordReader,
    source: &Source,
    feed_current: bool,
    query: &FindQuery,
) -> Check {
    let root = &source.scope.registration.canonical_source_root;
    fs::create_dir(root.join("batches"))?;
    let matching = [0usize, 1, 254, 255, 256, 257, 511, 512, 599];
    let files: Vec<(i64, String, Vec<u8>)> = (0..600)
        .map(|id| {
            let text: &[u8] = if matching.contains(&id) {
                b"fn batch() {} // batch_needle\n"
            } else {
                b"fn other() {}\n"
            };
            (
                3_000 + id as i64,
                format!("batches/{id:04}.txt"),
                text.to_vec(),
            )
        })
        .collect();
    register(cache, root, &files)?;
    let expected: Vec<String> = matching
        .iter()
        .map(|id| format!("batches/{id:04}.txt"))
        .collect();
    let mut reader = super::outer_reader(cache, viewer, records, source, 1, feed_current);
    let mut text = text_query(query, "batch_needle", "batches")?;
    // Fresh start: one call walks every batch.
    let whole = present(reader.find(&text)?.data)?;
    let mut found = paths(&whole);
    found.sort();
    assert_eq!(found, expected, "a single scan lost a file at a batch edge");
    let stats = whole.text.as_ref().ok_or("missing text scan counts")?;
    assert_eq!(
        stats.scanned_files, 600,
        "a batch boundary skipped or rescanned rows"
    );
    assert!(whole.page.next().is_none());
    // Cursor resumes: each page restarts the walk inside a different batch.
    for size in [1u16, 2, 4] {
        text.budget = Validate.query_budget(size, 16384)?;
        text.next = None;
        let mut seen = Vec::new();
        for _ in 0..expected.len() + 2 {
            let page = present(reader.find(&text)?.data)?;
            assert!(page.page.items().len() <= usize::from(size));
            for path in paths(&page) {
                assert!(!seen.contains(&path), "resume repeated {path}");
                seen.push(path);
            }
            let Some(next) = page.page.next() else {
                break;
            };
            text.next = Some(AtlasCursor::new(next.as_str())?);
        }
        seen.sort();
        assert_eq!(
            seen, expected,
            "cursor resume lost a file with page size {size}"
        );
    }
    Ok(())
}
/// Code literal matches rank each file through literal metadata, the file
/// window, and record-backed activity within the statement memory budget.
pub(super) fn ranked(
    cache: &mut CacheConnection<'_>,
    viewer: &AtlasPrincipal,
    records: &dyn RecordReader,
    source: &Source,
    feed_current: bool,
    query: &FindQuery,
) -> Check {
    let root = &source.scope.registration.canonical_source_root;
    fs::create_dir(root.join("ranked"))?;
    let text = "fn ranked_needle() {}\n";
    for id in 0..12 {
        fs::write(root.join(format!("ranked/{id:02}.rs")), text)?;
    }
    cache.write(4_000_000, end(), |sql| {
        let record: i64 = sql
            .prepare("SELECT id FROM records ORDER BY id LIMIT 1")?
            .query_row([], |r| r.get(0))
            .map_err(fail)?;
        sql.prepare("INSERT INTO names(text) VALUES('ranked_needle')")?
            .execute([])
            .map_err(fail)?;
        for id in 0i64..12 {
            let row = 5_000 + id;
            let path = format!("ranked/{id:02}.rs");
            sql.prepare("INSERT INTO files(id,key,path,path_key,language,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?3,?3,'Rust',22,x'01','\"Indexed\"',1,0,0)")?
                .execute((row, key::<16>(row).as_slice(), path)).map_err(fail)?;
            sql.prepare("INSERT INTO symbols(id,key,file,name,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,exported,doc_line) VALUES(?1,?2,?1,(SELECT id FROM names WHERE text='ranked_needle'),'Function',0,21,1,0,1,21,0,'')")?
                .execute((row, key::<32>(row).as_slice())).map_err(fail)?;
            for ordinal in 0..3i64 {
                sql.prepare("INSERT INTO touches(target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms,source_record,restricted_record) VALUES('file',?1,?2,'edit',NULL,?3,?4,NULL)")?
                    .execute((key::<16>(row).as_slice(), ordinal, 1 + id, record)).map_err(fail)?;
            }
            sql.prepare("INSERT INTO activity VALUES('file',?1,?2,0)")?
                .execute((key::<16>(row).as_slice(), 1 + id)).map_err(fail)?;
        }
        Ok(())
    })?;
    let mut reader = super::outer_reader(cache, viewer, records, source, 1, feed_current);
    let mut code = text_query(query, "ranked_needle", "ranked")?;
    code.kind = SearchKind::Code;
    let results = present(reader.find(&code)?.data)?;
    assert_eq!(results.page.items().len(), 10);
    for hit in results.page.items() {
        let HitTarget::Code(code) = &hit.target else {
            return Err("code literal returned another kind".into());
        };
        assert!(
            code.symbol.is_some(),
            "literal metadata was dropped for a touched file"
        );
        assert_eq!(hit.reason.match_tier, 1);
        let id: i64 = code.pointer.path.as_str()[7..9].parse()?;
        assert_eq!(
            hit.reason.last_touch_unix_ms,
            Some(1 + id),
            "record-backed activity was lost or read for another file"
        );
    }
    let stats = results.text.as_ref().ok_or("missing text scan counts")?;
    assert_eq!(stats.matching_files, 12);
    Ok(())
}
