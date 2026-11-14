//! Native adapter development checks; SqlProfile(1) is not an RSS qualification.
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "atlas_query_reads/hooks.rs"]
mod hooks;
#[path = "atlas_query_reads/literal.rs"]
mod literal_queries;
#[path = "atlas_query_reads/private.rs"]
mod private;
#[path = "atlas_query_reads/deadline.rs"]
mod scan_deadline;
#[path = "atlas_query_reads/scope.rs"]
mod scope_queries;
#[path = "../../test-support/atlas_clock.rs"]
mod test_clock;
#[path = "atlas_query_reads/text.rs"]
mod text_queries;
use fixture::*;
use se_atlas::{
    cache::{connection::*, *},
    lifecycle::{AtlasSource, SourceRead},
    model::*,
    queries::AtlasQueries,
    query::{QueryReader, ReaderContext},
};
use se_host::{
    atlas_cache::NativeAtlasCache, atlas_records::AtlasRecordReader,
    atlas_source::NativeAtlasSource,
};
use se_store::*;
use se_types::code::*;
use std::{
    fs,
    time::{Duration, Instant},
};
fn end() -> Instant {
    se_atlas::clock::now() + Duration::from_secs(5)
}
fn fail(e: impl std::fmt::Display) -> se_types::SeError {
    se_types::SeError::invalid("query fixture", &e.to_string())
}
fn prepared<'a>(
    sql: &'a SqlView<'_>,
    statement: &str,
) -> se_atlas::errors::AtlasResult<BudgetStatement<'a>> {
    sql.prepare(statement)
        .map_err(|e| fail(format!("{}: {e}", &statement[..statement.len().min(45)])))
}
fn outer_reader<'a, 'c, 'x>(
    cache: &'a mut CacheConnection<'c>,
    viewer: &'x AtlasPrincipal,
    records: &'x dyn se_atlas::query::RecordReader,
    source: &'x se_atlas::source::RegisteredSource<NativeAtlasSource>,
    now_unix_ms: i64,
    feed_current: bool,
) -> QueryReader<'a, 'c, 'x> {
    QueryReader::new(
        cache,
        ReaderContext {
            memory: None,
            viewer: viewer.clone(),
            records,
            source: Some(source),
            hostless: false,
            epoch_retired: false,
            now_unix_ms: Some(now_unix_ms),
            record_feed_current: feed_current,
        },
    )
}
#[test]
#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn five_native_reads_and_streaming_text_share_one_scoped_snapshot() -> Check {
    let _clock = test_clock::control();
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    direct.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.a.clone()),
            message()?,
            "The packet budget applies to alpha.rs and hook_large.rs",
            "atlas-query-record",
        )?,
        &*lease,
    )?;
    let source_dir = f.home.join("source");
    fs::create_dir(&source_dir)?;
    let text = "fn alpha() {}\nfn caller() { alpha(); }\n";
    fs::write(source_dir.join("alpha.rs"), text)?;
    let late = "x\n".repeat(300_000) + "late_line_marker\n";
    fs::write(source_dir.join("large.txt"), late.as_bytes())?;
    fs::write(source_dir.join("binary.bin"), b"caller\0")?;
    fs::write(source_dir.join("encoding.txt"), b"caller\xff")?;
    fs::File::create(source_dir.join("oversized.txt"))?.set_len(64 * 1024 * 1024 + 1)?;
    for id in 7..40 {
        fs::write(source_dir.join(format!("empty-{id}.txt")), b"empty\n")?;
    }
    fs::write(source_dir.join("consumer.rs"), b"use crate::alpha;\n")?;
    fs::write(
        source_dir.join("hook_large.rs"),
        format!("fn large_marker() {{}}\n{}", "\n".repeat(32768)),
    )?;
    let atlas_home = f.home.join("atlas");
    let root = RootId::from_parts(1, [2; 10])?;
    let source = NativeAtlasSource::open(
        RootRegistration {
            project: f.project.clone(),
            root: root.clone(),
            canonical_source_root: source_dir,
            cache: CacheLocation {
                directory: atlas_home.join(f.project.as_str()).join(root.as_str()),
            },
            git_metadata: None,
        },
        se_atlas::lifecycle::CaseMode::Sensitive,
    )?;
    let SourceRead::Bytes(hook_file) = source.read(
        &RelativePath::new("hook_large.rs")?,
        ParseBudget {
            max_source_bytes: 65536,
            max_rows: 128,
            max_work: Duration::from_millis(200),
            reserved_bytes: 65536,
        },
    )?
    else {
        return Err("large hook fixture unavailable".into());
    };
    let SourceRead::Bytes(file) = source.read(
        &RelativePath::new("alpha.rs")?,
        ParseBudget {
            max_source_bytes: 1024,
            max_rows: 128,
            max_work: Duration::from_millis(200),
            reserved_bytes: 1024,
        },
    )?
    else {
        return Err("source fixture unavailable".into());
    };
    let native = NativeAtlasCache::create(&atlas_home, source.scope.clone())?;
    let coverage = serde_json::from_value(
        serde_json::json!({"discovered_files":40,"indexed_files":3,"partial_files":0,"deferred_files":37,"failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":1,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":true,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
    )?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: source.scope.clone(),
            epoch: CacheEpoch::from_parts(1, [3; 10])?,
        },
        extractor_version: "query-development-fixture".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage,
        state: IndexState::Current,
    };
    let mut cache = CacheConnection::create(
        &native,
        &seed,
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        end(),
    )?;
    let pointer = CodePointer {
        file: FileId([1; 16]),
        path: RelativePath::new("alpha.rs")?,
        span: None,
        content_hash: Some(file.content_hash),
        freshness: SnapshotFreshness::Current,
    };
    cache.write(1_000_000,end(),|sql|{
        for statement in [
            "UPDATE meta SET index_generation=1,published_generation=1,discovery_complete=1",
            "INSERT INTO names(id,text) VALUES(1,'alpha'),(2,'caller')",
            "INSERT INTO generations VALUES(1,1,1,'edit')",
        ]{prepared(sql,statement)?.execute([]).map_err(fail)?;}
        prepared(sql,"INSERT INTO files(id,key,path,path_key,bytes,identity,indexed_hash,coverage_json,last_code_generation,last_author_generation,baseline_reset,language) VALUES(1,?1,'alpha.rs','alpha.rs',39,x'01',?2,'\"Indexed\"',1,0,0,'Rust')")?.execute((pointer.file.0.as_slice(),file.content_hash.0.as_slice())).map_err(fail)?;
        let deferred=serde_json::to_string(&FileCoverage::Deferred{reason:CoverageReason::SourceBytesLimit}).map_err(fail)?;
        for (id,path,bytes) in [(3i64,"large.txt",late.len() as i64),(4,"binary.bin",7),(5,"encoding.txt",7),(6,"oversized.txt",64*1024*1024+1)] {
            let key=[id as u8;16];
            prepared(sql,"INSERT INTO files(id,key,path,path_key,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?3,?3,?4,x'01',?5,1,0,0)")?.execute((id,key.as_slice(),path,bytes,&deferred)).map_err(fail)?;
        }
        prepared(sql,"INSERT INTO touches(target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms,source_record,restricted_record) VALUES('file',?1,0,'edit',NULL,0,NULL,NULL)")?.execute([[1u8;16].as_slice()]).map_err(fail)?;
        prepared(sql,"INSERT INTO activity VALUES('file',?1,0,0)")?.execute([[1u8;16].as_slice()]).map_err(fail)?;
        for id in 7i64..40 {
            let key=[id as u8;16];let path=format!("empty-{id}.txt");
            prepared(sql,"INSERT INTO files(id,key,path,path_key,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(?1,?2,?3,?3,6,x'01',?4,1,0,0)")?.execute((id,key.as_slice(),path,&deferred)).map_err(fail)?;
        }
        prepared(sql,"INSERT INTO files(id,key,path,path_key,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset,language) VALUES(40,?1,'consumer.rs','consumer.rs',18,x'01','\"Indexed\"',1,0,0,'Rust')")?.execute([[40u8;16].as_slice()]).map_err(fail)?;
        prepared(sql,"INSERT INTO files(id,key,path,path_key,bytes,identity,indexed_hash,coverage_json,last_code_generation,last_author_generation,baseline_reset,language) VALUES(41,?1,'hook_large.rs','hook_large.rs',?2,x'01',?3,'\"Indexed\"',1,0,0,'Rust')")?.execute(([41u8;16].as_slice(),hook_file.identity.size as i64,hook_file.content_hash.0.as_slice())).map_err(fail)?;
        prepared(sql,"INSERT INTO imports(id,file,spelling,target_file,start_byte,end_byte,resolution,kind) VALUES(1,40,'crate::alpha',1,0,17,'ExplicitImport','Rust')")?.execute([]).map_err(fail)?;
        for (id,name,start,stop,line) in [(1i64,1i64,0i64,13i64,1i64),(2,2,14,37,2)]{
            let key=[id as u8;32];prepared(sql,"INSERT INTO symbols(id,key,file,name,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,exported,doc_line) VALUES(?1,?2,1,?3,'Function',?4,?5,?6,0,?6,?7,0,'')")?.execute((id,key.as_slice(),name,start,stop,line,stop-start)).map_err(fail)?;
        }
        prepared(sql,"INSERT INTO symbol_fts(rowid,name,split_name,path,container,doc_line) VALUES(1,'alpha','alpha','alpha.rs','',''),(2,'caller','caller','alpha.rs','','')")?.execute([]).map_err(fail)?;
        prepared(sql,"INSERT INTO refs(id,file,enclosing,target,spelling,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,accuracy) VALUES(1,1,2,1,1,'Call',28,33,2,14,2,19,'LexicalBinding')")?.execute([]).map_err(fail)?;
        let json=serde_json::to_string(&pointer).map_err(fail)?;
        prepared(sql,"INSERT INTO changes(generation,ordinal,file_key,path,kind,pointer_json,baseline_reset) VALUES(1,0,?1,'alpha.rs','Added',?2,0)")?.execute((pointer.file.0.as_slice(),json)).map_err(fail)?;
        Ok(())
    })?;
    let store = present(SqliteFactory::open_reader(&f.options)?)?;
    let owner_scope = f.scoped(Visibility::Owner);
    let mut owner = store.snapshot(owner_scope.clone())?;
    let feed = se_core::atlas_records::feed::next(&mut owner, &owner_scope.admission, None)?
        .ok_or("missing feed")?;
    se_atlas::records::apply(&mut cache, &feed, end())?;
    owner.close()?;
    let scope = f.self_scope(&f.a);
    let mut snapshot = store.snapshot(scope.clone())?;
    let records = AtlasRecordReader::new(&mut snapshot, &scope.admission);
    let viewer = AtlasPrincipal::Agent(f.a.clone());
    let budget = Validate.query_budget(10, 4096)?;
    let query = FindQuery {
        query: QueryText::new("alpha")?,
        kind: SearchKind::All,
        scope: SearchScope {
            paths: vec![],
            languages: vec![],
        },
        next: None,
        budget,
        mode: Some(SearchMode::Exact),
        order: SearchOrder::Relevance,
        full: false,
        regex: false,
    };
    // The delayed first read must finish before its SQL deadline. The reader
    // owns the connection exclusively, so it runs before the regular reader.
    let deadline_query =
        scan_deadline::delayed_scan(&mut cache, &source, &records, &viewer, &query)?;
    let public = se_core::ops::decode_tool(
        "stateengine_atlas_find",
        serde_json::json!({"query":"alpha","mode":"exact"}),
    )?;
    let se_core::ops::AnyOp::AtlasFind(public) = public else {
        return Err("wrong decoded family".into());
    };
    let mut reader = outer_reader(&mut cache, &viewer, &records, &source, 1, feed.complete);
    scan_deadline::continuation(&mut reader, &deadline_query)?;
    let routed =
        se_host::atlas_queries::execute(&mut reader, &se_core::ops::AtlasRead::Find(public))?;
    let compact =
        se_host::atlas_queries::compact(&routed, 4096, false)?.ok_or("compact output absent")?;
    assert!(compact.contains("alpha.rs:1 (13 B) alpha"));
    let result = present(AtlasQueries::find(&mut reader, &query)?.data)?;
    assert_eq!(result.page.items()[0].reason.match_tier, 1);
    assert!(
        result
            .page
            .items()
            .iter()
            .any(|hit| hit.reason.match_tier == 5)
    );
    assert!(result.text.is_some());
    assert!(result.page.items()[0].body.is_none());
    let outline = present(
        reader
            .outline(&OutlineQuery {
                path: RelativePath::new("alpha.rs")?,
                next: None,
                budget,
            })?
            .data,
    )?;
    assert_eq!(outline.symbols.len(), 2);
    assert_eq!(outline.records.len(), 1);
    let refs = present(
        reader
            .refs(&RefsQuery {
                target: AtlasTarget::Symbol(SymbolSelector::Id(SymbolId([1; 32]))),
                kinds: vec![],
                include_name_only: true,
                next: None,
                budget,
            })?
            .data,
    )?;
    assert_eq!(
        refs.items()
            .iter()
            .filter(|r| matches!(r, ReferenceHit::Code(_)))
            .count(),
        1
    );
    drop(reader);
    hooks::check(&mut cache, &source, &records, &viewer, &f.b, feed.complete)?;
    let mut reader = outer_reader(&mut cache, &viewer, &records, &source, 1, feed.complete);
    let impact = present(
        reader
            .impact(&ImpactQuery {
                target: AtlasTarget::Symbol(SymbolSelector::Id(SymbolId([1; 32]))),
                depth: 2,
                include_name_only: false,
                next: None,
                budget,
            })?
            .data,
    )?;
    assert!(
        impact
            .dependents
            .iter()
            .any(|d| d.symbol == Some(SymbolId([2; 32])))
    );
    assert_eq!(
        impact
            .dependents
            .iter()
            .find(|d| d.symbol == Some(SymbolId([2; 32])))
            .ok_or("caller missing")?
            .hops[0]
            .accuracy,
        Accuracy::LexicalBinding
    );
    assert_eq!(impact.records.len(), 1);
    let file_impact = present(
        reader
            .impact(&ImpactQuery {
                target: AtlasTarget::File(RelativePath::new("alpha.rs")?),
                depth: 2,
                include_name_only: false,
                next: None,
                budget,
            })?
            .data,
    )?;
    let importer = file_impact
        .dependents
        .iter()
        .find(|d| d.pointer.path.as_str() == "consumer.rs")
        .ok_or("file-only importer missing")?;
    assert!(importer.symbol.is_none());
    assert_eq!(importer.file_hops.len(), 1);
    assert_eq!(importer.file_hops[0].accuracy, Accuracy::ExplicitImport);
    assert_eq!(importer.file_hops[0].start_byte, 0);
    assert_eq!(importer.file_hops[0].end_byte, 17);
    let summary = reader.status()?;
    let cursor = CodeCursorPosition::new(
        &summary,
        "changes-range",
        cursor_digest(&("changes-range", &viewer))?,
        CursorKey {
            integers: vec![0, u64::from(u32::MAX)],
            bytes: vec![],
        },
        None,
    )?
    .encode()?;
    let changes = present(
        reader
            .changes(&ChangesQuery {
                since: ChangeBaseline::Cursor(cursor.clone()),
                scope: query.scope.clone(),
                next: None,
                budget,
            })?
            .data,
    )?;
    assert_eq!(changes.items().len(), 1);
    let timed = present(
        reader
            .changes(&ChangesQuery {
                since: ChangeBaseline::ObservedUnixMillis(1),
                scope: query.scope.clone(),
                next: None,
                budget,
            })?
            .data,
    )?;
    assert!(timed.items().is_empty());
    let request = ResumeRequest {
        viewer: f.a.clone(),
        saved_cursor: Some(cursor),
        cursor_revision: 0,
        recently_edited_symbols: vec![],
    };
    let news = reader.resume_code(&request)?;
    assert!(news.items.is_empty());
    assert_eq!(news.unattributed_omitted, Some(1));
    assert!(!news.complete);
    assert!(news.advance.is_some());
    drop(reader);
    let captured = serde_json::to_string(&AuthorHint::Captured {
        agent: f.b.clone(),
        evidence: feed.through.clone(),
    })?;
    cache.write(65536,end(),|sql|{sql.prepare("INSERT INTO authors(generation,ordinal,resolved_at_generation,hint_json) VALUES(1,0,1,?1)")?.execute([captured]).map_err(fail)?;Ok(())})?;
    let mut reader = outer_reader(&mut cache, &viewer, &records, &source, 1, feed.complete);
    let news = reader.resume_code(&request)?;
    assert_eq!(news.items.len(), 1);
    assert!(
        matches!(&news.items[0],ResumeChange::File{author:AuthorHint::Captured{agent,..},..} if agent==&f.b)
    );
    assert!(se_atlas::render::resume(&news)?.len() <= 600);
    let mut record_query = query.clone();
    record_query.kind = SearchKind::Message;
    record_query.query = QueryText::new("packet budget")?;
    record_query.mode = Some(SearchMode::Phrase);
    let hits = present(reader.find(&record_query)?.data)?;
    let record_key = match &hits.page.items()[0].target {
        HitTarget::Record(record) => record.pointer.key.clone(),
        _ => return Err("expected record".into()),
    };
    assert!(
        matches!(&hits.page.items().first().ok_or("record not found")?.target,HitTarget::Record(record) if record.line.contains("packet budget"))
    );
    let mut related = record_query.clone();
    related.kind = SearchKind::Symbol;
    related.mode = Some(SearchMode::Related);
    let neighbors = present(reader.find(&related)?.data)?;
    assert!(neighbors.page.items().iter().any(|hit| hit.reason.related
        && matches!(&hit.target, HitTarget::Code(code) if code.symbol == Some(SymbolId([1;32])))));
    let mut interior = record_query.clone();
    interior.mode = Some(SearchMode::Literal);
    interior.query = QueryText::new("udge")?;
    assert_eq!(present(reader.find(&interior)?.data)?.page.items().len(), 1);
    interior.query = QueryText::new("Packet Budget")?;
    assert!(
        present(reader.find(&interior)?.data)?
            .page
            .items()
            .is_empty()
    );
    let mut prefix = query.clone();
    prefix.kind = SearchKind::Symbol;
    prefix.mode = Some(SearchMode::Literal);
    prefix.query = QueryText::new("al")?;
    assert_eq!(
        present(reader.find(&prefix)?.data)?.page.items()[0]
            .reason
            .match_tier,
        2
    );
    let mut paged = prefix.clone();
    paged.mode = None;
    paged.budget = Validate.query_budget(1, 4096)?;
    let first = present(reader.find(&paged)?.data)?;
    assert_eq!(first.mode, SearchMode::Literal);
    paged.next = Some(AtlasCursor::new(
        first
            .page
            .next()
            .ok_or("fallback page missing cursor")?
            .as_str(),
    )?);
    let second = present(reader.find(&paged)?.data)?;
    assert_eq!(second.mode, SearchMode::Literal);
    assert_eq!(second.fallback_from, Some(SearchMode::Exact));
    assert_ne!(first.page.items()[0].target, second.page.items()[0].target);
    prefix.query = QueryText::new("pha")?;
    assert_eq!(
        present(reader.find(&prefix)?.data)?.page.items()[0]
            .reason
            .match_tier,
        4
    );
    let mut full = query.clone();
    full.full = true;
    let result = reader.find(&full)?;
    let encoded = serde_json::to_vec(&result)?;
    assert!(encoded.len() <= 12 * 1024);
    let hits = present(result.data)?;
    assert!(
        hits.page.items()[0]
            .body
            .as_ref()
            .is_some_and(|b| b.text == "fn alpha() {}")
    );
    drop(reader);
    let mut text = text_queries::check(
        &mut cache,
        &viewer,
        &records,
        &source,
        feed.complete,
        &query,
    )?;
    cache.write(65536, end(), |sql| {
        sql.prepare("UPDATE records SET body_truncated=1")?
            .execute([])
            .map_err(fail)?;
        Ok(())
    })?;
    let limited = {
        let mut reader = outer_reader(&mut cache, &viewer, &records, &source, 1, feed.complete);
        reader.summary()?
    };
    assert!(
        limited
            .coverage
            .reasons
            .contains(&CoverageReason::RecordBodyLimit)
    );
    let remove = RecordFeed {
        project: f.project.clone(),
        after: Some(feed.through.clone()),
        through: se_types::EventId::from_parts(2, [6; 10])?,
        changes: vec![RecordFeedChange::Remove {
            project: f.project.clone(),
            key: record_key,
        }],
        complete: true,
    };
    let before = {
        let mut reader = outer_reader(&mut cache, &viewer, &records, &source, 1, feed.complete);
        reader.summary()?.generation
    };
    se_atlas::records::apply(&mut cache, &remove, end())?;
    let after = {
        let mut reader = outer_reader(&mut cache, &viewer, &records, &source, 1, feed.complete);
        reader.summary()?.generation
    };
    assert!(
        after.map(|g| g.0) > before.map(|g| g.0),
        "record publication did not fence live continuations"
    );
    se_atlas::records::apply(&mut cache, &remove, end())?;
    let replayed = {
        let mut reader = outer_reader(&mut cache, &viewer, &records, &source, 1, feed.complete);
        reader.summary()?.generation
    };
    assert_eq!(replayed, after, "feed replay changed generation");
    {
        let mut behind = QueryReader::new(
            &mut cache,
            ReaderContext {
                memory: None,
                viewer: viewer.clone(),
                records: &records,
                source: Some(&source),
                hostless: false,
                epoch_retired: false,
                now_unix_ms: Some(1),
                record_feed_current: false,
            },
        );
        let missing = behind.find(&record_query)?;
        assert!(
            missing
                .index
                .coverage
                .reasons
                .contains(&CoverageReason::RecordFeedLag)
        );
        assert!(!present(missing.data)?.page.window().complete());
    }
    let mut reader = outer_reader(&mut cache, &viewer, &records, &source, 1, feed.complete);
    let hits = present(reader.find(&record_query)?.data)?;
    assert!(hits.page.items().is_empty());
    fs::write(
        source
            .scope
            .registration
            .canonical_source_root
            .join("alpha.rs"),
        "fn newly_changed() {}
",
    )?;
    text.query = QueryText::new("newly_changed")?;
    let changed = reader.find(&text)?;
    assert!(
        changed
            .index
            .coverage
            .reasons
            .contains(&CoverageReason::StaleSnapshot)
    );
    let page = present(changed.data)?;
    assert!(!page.page.window().complete());
    assert!(
        matches!(&page.page.items()[0].target, HitTarget::Code(code) if code.pointer.freshness == SnapshotFreshness::Stale)
    );
    drop(reader);
    private::retained(
        &mut cache,
        &viewer,
        &records,
        &source,
        feed.complete,
        &pointer,
        &request,
        &query,
        budget,
    )?;
    scope_queries::check(
        &mut cache,
        &viewer,
        &records,
        &source,
        feed.complete,
        &query,
    )?;
    literal_queries::check(
        &mut cache,
        &viewer,
        &records,
        &source,
        feed.complete,
        &query,
    )?;
    Ok(())
}
