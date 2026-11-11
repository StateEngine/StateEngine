//! Public compact search must admit matching files, including late source bytes.
//! Synthetic SQL overhead here is functional evidence, not a native RAM profile.
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_atlas::{
    cache::{connection::*, *},
    lifecycle::CaseMode,
    model::*,
    query::{QueryReader, ReaderContext, RecordReader},
};
use se_host::{atlas_cache::NativeAtlasCache, atlas_source::NativeAtlasSource};
use se_types::{Read, code::*};
use std::{
    fs,
    time::{Duration, Instant},
};
struct NoRecords;
fn unexpected() -> se_types::SeError {
    se_types::SeError::invalid(
        "source scan",
        "code-only query must not read authoritative records",
    )
}
impl RecordReader for NoRecords {
    fn read(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> se_atlas::errors::AtlasResult<Read<RecordHit>> {
        Err(unexpected())
    }
    fn literal_read(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: &QueryText,
    ) -> se_atlas::errors::AtlasResult<Read<RecordHit>> {
        Err(unexpected())
    }
    fn body(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> se_atlas::errors::AtlasResult<Read<HitBody>> {
        Err(unexpected())
    }
}
fn end() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn compact_literal_and_regex_reach_ten_files_past_unmatched_files_and_prefix_bytes() -> Check {
    let f = Fixture::new()?;
    let root = RootId::from_parts(1, [2; 10])?;
    let directory = f.home.join("source");
    fs::create_dir_all(directory.join("z-target"))?;
    let mut files = Vec::new();
    for id in 0..220 {
        let path = RelativePath::new(format!("a-{id:03}.rs"))?;
        fs::write(
            directory.join(path.as_str()),
            b"needle_nominee without actual match\n",
        )?;
        files.push(path);
    }
    for id in 0..10 {
        let path = RelativePath::new(format!("z-target/{id:02}.rs"))?;
        fs::write(
            directory.join(path.as_str()),
            "x".repeat(1023) + "needle_target\n",
        )?;
        files.push(path);
    }
    let home = f.home.join("atlas");
    let source = NativeAtlasSource::open(
        RootRegistration {
            project: f.project.clone(),
            root: root.clone(),
            canonical_source_root: directory,
            cache: CacheLocation {
                directory: home.join(f.project.as_str()).join(root.as_str()),
            },
            git_metadata: None,
        },
        CaseMode::Sensitive,
    )?;
    let native = NativeAtlasCache::create(&home, source.scope.clone())?;
    let coverage = serde_json::from_value(
        serde_json::json!({"discovered_files":230,"indexed_files":0,"partial_files":0,"deferred_files":230,"failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":true,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
    )?;
    let mut cache = CacheConnection::create(
        &native,
        &CacheSeed {
            identity: CacheIdentity {
                scope: source.scope.clone(),
                epoch: CacheEpoch::from_parts(1, [3; 10])?,
            },
            extractor_version: "streaming-fixture".into(),
            ignore_digest: ContentHash([0; 32]),
            coverage,
            state: IndexState::Current,
        },
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        end(),
    )?;
    cache.write(1_000_000,end(),|sql| {
        sql.prepare("UPDATE meta SET index_generation=1,published_generation=1,discovery_complete=1")?.execute([]).map_err(|_|unexpected())?;
        for (id,path) in files.iter().enumerate() {
            let key=source.scope.file_id(path);
            sql.prepare("INSERT INTO files(id,key,path,path_key,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset,language) VALUES(?1,?2,?3,?3,2048,x'01',?4,1,0,0,'Rust')")?
                .execute((id as i64+1,key.0.as_slice(),path.as_str(),"{\"Deferred\":{\"reason\":\"SourceBytesLimit\"}}"))
                .map_err(|e|se_types::SeError::invalid("source fixture",&e.to_string()))?;
        }
        Ok(())
    })?;
    let mut reader = QueryReader::new(
        &mut cache,
        ReaderContext {
            memory: None,
            viewer: AtlasPrincipal::Agent(f.a.clone()),
            records: &NoRecords,
            source: Some(&source),
            hostless: false,
            epoch_retired: false,
            now_unix_ms: Some(1),
            record_feed_current: true,
        },
    );
    for regex in [false, true] {
        let op = se_core::ops::decode_tool(
            "stateengine_atlas_find",
            serde_json::json!({"query":if regex {"needle_t[a-z]+"} else {"needle_target"},"kind":"code","mode":"literal","regex":regex}),
        )?;
        let se_core::ops::AnyOp::AtlasFind(input) = op else {
            return Err("wrong operation".into());
        };
        let result =
            se_host::atlas_queries::execute(&mut reader, &se_core::ops::AtlasRead::Find(input))?;
        let compact =
            se_host::atlas_queries::compact(&result, 4096, false)?.ok_or("compact absent")?;
        assert!(compact.len() <= 4096);
        let se_core::ops::AnyOutput::AtlasFind(output) = result else {
            return Err("wrong output".into());
        };
        let value = present(output.value.answer.data)?;
        assert_eq!(
            value.page.items().len(),
            10,
            "unmatched files or typed metadata consumed the result window"
        );
        assert_eq!(
            value
                .text
                .as_ref()
                .ok_or("scan stats absent")?
                .scanned_files,
            230
        );
        for (id, hit) in value.page.items().iter().enumerate() {
            let HitTarget::Code(code) = &hit.target else {
                return Err("non-source hit".into());
            };
            assert_eq!(code.pointer.path.as_str(), format!("z-target/{id:02}.rs"));
            assert!(code.pointer.span.is_some_and(|s| s.start_byte > 900));
            assert!(compact.contains(code.pointer.path.as_str()));
        }
    }
    // Regex preserves its flags; literal search uses the documented smart case.
    fs::write(
        source
            .scope
            .registration
            .canonical_source_root
            .join("a-000.rs"),
        "CASE_MARKER\n",
    )?;
    for (query, regex, expected) in [
        ("case_marker", false, 1),
        ("case_marker", true, 0),
        ("(?i)case_marker", true, 1),
    ] {
        let op = se_core::ops::decode_tool(
            "stateengine_atlas_find",
            serde_json::json!({"query":query,"kind":"code","mode":"literal","regex":regex}),
        )?;
        let se_core::ops::AnyOp::AtlasFind(input) = op else {
            return Err("wrong operation".into());
        };
        let result =
            se_host::atlas_queries::execute(&mut reader, &se_core::ops::AtlasRead::Find(input))?;
        let se_core::ops::AnyOutput::AtlasFind(output) = result else {
            return Err("wrong output".into());
        };
        assert_eq!(
            present(output.value.answer.data)?.page.items().len(),
            expected,
            "regex flags changed: {query}"
        );
    }
    // Broad source scoring must use term rarity, including words beyond the
    // displayed excerpt. Exercise compact ingress and replay its ranked window.
    for id in 0..10 {
        let text = if id == 9 {
            "x".repeat(1024) + " " + "marker_rare\n"
        } else {
            "x".repeat(1024) + " " + "marker_common marker_common marker_common\n"
        };
        fs::write(
            source
                .scope
                .registration
                .canonical_source_root
                .join(format!("z-target/{id:02}.rs")),
            text,
        )?;
    }
    let mut cursor = None;
    let mut paths = Vec::new();
    for _ in 0..10 {
        let op = se_core::ops::decode_tool(
            "stateengine_atlas_find",
            serde_json::json!({"query":"marker_common marker_rare","kind":"code","mode":"broad","limit":3,"cursor":cursor}),
        )?;
        let se_core::ops::AnyOp::AtlasFind(input) = op else {
            return Err("wrong operation".into());
        };
        let result =
            se_host::atlas_queries::execute(&mut reader, &se_core::ops::AtlasRead::Find(input))?;
        let compact =
            se_host::atlas_queries::compact(&result, 4096, false)?.ok_or("compact absent")?;
        assert!(compact.len() <= 4096);
        let se_core::ops::AnyOutput::AtlasFind(output) = result else {
            return Err("wrong output".into());
        };
        let value = present(output.value.answer.data)?;
        for hit in value.page.items() {
            let HitTarget::Code(code) = &hit.target else {
                return Err("non-source hit".into());
            };
            paths.push(code.pointer.path.as_str().to_owned());
        }
        cursor = value.page.next().cloned();
        if cursor.is_none() {
            break;
        }
    }
    assert!(cursor.is_none(), "ranked pagination did not finish");
    assert_eq!(paths.len(), 10, "Broad replay lost or repeated files");
    assert_eq!(
        paths[0], "z-target/09.rs",
        "rare source term did not outrank the common term"
    );
    paths.sort();
    paths.dedup();
    assert_eq!(paths.len(), 10);
    // Force multiple bounded staging windows, then traverse every continuation.
    // A memory cut must retain a whole file for the next window.
    for id in 0..220 {
        fs::write(
            source
                .scope
                .registration
                .canonical_source_root
                .join(format!("a-{id:03}.rs")),
            "marker_common\n",
        )?;
    }
    let mut cursor = None;
    let mut paths = Vec::new();
    for _ in 0..100 {
        let op = se_core::ops::decode_tool(
            "stateengine_atlas_find",
            serde_json::json!({"query":"marker_common marker_rare","kind":"code","mode":"broad","limit":10,"cursor":cursor}),
        )?;
        let se_core::ops::AnyOp::AtlasFind(input) = op else {
            return Err("wrong operation".into());
        };
        let result =
            se_host::atlas_queries::execute(&mut reader, &se_core::ops::AtlasRead::Find(input))?;
        let se_core::ops::AnyOutput::AtlasFind(output) = result else {
            return Err("wrong output".into());
        };
        let value = present(output.value.answer.data)?;
        for hit in value.page.items() {
            let HitTarget::Code(code) = &hit.target else {
                return Err("non-source hit".into());
            };
            paths.push(code.pointer.path.as_str().to_owned());
        }
        cursor = value.page.next().cloned();
        if cursor.is_none() {
            break;
        }
    }
    assert!(cursor.is_none(), "staged pagination did not finish");
    assert_eq!(
        paths.len(),
        230,
        "a staging boundary lost or repeated matches"
    );
    paths.sort();
    paths.dedup();
    assert_eq!(paths.len(), 230);
    Ok(())
}
