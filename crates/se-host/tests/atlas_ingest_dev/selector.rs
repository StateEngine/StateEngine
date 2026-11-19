//! The Name selector resolves a type definition and its same-named impl
//! block without refusing the query, and kind or line narrow it further.
use super::*;
use se_atlas::query::{QueryReader, ReaderContext, RecordReader};
use se_types::{Page, Read, code::*};
struct NoRecords;
impl RecordReader for NoRecords {
    fn read(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> se_atlas::errors::AtlasResult<Read<RecordHit>> {
        panic!("the development fixture applies no record feed")
    }
    fn literal_read(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: &QueryText,
    ) -> se_atlas::errors::AtlasResult<Read<RecordHit>> {
        panic!("the development fixture applies no record feed")
    }
    fn body(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> se_atlas::errors::AtlasResult<Read<HitBody>> {
        panic!("the development fixture applies no record feed")
    }
}
fn run_refs<'a, 'c, 'x>(
    reader: &mut QueryReader<'a, 'c, 'x>,
    budget: QueryBudget,
    name: &str,
    path: Option<&str>,
    kind: Option<SymbolKind>,
    line: Option<u32>,
) -> Result<Page<ReferenceHit>, se_types::SeError> {
    let target = AtlasTarget::Symbol(SymbolSelector::Name {
        name: QueryText::new(name)?,
        path: path.map(RelativePath::new).transpose()?,
        container: None,
        kind,
        line,
    });
    let answer = reader.refs(&RefsQuery {
        target,
        kinds: vec![],
        include_name_only: true,
        next: None,
        budget,
    })?;
    match answer.data {
        Read::Present { value } => Ok(value),
        other => Err(se_types::SeError::invalid(
            "selector development read",
            "a present refs page",
        )
        .with_cause(std::io::Error::other(format!("{other:?}")))),
    }
}
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one real-parser fixture, then a short matrix of selector queries"
)]
fn name_selector_prefers_the_type_definition_over_its_impl_block() -> Check {
    se_proc::initialize_file_creation_owner()?;
    let dir = std::env::temp_dir().join(format!(
        "atlas-ingest-dev-selector-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&dir)?;
    let _root_owner = cleanup_directory::PrivateDirectory::for_case(dir.clone());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    let project = se_types::ProjectId::from_parts(1, [1; 10])?;
    let root = RootId::from_parts(1, [2; 10])?;
    let home = dir.join("atlas");
    let registration = RootRegistration {
        project: project.clone(),
        root: root.clone(),
        canonical_source_root: dir.clone(),
        cache: CacheLocation {
            directory: home.join(project.as_str()).join(root.as_str()),
        },
        git_metadata: None,
    };
    let source = NativeAtlasSource::open(registration, CaseMode::Sensitive)?;
    let scope: Scope = source.scope.clone();
    let cache = NativeAtlasCache::create(&home, scope.clone())?;
    let coverage: Coverage = serde_json::from_value(
        serde_json::json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":false,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":false,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
    )?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: scope.clone(),
            epoch: CacheEpoch::from_parts(1, [4; 10])?,
        },
        extractor_version: "development".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage,
        state: IndexState::Updating {
            pending_files: 4,
            pending_change_batches: 0,
            discovery_complete: false,
        },
    };
    let sql_profile = SqlProfile::from_qualified_overhead(1)?;
    let mut db = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::HostWriter,
        &sql_profile,
        deadline(),
    )?;
    let mut parser = SemanticParser::cold_child(
        scope.clone(),
        [
            Language::JavaScript,
            Language::Jsx,
            Language::TypeScript,
            Language::Tsx,
            Language::Rust,
            Language::Python,
        ]
        .into_iter()
        .map(|language| {
            ParserProfile::from_qualified_measurement(
                language,
                ParserPlacement::ColdChild,
                524288,
                4096,
                4_000_000,
                8_000_000,
            )
        })
        .collect::<se_atlas::errors::AtlasResult<Vec<_>>>()?,
    )?;
    fs::write(
        dir.join("foo.rs"),
        "pub struct Foo {\n    pub value: u32,\n}\n\nimpl Foo {\n    pub fn new(value: u32) -> Self {\n        Self { value }\n    }\n}\n\npub fn use_foo() -> u32 {\n    let f: Foo = Foo::new(1);\n    f.value\n}\n",
    )?;
    fs::write(dir.join("a.rs"), "pub fn helper() {}\n")?;
    fs::write(dir.join("b.rs"), "pub fn helper() {}\n")?;
    fs::write(
        dir.join("e.rs"),
        "pub mod math {\n    pub fn answer() -> u32 {\n        42\n    }\n}\n\npub fn caller() -> u32 {\n    math::answer()\n}\n",
    )?;
    ingest(
        &source,
        &mut db,
        &mut parser,
        &RelativePath::new("foo.rs")?,
        Language::Rust,
        true,
        1,
    )?;
    ingest(
        &source,
        &mut db,
        &mut parser,
        &RelativePath::new("a.rs")?,
        Language::Rust,
        false,
        2,
    )?;
    ingest(
        &source,
        &mut db,
        &mut parser,
        &RelativePath::new("b.rs")?,
        Language::Rust,
        false,
        3,
    )?;
    ingest(
        &source,
        &mut db,
        &mut parser,
        &RelativePath::new("e.rs")?,
        Language::Rust,
        false,
        4,
    )?;
    // Keep the selector assertions independent of runner scheduling.
    #[cfg(debug_assertions)]
    let _clock = se_atlas::clock::pause();
    let viewer = AtlasPrincipal::Human(se_types::HumanId::from_parts(1, [22; 10])?);
    let records = NoRecords;
    let mut reader = QueryReader::new(
        &mut db,
        ReaderContext {
            memory: None,
            viewer: viewer.clone(),
            records: &records,
            source: Some(&source),
            hostless: false,
            epoch_retired: false,
            now_unix_ms: Some(1000),
            record_feed_current: true,
        },
    );
    let budget = Validate.query_budget(10, 4096)?;
    // The struct and its impl block share the name Foo in one file.
    let default = run_refs(&mut reader, budget, "Foo", Some("foo.rs"), None, None)?;
    assert!(
        !default.items().is_empty(),
        "the use site must resolve to the type"
    );
    let declared = run_refs(
        &mut reader,
        budget,
        "Foo",
        Some("foo.rs"),
        Some(SymbolKind::Struct),
        None,
    )?;
    assert_eq!(
        default.items(),
        declared.items(),
        "without a kind or line the type definition must win"
    );
    let by_line = run_refs(&mut reader, budget, "Foo", Some("foo.rs"), None, Some(1))?;
    assert_eq!(
        by_line.items(),
        declared.items(),
        "the definition start line must select the struct"
    );
    // An explicit kind must resolve to that symbol without refusal. The
    // resolver keeps use sites NameOnly while a type and its impl share a
    // name in one scope, so the pages coincide in this fixture.
    run_refs(
        &mut reader,
        budget,
        "Foo",
        Some("foo.rs"),
        Some(SymbolKind::Namespace),
        None,
    )?;
    // The line filter matches the declaration start line, so an indented
    // definition resolves by name plus line; the caller's site witnesses it.
    let indented = run_refs(&mut reader, budget, "answer", Some("e.rs"), None, Some(2))?;
    assert!(
        !indented.items().is_empty(),
        "the indented declaration must resolve through the line filter"
    );
    // Two same-kind functions stay ambiguous, and the refusal lists the
    // kind, path and line of every candidate.
    let refused = match run_refs(&mut reader, budget, "helper", None, None, None) {
        Err(refused) => refused,
        Ok(_) => panic!("same-kind duplicates must stay ambiguous"),
    };
    let candidates = match refused.body.detail() {
        se_types::Detail::AtlasSymbolAmbiguous(value) => value.candidates.clone(),
        other => panic!("expected an ambiguity refusal, got {other:?}"),
    };
    assert!(
        candidates
            .iter()
            .all(|candidate| candidate.starts_with("Function ")),
        "candidates must name their kind: {candidates:?}"
    );
    assert!(
        candidates
            .iter()
            .any(|candidate| candidate.contains("a.rs:1"))
            && candidates
                .iter()
                .any(|candidate| candidate.contains("b.rs:1")),
        "candidates must name their paths: {candidates:?}"
    );
    // The same shared resolution must unblock impact, not only refs.
    let impact = reader
        .impact(&ImpactQuery {
            target: AtlasTarget::Symbol(SymbolSelector::Name {
                name: QueryText::new("Foo")?,
                path: Some(RelativePath::new("foo.rs")?),
                container: None,
                kind: None,
                line: None,
            }),
            depth: 1,
            include_name_only: false,
            next: None,
            budget,
        })?
        .data;
    match impact {
        Read::Present { .. } => Ok(()),
        other => Err(format!("impact refused: {other:?}").into()),
    }
}
