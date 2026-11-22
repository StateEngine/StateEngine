//! Atlas query contract on a real parsed and published index: exit codes,
//! positional targets, loose-guess fallbacks, BOM-free spans and relative
//! `--since` paging, read through the same CLI and MCP decoders users hit.
//! Debug budgets run on a paused Atlas clock; this is not latency evidence.
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
#[path = "../../test-support/atlas_clock.rs"]
mod test_clock;
use se_atlas::{
    cache::{connection::*, *},
    lifecycle::*,
    model::*,
    parse::*,
    query::{QueryReader, ReaderContext, RecordReader},
    resolve::{self, catalog::SqlCatalog},
    source::RegisteredSource,
    update::{batch, file},
};
use se_core::ops::{AnyOp, AnyOutput, AtlasRead};
use se_host::{
    McpBackend, McpReply, atlas_cache::NativeAtlasCache, atlas_source::NativeAtlasSource,
};
use se_types::{OmissionReason, Read, Secret, code::*};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;
type Outcome<T> = Result<T, Box<dyn std::error::Error>>;
// The production SQL writer slot is process-global.
static CASE_LOCK: Mutex<()> = Mutex::new(());

const LIB: &str = "pub fn invalid() -> u32 { 1 }
pub fn missing() -> u32 { 2 }
pub fn target() -> u32 { invalid() + missing() }
pub fn caller() -> u32 { target() }
pub fn twin() -> u32 { 3 }
pub fn wide() -> u32 {
    6
}
pub fn uses_wide() -> u32 { wide() }
";
const INNER: &str = "pub fn twin() -> u32 { 4 }\n";
const BOM: &str = "\u{feff}pub fn bom_marker() -> u32 { 5 }
pub const MID: &str = \"mid_marker x\u{feff}y\";
";

fn deadline() -> Instant {
    se_atlas::clock::now() + Duration::from_secs(5)
}
fn now_ms() -> Outcome<i64> {
    Ok(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}
fn budget() -> ParseBudget {
    ParseBudget {
        max_source_bytes: 524_288,
        max_rows: 4096,
        max_work: Duration::from_millis(200),
        reserved_bytes: 16_000_000,
    }
}
struct NoRecords;
impl RecordReader for NoRecords {
    fn read(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> se_types::Result<Read<RecordHit>> {
        Ok(Read::Absent {
            checked: "fixture has no records".into(),
        })
    }
    fn literal_read(
        &self,
        p: &se_types::ProjectId,
        v: &AtlasPrincipal,
        r: &RecordPointer,
        _: &QueryText,
    ) -> se_types::Result<Read<RecordHit>> {
        self.read(p, v, r, None)
    }
    fn body(
        &self,
        _: &se_types::ProjectId,
        _: &AtlasPrincipal,
        _: &RecordPointer,
        _: Option<&QueryText>,
    ) -> se_types::Result<Read<HitBody>> {
        Ok(Read::Absent {
            checked: "fixture has no records".into(),
        })
    }
}

/// One published index over `LIB`, `INNER` and `BOM`, parsed by the real
/// semantic parser and resolver, read through the public query adapter.
struct Atlas<'c, 's> {
    db: CacheConnection<'c>,
    source: &'s RegisteredSource<NativeAtlasSource>,
    root: &'s Path,
    parser: SemanticParser,
    viewer: AtlasPrincipal,
}
impl Atlas<'_, '_> {
    fn ingest(&mut self, path: &str, cold: bool, serial: u64, observed_ms: i64) -> Check {
        let path = RelativePath::new(path)?;
        let SourceRead::Bytes(snapshot) = self.source.read(&path, budget())? else {
            return Err(format!("fixture source {} unreadable", path.as_str()).into());
        };
        let mut parsed = self.parser.parse(&snapshot, Language::Rust, budget())?;
        self.db.read(deadline(), |sql| {
            let mut catalog = SqlCatalog {
                sql,
                deadline: deadline(),
            };
            resolve::resolve(&mut parsed, &path, &mut catalog, deadline()).map(|_| ())
        })?;
        let scope = self.source.scope.clone();
        self.db.write(2_000_000, deadline(), |sql| {
            if !cold {
                batch::begin(sql, serial, BulkReason::FilesystemBurst, false)?;
            }
            file::apply(sql, &scope, &snapshot, &parsed, cold, serial)?;
            if !cold {
                batch::publish(sql, observed_ms, false)?;
            }
            Ok(())
        })?;
        Ok(())
    }
    fn edit(&mut self, path: &str, text: &str, serial: u64, observed_ms: i64) -> Check {
        fs::write(self.root.join(path), text)?;
        self.ingest(path, false, serial, observed_ms)
    }
    /// A complete index is `Current` with every discovered file indexed;
    /// otherwise it is `Partial`, as while a scan is still unfinished.
    fn set_complete(&mut self, complete: bool) -> Check {
        let state = if complete {
            IndexState::Current
        } else {
            IndexState::Partial {
                error: se_types::SeError::invalid("fixture scan", "unfinished").body,
            }
        };
        let coverage = json!({"discovered_files":3,"indexed_files":3,"partial_files":0,
            "deferred_files":0,"failed_files":0,"discovery_complete":complete,"stale_files":0,
            "resolved_references":0,"name_only_references":0,"watched_directories":0,
            "unwatched_directories":0,"watch_discovery_complete":true,"watch_stats_started":null,
            "watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]});
        let (state, coverage) = (serde_json::to_string(&state)?, coverage.to_string());
        self.db.write(1_000_000, deadline(), |sql| {
            sql.prepare("UPDATE meta SET state_json=?1,coverage_json=?2 WHERE singleton=1")?
                .execute([state.as_str(), coverage.as_str()])
                .map_err(|e| se_types::SeError::invalid("fixture meta", &e.to_string()))?;
            Ok(())
        })?;
        Ok(())
    }
    fn run(&mut self, operation: &AnyOp) -> se_types::Result<AnyOutput> {
        let request = match operation.clone() {
            AnyOp::AtlasFind(v) => AtlasRead::Find(v),
            AnyOp::AtlasRefs(v) => AtlasRead::Refs(v),
            AnyOp::AtlasImpact(v) => AtlasRead::Impact(v),
            AnyOp::AtlasChanges(v) => AtlasRead::Changes(v),
            AnyOp::AtlasOutline(v) => AtlasRead::Outline(v),
            _ => return Err(se_types::SeError::invalid("fixture", "an Atlas read")),
        };
        let mut reader = QueryReader::new(
            &mut self.db,
            ReaderContext {
                memory: None,
                viewer: self.viewer.clone(),
                records: &NoRecords,
                source: Some(self.source),
                hostless: false,
                epoch_retired: false,
                now_unix_ms: now_ms().ok(),
                record_feed_current: true,
            },
        );
        se_host::atlas_queries::execute(&mut reader, &request)
    }
}
fn with_atlas(body: impl FnOnce(&mut Atlas<'_, '_>) -> Check) -> Check {
    // One failed case must not fail every later one through a poisoned lock.
    let _case = CASE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    se_proc::initialize_file_creation_owner()?;
    let dir = cleanup_directory::private_case_directory()?;
    let root = dir.join("source");
    fs::create_dir_all(root.join("src").join("deep"))?;
    fs::write(root.join("src/lib.rs"), LIB)?;
    fs::write(root.join("src/deep/inner.rs"), INNER)?;
    fs::write(root.join("src/bom.rs"), BOM)?;
    let project = se_types::ProjectId::from_parts(1, [61; 10])?;
    let root_id = RootId::from_parts(1, [62; 10])?;
    let home = dir.join("atlas");
    let source = NativeAtlasSource::open(
        RootRegistration {
            project: project.clone(),
            root: root_id.clone(),
            canonical_source_root: root.clone(),
            cache: CacheLocation {
                directory: home.join(project.as_str()).join(root_id.as_str()),
            },
            git_metadata: None,
        },
        CaseMode::Sensitive,
    )?;
    let cache = NativeAtlasCache::create(&home, source.scope.clone())?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope: source.scope.clone(),
            epoch: CacheEpoch::from_parts(1, [63; 10])?,
        },
        extractor_version: "query-contract-fixture".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage: serde_json::from_value(json!({"discovered_files":0,"indexed_files":0,
            "partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":false,
            "stale_files":0,"resolved_references":0,"name_only_references":0,
            "watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":false,
            "watch_stats_started":null,"watch_activation_attempts":0,
            "watch_limited_activations":0,"reasons":[]}))?,
        state: IndexState::Current,
    };
    let db = CacheConnection::create(
        &cache,
        &seed,
        ConnectionRole::HostWriter,
        &SqlProfile::from_qualified_overhead(1)?,
        deadline(),
    )?;
    let parser = SemanticParser::cold_child(
        source.scope.clone(),
        vec![ParserProfile::from_qualified_measurement(
            Language::Rust,
            ParserPlacement::ColdChild,
            524_288,
            4096,
            4_000_000,
            8_000_000,
        )?],
    )?;
    let mut atlas = Atlas {
        db,
        source: &source,
        root: &root,
        parser,
        viewer: AtlasPrincipal::Agent(se_types::AgentId::from_parts(1, [64; 10])?),
    };
    // Parse slices run on a paused clock; queries keep the same frozen budget.
    let _clock = test_clock::control();
    for path in ["src/lib.rs", "src/deep/inner.rs", "src/bom.rs"] {
        atlas.ingest(path, true, 0, 0)?;
    }
    atlas.set_complete(true)?;
    dir.finish(body(&mut atlas))
}

fn cli(argv: &[&str]) -> se_types::Result<AnyOp> {
    let matches = se_cli_spec::cli_command()
        .try_get_matches_from(argv)
        .map_err(|e| se_types::SeError::invalid("fixture argv", &e.to_string()))?;
    let operation = se_cli_spec::from_matches(&matches)?;
    operation.validate()?;
    Ok(operation)
}
fn mcp(tool: &str, arguments: Value) -> se_types::Result<AnyOp> {
    let operation = se_core::ops::decode_tool(tool, arguments)?;
    operation.validate()?;
    Ok(operation)
}
/// The CLI's exit: `--require-complete` from the parsed options, else the default.
fn exit(operation: &AnyOp, output: &AnyOutput) -> Outcome<u8> {
    let options = operation.atlas_options().ok_or("not an Atlas operation")?;
    Ok(output
        .atlas_exit(options.require_complete)
        .ok_or("not an Atlas output")?)
}
fn hits(output: &AnyOutput) -> Outcome<&SearchResults> {
    let AnyOutput::AtlasFind(found) = output else {
        return Err("not a find output".into());
    };
    let Read::Present { value } = &found.value.answer.data else {
        return Err(format!("find was not present: {:?}", found.value.answer.data).into());
    };
    Ok(value)
}
fn names(results: &SearchResults) -> Vec<String> {
    results
        .page
        .items()
        .iter()
        .filter_map(|hit| match &hit.target {
            HitTarget::Code(code) => Some(code.name.clone()),
            _ => None,
        })
        .collect()
}
fn compact(output: &AnyOutput) -> Outcome<String> {
    Ok(se_host::atlas_queries::compact(output, 16_384, false)?.ok_or("no compact text")?)
}

#[test]
fn a_real_hit_exits_zero_even_while_the_index_is_partial() -> Check {
    with_atlas(|atlas| {
        let find = cli(&["se", "atlas", "find", "caller", "--kind", "symbol"])?;
        let strict = cli(&[
            "se",
            "atlas",
            "find",
            "caller",
            "--kind",
            "symbol",
            "--require-complete",
        ])?;
        let empty = cli(&["se", "atlas", "find", "absent_name", "--kind", "symbol"])?;
        atlas.set_complete(false)?;
        let found = atlas.run(&find)?;
        assert_eq!(names(hits(&found)?), ["caller"]);
        assert_eq!(
            found.exit_code(),
            0,
            "a real hit on a partial index is an answer"
        );
        assert_eq!(
            exit(&strict, &atlas.run(&strict)?)?,
            2,
            "--require-complete refuses a gap"
        );
        let none = atlas.run(&empty)?;
        assert!(hits(&none)?.page.items().is_empty());
        assert_eq!(
            none.exit_code(),
            2,
            "an empty partial answer is not a confirmed zero"
        );
        assert!(compact(&none)?.contains("no matches (incomplete;"));
        atlas.set_complete(true)?;
        let none = atlas.run(&empty)?;
        assert_eq!(
            none.exit_code(),
            0,
            "an empty complete answer is a confirmed zero"
        );
        assert!(compact(&none)?.starts_with("no matches\n"));
        Ok(())
    })
}

#[test]
fn a_page_limit_is_not_a_gap_but_an_incomplete_source_outranks_it() -> Check {
    with_atlas(|atlas| {
        let twin = |extra: &[&'static str]| {
            let mut argv = vec!["se", "atlas", "find", "twin", "--kind", "symbol"];
            argv.extend(["--mode", "exact", "--limit", "1"]);
            argv.extend(extra);
            cli(&argv)
        };
        let strict = twin(&["--require-complete"])?;
        let first = atlas.run(&strict)?;
        let page = &hits(&first)?.page;
        assert_eq!(page.items().len(), 1);
        assert!(
            page.next().is_some(),
            "two twins over a one-hit page leave a cursor"
        );
        assert_eq!(page.window().omitted().reason, Some(OmissionReason::Limit));
        assert_eq!(
            exit(&strict, &first)?,
            0,
            "pagination alone satisfies --require-complete"
        );
        atlas.set_complete(false)?;
        let partial = atlas.run(&twin(&[])?)?;
        let page = &hits(&partial)?.page;
        assert!(page.next().is_some());
        assert_eq!(
            page.window().omitted().reason,
            Some(OmissionReason::SourceIncomplete),
            "a cursor must never hide an incomplete source"
        );
        Ok(())
    })
}

#[test]
fn mcp_marks_a_require_complete_rejection_as_an_error_result() -> Check {
    struct Fixed(Value);
    impl McpBackend for Fixed {
        async fn check_session(&mut self, _: Arc<Secret>) -> se_types::Result<()> {
            Ok(())
        }
        async fn call(&mut self, _: Arc<Secret>, operation: AnyOp) -> se_types::Result<Value> {
            operation.validate()?;
            Ok(self.0.clone())
        }
        fn response_limit(&self) -> usize {
            65_536
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let ask = |output: &AnyOutput, format: &str| -> Outcome<Value> {
        let arguments = json!({"query":"caller","kind":"symbol","require_complete":true,
            "format":format});
        let request = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"stateengine_atlas_find","arguments":arguments}}))?;
        let mut backend = Fixed(serde_json::to_value(output)?);
        let McpReply::Json(reply) = runtime.block_on(se_host::mcp::dispatch(
            &request,
            Some(Arc::new(Secret::new(vec![7; 32])?)),
            &mut backend,
        )) else {
            return Err("missing MCP reply".into());
        };
        Ok(reply["result"]["isError"].clone())
    };
    with_atlas(|atlas| {
        let find = mcp(
            "stateengine_atlas_find",
            json!({"query":"caller","kind":"symbol"}),
        )?;
        let complete = atlas.run(&find)?;
        atlas.set_complete(false)?;
        let partial = atlas.run(&find)?;
        for format in ["compact", "json"] {
            assert_eq!(ask(&complete, format)?, false, "{format}: complete answer");
            assert_eq!(
                ask(&partial, format)?,
                true,
                "{format}: gap under require_complete"
            );
        }
        Ok(())
    })
}

#[test]
fn policy_denied_outline_is_a_refusal_not_an_empty_file() -> Check {
    with_atlas(|atlas| {
        let outline = cli(&["se", "atlas", "outline", ".env"])?;
        let output = atlas.run(&outline)?;
        let AnyOutput::AtlasOutline(answer) = &output else {
            return Err("not an outline".into());
        };
        assert!(matches!(answer.value.answer.data, Read::Unknown { .. }));
        assert_eq!(output.exit_code(), 4);
        Ok(())
    })
}

#[test]
fn an_unmatched_token_never_splits_into_invented_or_matches() -> Check {
    with_atlas(|atlas| {
        // Both fragments name real symbols; the whole token names nothing.
        let garbage = cli(&["se", "atlas", "find", "nope.invalid/missing"])?;
        let output = atlas.run(&garbage)?;
        let results = hits(&output)?;
        assert!(
            results.page.items().is_empty(),
            "fragments were reported as matches: {:?}",
            names(results)
        );
        assert_eq!(output.exit_code(), 0);
        // A multi-word phrase may widen to loose words, labelled as guesses.
        let phrase = cli(&["se", "atlas", "find", "zzqx invalid", "--kind", "symbol"])?;
        let output = atlas.run(&phrase)?;
        let results = hits(&output)?;
        assert_eq!(results.fallback_from, Some(SearchMode::Phrase));
        assert!(matches!(
            results.mode,
            SearchMode::Broad | SearchMode::Related
        ));
        assert!(names(results).iter().any(|name| name == "invalid"));
        assert!(compact(&output)?.contains("loose guesses"));
        atlas.set_complete(false)?;
        let output = atlas.run(&phrase)?;
        assert!(!hits(&output)?.page.items().is_empty());
        assert_eq!(output.exit_code(), 2, "loose guesses never count as hits");
        Ok(())
    })
}

#[test]
fn compact_find_accepts_a_budget_above_the_old_32_kib_ceiling() -> Check {
    with_atlas(|atlas| {
        let find = cli(&["se", "atlas", "find", "target", "--budget", "65536"])?;
        let output = atlas.run(&find)?;
        assert!(names(hits(&output)?).iter().any(|name| name == "target"));
        assert!(se_host::atlas_queries::compact(&output, 65_536, false)?.is_some());
        assert_eq!(output.exit_code(), 0);
        Ok(())
    })
}

#[test]
fn positional_impact_targets_resolve_as_path_line_or_symbol() -> Check {
    with_atlas(|atlas| {
        let impact = |target: &str| cli(&["se", "atlas", "impact", target, "--depth", "1"]);
        let callers = |output: &AnyOutput| -> Outcome<usize> {
            let AnyOutput::AtlasImpact(answer) = output else {
                return Err("not an impact".into());
            };
            match &answer.value.answer.data {
                Read::Present { value } => Ok(value.dependents.len()),
                other => Err(format!("target did not resolve: {other:?}").into()),
            }
        };
        for target in ["src/lib.rs", "src\\lib.rs", "src\\deep\\inner.rs"] {
            let output = atlas.run(&impact(target)?)?;
            callers(&output)?;
            assert_eq!(output.exit_code(), 0, "{target}");
        }
        // `wide` spans lines 6-8 and `uses_wide` calls it; one-line `target`
        // on line 3 is called by `caller`. A line names the symbol on it.
        for target in ["src/lib.rs:6", "src/lib.rs:7", "target", "src/lib.rs:3"] {
            let output = atlas.run(&impact(target)?)?;
            assert!(callers(&output)? >= 1, "{target} lost its caller");
            assert_eq!(output.exit_code(), 0, "{target}");
        }
        let unknown = impact("no_such_target")?;
        let error = atlas
            .run(&unknown)
            .err()
            .ok_or("an unresolved target on a complete index was not refused")?;
        assert_eq!(error.body.class().exit_code(), 64, "{error}");
        atlas.set_complete(false)?;
        let output = atlas.run(&unknown)?;
        assert_eq!(output.exit_code(), 2, "it may still appear while indexing");
        Ok(())
    })
}

#[test]
fn a_leading_bom_is_not_content_but_an_inner_one_is() -> Check {
    with_atlas(|atlas| {
        let text = |query: &str| cli(&["se", "atlas", "find", query, "--kind", "text"]);
        let output = atlas.run(&text("bom_marker")?)?;
        let first = hits(&output)?
            .page
            .items()
            .iter()
            .find_map(|hit| match &hit.target {
                HitTarget::Code(code) if code.pointer.path.as_str() == "src/bom.rs" => Some(code),
                _ => None,
            })
            .ok_or("no text hit in src/bom.rs")?;
        assert!(
            first.name.starts_with("pub fn bom_marker"),
            "{:?}",
            first.name
        );
        let span = first.pointer.span.ok_or("text hit has no span")?;
        assert_eq!((span.start.line, span.start.byte_column), (1, 3));
        assert_eq!(span.start_byte, 3);
        let output = atlas.run(&text("mid_marker")?)?;
        assert!(
            names(hits(&output)?)
                .iter()
                .any(|name| name.contains("x\u{feff}y")),
            "an inner U+FEFF is content"
        );
        Ok(())
    })
}

#[test]
fn full_bodies_keep_lines_and_tabs_but_escape_terminal_controls() {
    let shown = se_atlas::render::escape_body("a\r\n\tb\x1b[31m\u{9b}");
    assert_eq!(shown, "a\n\tb\\u{1b}[31m\\u{9b}");
    assert_eq!(se_atlas::render::escape("a\nb"), "a\\nb");
}

#[test]
fn relative_since_keeps_its_cursor_across_pages_on_cli_and_mcp() -> Check {
    with_atlas(|atlas| {
        let now = now_ms()?;
        atlas.edit(
            "src/lib.rs",
            &format!("{LIB}pub fn early() {{}}\n"),
            1,
            now - 3 * 3_600_000,
        )?;
        atlas.edit(
            "src/lib.rs",
            &format!("{LIB}pub fn later() {{}}\n"),
            2,
            now - 120_000,
        )?;
        atlas.edit(
            "src/deep/inner.rs",
            &format!("{INNER}pub fn last() {{}}\n"),
            3,
            now - 60_000,
        )?;
        let page = |output: &AnyOutput| -> Outcome<(Vec<ChangeId>, Option<String>)> {
            let AnyOutput::AtlasChanges(answer) = output else {
                return Err("not a changes output".into());
            };
            let Read::Present { value } = &answer.value.answer.data else {
                return Err(format!("changes not present: {:?}", answer.value.answer.data).into());
            };
            let ids = value.items().iter().map(|change| match change {
                CodeChange::Edit(edit) => edit.id,
                CodeChange::Bulk(bulk) => bulk.id,
            });
            Ok((ids.collect(), value.next().map(|n| n.as_str().to_owned())))
        };
        let (first, next) = page(&atlas.run(&cli(&[
            "se", "atlas", "changes", "--since", "10m", "--limit", "1",
        ])?)?)?;
        let next = next.ok_or("changes in two recent generations fit one page")?;
        assert!(first.iter().all(|id| id.generation.0 >= 2), "{first:?}");
        let (second, _) = page(&atlas.run(&cli(&[
            "se", "atlas", "changes", "--since", "10m", "--limit", "1", "--cursor", &next,
        ])?)?)?;
        assert_eq!(second.len(), 1);
        let order = |id: &ChangeId| (id.generation.0, id.ordinal);
        assert!(
            order(&second[0]) > order(&first[0]),
            "page two repeated or went back: {second:?}"
        );
        let (_, mcp_next) = page(&atlas.run(&mcp(
            "stateengine_atlas_changes",
            json!({"since":"10m","limit":1}),
        )?)?)?;
        let mcp_next = mcp_next.ok_or("MCP page one had no cursor")?;
        let resumed = mcp(
            "stateengine_atlas_changes",
            json!({"since":"10m","limit":1,"cursor":mcp_next}),
        )?;
        assert_eq!(page(&atlas.run(&resumed)?)?.0, second);
        let changed = mcp(
            "stateengine_atlas_changes",
            json!({"since":"2h","limit":1,"cursor":next}),
        )?;
        let error = atlas
            .run(&changed)
            .err()
            .ok_or("a different --since reused the cursor")?;
        assert!(error.to_string().contains("CursorQueryMismatch"), "{error}");
        Ok(())
    })
}
