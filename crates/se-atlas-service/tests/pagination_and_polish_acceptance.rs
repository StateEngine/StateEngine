#![forbid(unsafe_code)]
//! Reviewer acceptance tests for exact byte-budget paging, mid-file line-offset
//! resume in `refs`, resumed-page deadline edge cases, `changes` byte-budget
//! paging, `outline` byte-budget trimming, and `impact` accuracy and deadline.

mod support;

use se_atlas_index::{
    custody::IndexSourceRoot,
    store::{BuildOptions, Reader, Store, StoreIdentity},
};
use se_atlas_query::{Answer as Found, Target, refs::RefsRequest};
use se_types::{
    Cursor, Detail, Page, Read, SeError, StopReason,
    code::{
        Accuracy, AtlasCursor, AtlasTarget, AtlasText as _, ChangeBaseline, CodeChange,
        CoverageReason, ImpactQuery, OutlineQuery, QueryBudget, ReferenceHit, RefsQuery,
        RelativePath, SearchScope,
    },
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;
use support::*;

fn build_query_repo(
    label: &str,
    files: &[(&str, &str)],
) -> Result<(TempDir, TempDir, IndexSourceRoot, PathBuf), Box<dyn std::error::Error>> {
    let repo = TempDir::new(&format!("{label}-repo"))?;
    let state = TempDir::new(&format!("{label}-state"))?;
    for (path, text) in files {
        repo.write(path, text)?;
    }
    let root = IndexSourceRoot::open(repo.path())?;
    let db = state.join("atlas.db");
    let (mut store, _) = Store::open(&db, &StoreIdentity::default())?;
    store.cold_build(&root, &BuildOptions::default())?;
    Ok((repo, state, root, db))
}

fn query_reader(db: &std::path::Path) -> se_atlas_index::Result<Reader> {
    Reader::open(db)
}

fn refs_query(
    target: AtlasTarget,
    max_results: u16,
    max_bytes: u32,
    next: Option<AtlasCursor>,
) -> se_types::Result<RefsQuery> {
    Ok(RefsQuery {
        target,
        kinds: Vec::new(),
        include_name_only: false,
        next,
        budget: QueryBudget {
            max_results,
            max_bytes,
            work: Duration::from_millis(250),
        }
        .checked()?,
    })
}

fn refs_lines(page: &Page<ReferenceHit>) -> Vec<(String, u32)> {
    page.items()
        .iter()
        .filter_map(|hit| match hit {
            ReferenceHit::Code(r) => {
                let line = r.site.span.as_ref().map_or(0, |s| s.start.line);
                Some((r.site.path.as_str().to_owned(), line))
            }
            _ => None,
        })
        .collect()
}

fn changes_query_with_bytes(
    since: ChangeBaseline,
    max_results: u16,
    max_bytes: u32,
    next: Option<AtlasCursor>,
) -> se_types::Result<se_types::code::ChangesQuery> {
    Ok(se_types::code::ChangesQuery {
        since,
        scope: SearchScope {
            paths: Vec::new(),
            languages: Vec::new(),
        },
        next,
        budget: QueryBudget {
            max_results,
            max_bytes,
            work: Duration::from_millis(250),
        }
        .checked()?,
    })
}

fn scoped_changes_query(
    since: ChangeBaseline,
    max_results: u16,
    max_bytes: u32,
    scope_path: &str,
    next: Option<AtlasCursor>,
) -> se_types::Result<se_types::code::ChangesQuery> {
    Ok(se_types::code::ChangesQuery {
        since,
        scope: SearchScope {
            paths: vec![RelativePath::new(scope_path)?],
            languages: Vec::new(),
        },
        next,
        budget: QueryBudget {
            max_results,
            max_bytes,
            work: Duration::from_millis(250),
        }
        .checked()?,
    })
}

fn cursor_to_atlas(c: &Cursor) -> se_types::Result<AtlasCursor> {
    AtlasCursor::new(c.as_str())
}

fn assert_over_budget(result: se_types::Result<impl std::fmt::Debug>, label: &str) -> TestResult {
    if let Err(SeError { body, .. }) = &result
        && matches!(body.detail(), Detail::AtlasResourceBudget(_))
    {
        return Ok(());
    }
    Err(format!("expected AtlasResourceBudget on {label}, got {result:?}").into())
}

type RefsWalk = (Vec<(String, u32)>, usize);

fn walk_refs_pages(
    root: &se_atlas_service::Root,
    symbol: &str,
    tight: u32,
) -> Result<RefsWalk, Box<dyn std::error::Error>> {
    let mut collected = Vec::new();
    let mut cursor: Option<AtlasCursor> = None;
    let mut pages = 0usize;
    loop {
        let q = refs_query(
            AtlasTarget::Auto(se_types::code::QueryText::new(symbol)?),
            200,
            tight,
            cursor.clone(),
        )?;
        let ans = root.refs(&q)?;
        pages += 1;
        let page_json = serde_json::to_vec(&ans)?;
        let page = present(ans.data)?;
        assert!(
            page_json.len() <= tight as usize,
            "page {pages} JSON {} > budget {tight}",
            page_json.len()
        );
        collected.extend(refs_lines(&page));
        let next = page.next().map(cursor_to_atlas).transpose()?;
        if next.is_some() {
            assert!(!page.items().is_empty(), "non-final page {pages} empty");
            assert_ne!(next, cursor, "cursor must progress on page {pages}");
        }
        if next.is_none() {
            break;
        }
        cursor = next;
    }
    Ok((collected, pages))
}

// ── Test 1: refs exact byte-budget paging & mid-file line-offset resume ──

#[test]
fn refs_byte_budget_paging_and_mid_file_resume() -> TestResult {
    let symbol = "dispatch";
    let mut owned: Vec<(String, String)> = Vec::new();
    owned.push((
        "src/hub.js".into(),
        format!("export function {symbol}() {{}}\n"),
    ));
    for i in 0..6 {
        let mut body = format!("import {{ {symbol} }} from './hub.js';\n");
        for j in 1..=8 {
            body.push_str(&format!("function caller{i}_{j}() {{ {symbol}(); }}\n"));
        }
        owned.push((format!("src/use{i:02}.js"), body));
    }
    let file_refs: Vec<(&str, &str)> = owned
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let mut live = LiveRoot::start("refs-budget-page", &file_refs)?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    let full_q = refs_query(
        AtlasTarget::Auto(se_types::code::QueryText::new(symbol)?),
        200,
        65_536,
        None,
    )?;
    let full_ans = live.root()?.refs(&full_q)?;
    let full_page = present(full_ans.data)?;
    let total_lines = refs_lines(&full_page);
    assert!(total_lines.len() >= 40, "expected >= 40 refs lines");
    let full_json = serde_json::to_vec(&full_page)?;
    let tight = (full_json.len() / 4).max(512) as u32;

    let (collected, pages) = walk_refs_pages(live.root()?, symbol, tight)?;
    assert!(pages >= 2, "tight budget must split into >= 2 pages");
    let full_set: BTreeSet<_> = total_lines.iter().collect();
    let paged_set: BTreeSet<_> = collected.iter().collect();
    assert_eq!(full_set.len(), total_lines.len(), "full has duplicates");
    assert_eq!(paged_set.len(), collected.len(), "paged has duplicates");
    assert_eq!(full_set, paged_set, "paged walk must recover every line");

    // Legacy file-only cursor (r<file> without .lines) resumes at line 0.
    let legacy_q = refs_query(
        AtlasTarget::Auto(se_types::code::QueryText::new(symbol)?),
        200,
        65_536,
        Some(AtlasCursor::new("r1")?),
    )?;
    let legacy_page = present(live.root()?.refs(&legacy_q)?.data)?;
    assert!(!legacy_page.items().is_empty(), "legacy cursor must resume");

    // Single hit larger than max_bytes returns AtlasResourceBudget.
    if let Ok(q) = refs_query(
        AtlasTarget::Auto(se_types::code::QueryText::new(symbol)?),
        200,
        64,
        None,
    ) {
        assert_over_budget(live.root()?.refs(&q), "tiny refs budget")?;
    }

    live.stop(STOP_TIMEOUT)
}

// ── Test 2: refs resumed-page deadline edge case ──

#[test]
fn refs_resumed_page_deadline_preserves_offset() -> TestResult {
    let files: &[(&str, &str)] = &[
        ("src/hub.js", "export function target_fn() {}\n"),
        (
            "src/a.js",
            "import { target_fn } from './hub.js';\ntarget_fn();\ntarget_fn();\ntarget_fn();\ntarget_fn();\n",
        ),
        (
            "src/b.js",
            "import { target_fn } from './hub.js';\ntarget_fn();\n",
        ),
    ];

    // Query layer: verify the fix preserves (cursor, cursor_lines) on zero deadline.
    let (_repo, _state, root, db) = build_query_repo("refs-deadline-offset", files)?;
    let reader = query_reader(&db)?;
    let mut req = RefsRequest::new(Target::Symbol("target_fn".into()));
    req.cursor = Some(1);
    req.cursor_lines = 3;
    req.deadline = Duration::ZERO;
    let Found::Found(result) = se_atlas_query::refs::refs(&reader, &root, &req)? else {
        return Err("refs with resumed cursor must return Found".into());
    };
    assert!(
        result.deadline_reached,
        "zero deadline must set deadline_reached"
    );
    assert_eq!(
        result.next_cursor,
        Some(1),
        "next_cursor must stay at the same file"
    );
    assert_eq!(
        result.next_lines, 3,
        "next_lines must preserve the original cursor_lines"
    );
    assert!(
        result.groups.is_empty(),
        "zero-deadline must produce no groups"
    );

    // Service layer: a refs query with a resumed cursor and zero deadline must not
    // produce a Page::new error (the pre-existing finding).
    let mut live = LiveRoot::start("refs-deadline-svc", files)?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    // Build a cursor pointing at file 0, lines 0 (simulates a resumed query).
    let resume_cursor = AtlasCursor::new("r0_0")?;
    let deadline_q = RefsQuery {
        target: AtlasTarget::Auto(se_types::code::QueryText::new("target_fn")?),
        kinds: Vec::new(),
        include_name_only: false,
        next: Some(resume_cursor.clone()),
        budget: QueryBudget {
            max_results: 200,
            max_bytes: 65_536,
            work: Duration::from_millis(1),
        }
        .checked()?,
    };
    let deadline_ans = live.root()?.refs(&deadline_q)?;
    match deadline_ans.data {
        Read::Present { value } => {
            if let Some(next) = value.next() {
                let next_atlas = cursor_to_atlas(next)?;
                assert_ne!(
                    next_atlas, resume_cursor,
                    "returned cursor must not equal the input cursor (non-progressing)"
                );
            }
        }
        other => {
            return Err(format!("expected Present on deadline refs, got {other:?}").into());
        }
    }

    live.stop(STOP_TIMEOUT)
}

// ── Test 3: changes exact byte-budget paging ──

fn walk_changes_pages(
    root: &se_atlas_service::Root,
    viewer: &se_types::code::AtlasPrincipal,
    tight: u32,
    since: &ChangeBaseline,
) -> Result<(Vec<CodeChange>, usize), Box<dyn std::error::Error>> {
    let mut collected = Vec::new();
    let mut cursor: Option<AtlasCursor> = None;
    let mut pages = 0usize;
    loop {
        let q = changes_query_with_bytes(since.clone(), 200, tight, cursor.clone())?;
        let ans = root.changes(&q, viewer)?;
        pages += 1;
        let page_json = serde_json::to_vec(&ans)?;
        let page = present(ans.data)?;
        assert!(page_json.len() <= tight as usize, "changes page > budget");
        let next = page.next().map(cursor_to_atlas).transpose()?;
        if next.is_some() {
            assert!(!page.items().is_empty(), "non-final changes page empty");
            assert_ne!(next, cursor, "changes cursor must progress");
        }
        collected.extend(page.items().iter().cloned());
        if next.is_none() {
            break;
        }
        cursor = next;
    }
    Ok((collected, pages))
}

#[test]
fn changes_byte_budget_paging_no_duplicates_or_drops() -> TestResult {
    let mut live = LiveRoot::start(
        "changes-budget",
        &[
            ("src/a.rs", "pub fn alpha() -> u32 { 1 }\n"),
            ("src/b.rs", "pub fn beta() -> u32 { 2 }\n"),
            ("src/c.rs", "pub fn gamma() -> u32 { 3 }\n"),
        ],
    )?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    for (path, text) in [
        (
            "src/a.rs",
            "pub fn alpha() -> u32 { 10 }\npub fn alpha2() -> u32 { 11 }\n",
        ),
        (
            "src/b.rs",
            "pub fn beta() -> u32 { 20 }\npub fn beta2() -> u32 { 21 }\n",
        ),
        (
            "src/c.rs",
            "pub fn gamma() -> u32 { 30 }\npub fn gamma2() -> u32 { 31 }\n",
        ),
    ] {
        live.repo.write(path, text)?;
    }
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;
    let viewer = se_types::code::AtlasPrincipal::Agent(agent_id(1)?);

    let full_q =
        changes_query_with_bytes(ChangeBaseline::ObservedUnixMillis(0), 200, 65_536, None)?;
    let full_ans = live.root()?.changes(&full_q, &viewer)?;
    let full_json = serde_json::to_vec(&full_ans)?;
    let full_page = present(full_ans.data)?;
    let total = full_page.items().len();
    assert!(total >= 3, "expected >= 3 changes, got {total}");
    let tight = (full_json.len() / 2).max(512) as u32;

    let since = ChangeBaseline::ObservedUnixMillis(0);
    let (collected, _pages) = walk_changes_pages(live.root()?, &viewer, tight, &since)?;
    assert_eq!(collected.len(), total, "paged walk must recover every item");

    // Scoped changes: filter to src/a.rs only.
    let scoped_q = scoped_changes_query(
        ChangeBaseline::ObservedUnixMillis(0),
        200,
        65_536,
        "src/a.rs",
        None,
    )?;
    let scoped_page = present(live.root()?.changes(&scoped_q, &viewer)?.data)?;
    for item in scoped_page.items() {
        if let CodeChange::Edit(e) = item {
            assert!(
                e.pointer.path.as_str().starts_with("src/a.rs"),
                "scoped edit path {}",
                e.pointer.path.as_str()
            );
        }
    }

    // Single row over-budget returns AtlasResourceBudget.
    if let Ok(q) = changes_query_with_bytes(ChangeBaseline::ObservedUnixMillis(0), 200, 64, None) {
        assert_over_budget(live.root()?.changes(&q, &viewer), "tiny changes budget")?;
    }

    live.stop(STOP_TIMEOUT)
}

// ── Test 4: outline byte-budget trimming ──

#[test]
fn outline_byte_budget_trims_symbols() -> TestResult {
    let mut body = String::new();
    for i in 0..60 {
        body.push_str(&format!(
            "export function symbol_{i:03}() {{ return {i}; }}\n"
        ));
    }
    let mut live = LiveRoot::start("outline-budget", &[("src/big.js", &body)])?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    let full_q = OutlineQuery {
        path: RelativePath::new("src/big.js")?,
        next: None,
        budget: budget(200, 65_536)?,
    };
    let full_ans = live.root()?.outline(&full_q, &DenyAllRecords)?;
    let full_json = serde_json::to_vec(&full_ans)?;
    let full_outline = present(full_ans.data)?;
    let full_count = full_outline.symbols.len();
    assert!(full_count >= 50, "expected >= 50 symbols, got {full_count}");
    assert!(full_outline.complete, "full outline must be complete");
    let tight = (full_json.len() / 3).max(256) as u32;
    let tight_q = OutlineQuery {
        path: RelativePath::new("src/big.js")?,
        next: None,
        budget: QueryBudget {
            max_results: 200,
            max_bytes: tight,
            work: Duration::from_millis(250),
        }
        .checked()?,
    };
    let tight_ans = live.root()?.outline(&tight_q, &DenyAllRecords)?;
    let tight_json = serde_json::to_vec(&tight_ans)?;
    assert!(
        tight_json.len() <= tight as usize,
        "trimmed outline JSON {} > budget {tight}",
        tight_json.len()
    );
    let tight_outline = present(tight_ans.data)?;
    assert!(
        !tight_outline.complete,
        "trimmed outline must have complete == false"
    );
    assert!(
        tight_outline.symbols.len() < full_count,
        "trimmed outline must have fewer symbols ({} vs {full_count})",
        tight_outline.symbols.len()
    );
    assert!(
        !tight_outline.symbols.is_empty(),
        "trimmed outline must have >= 1 symbol"
    );

    // AtlasResourceBudget when even the envelope is too large.
    let tiny_q = OutlineQuery {
        path: RelativePath::new("src/big.js")?,
        next: None,
        budget: QueryBudget {
            max_results: 200,
            max_bytes: 64,
            work: Duration::from_millis(250),
        }
        .checked()?,
    };
    match live.root()?.outline(&tiny_q, &DenyAllRecords) {
        Err(SeError { body, .. }) if matches!(body.detail(), Detail::AtlasResourceBudget(_)) => {}
        other => {
            return Err(format!(
                "expected AtlasResourceBudget on tiny outline budget, got {other:?}"
            )
            .into());
        }
    }

    live.stop(STOP_TIMEOUT)
}

// ── Test 5: impact Accuracy::ImportedFile & StopReason::Deadline ──

fn assert_has_imported_accuracy(deps: &[&se_types::code::Dependent], label: &str) -> TestResult {
    assert!(!deps.is_empty(), "{label} must appear");
    for dep in deps {
        let has = dep
            .hops
            .iter()
            .any(|h| h.accuracy == Accuracy::ImportedFile)
            || dep
                .file_hops
                .iter()
                .any(|h| h.accuracy == Accuracy::ImportedFile);
        assert!(has, "{label} hops must carry Accuracy::ImportedFile");
    }
    Ok(())
}

#[test]
fn impact_imported_file_accuracy_and_deadline_stop_reason() -> TestResult {
    let mut live = LiveRoot::start(
        "impact-acc-dl",
        &[
            ("src/core.js", "export function compute() {}\n"),
            (
                "src/importer.js",
                "import { compute } from './core.js';\ncompute();\n",
            ),
            (
                "test/core.test.js",
                "import { compute } from '../src/core.js';\ncompute();\n",
            ),
            ("src/name_only.js", "function loose() { compute(); }\n"),
        ],
    )?;
    let _ = wait_current(live.root()?, SETTLE_TIMEOUT)?;

    let full_q = ImpactQuery {
        target: AtlasTarget::Auto(se_types::code::QueryText::new("compute")?),
        depth: 2,
        include_name_only: true,
        next: None,
        budget: budget(50, 65_536)?,
    };
    let impact = present(live.root()?.impact(&full_q, &DenyAllRecords)?.data)?;
    let importers: Vec<_> = impact
        .dependents
        .iter()
        .filter(|d| d.pointer.path.as_str() == "src/importer.js")
        .collect();
    assert_has_imported_accuracy(&importers, "src/importer.js")?;
    let tests: Vec<_> = impact
        .tests
        .iter()
        .filter(|d| d.pointer.path.as_str() == "test/core.test.js")
        .collect();
    assert_has_imported_accuracy(&tests, "test/core.test.js")?;

    // Deadline-stopped page must carry StopReason::Deadline + CoverageReason::TimeLimit.
    let deadline_refs_q = RefsQuery {
        target: AtlasTarget::Auto(se_types::code::QueryText::new("compute")?),
        kinds: Vec::new(),
        include_name_only: false,
        next: None,
        budget: QueryBudget {
            max_results: 200,
            max_bytes: 65_536,
            work: Duration::from_millis(1),
        }
        .checked()?,
    };
    let deadline_ans = live.root()?.refs(&deadline_refs_q)?;
    let deadline_page = present(deadline_ans.data)?;
    let stop = deadline_page.window().fields().map(|f| f.stop_reason);
    assert_eq!(stop, Some(StopReason::Deadline));
    assert!(
        deadline_ans
            .index
            .coverage
            .reasons
            .contains(&CoverageReason::TimeLimit)
    );

    live.stop(STOP_TIMEOUT)
}
