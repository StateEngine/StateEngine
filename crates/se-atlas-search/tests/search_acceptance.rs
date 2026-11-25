//! Reviewer acceptance tests for Atlas search, driven end to end: real files
//! in a temporary tree, a real cold build and incremental updates, and
//! `se_atlas_search::search` reading candidates back through custody.
use rusqlite::Connection;
use se_atlas_index::{
    custody::IndexSourceRoot,
    extract::imports::Resolver,
    store::{BuildOptions, PathOutcome, Reader, Store, StoreIdentity},
    walk::{self, WalkOptions},
};
use se_atlas_search::{
    Hit, HitField, HitSource, KindFilter, MatchKind, QueryMode, ScanReason, SearchOutcome,
    SearchRequest, search,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Generous enough that a loaded test host never trips the soft deadline.
const ROOMY: Duration = Duration::from_secs(60);

struct TempDir {
    path: PathBuf,
    junctions: Vec<PathBuf>,
}

impl TempDir {
    fn new(label: &str) -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "se-atlas-search-accept-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(Self {
            path,
            junctions: Vec::new(),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn join(&self, relative: &str) -> PathBuf {
        relative
            .split('/')
            .fold(self.path.clone(), |acc, part| acc.join(part))
    }

    fn write(&self, relative: &str, text: &str) -> io::Result<()> {
        let full = self.join(relative);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(full, text)
    }

    #[cfg(windows)]
    fn add_junction(&mut self, relative: &str, target: &Path) -> io::Result<()> {
        let link = self.join(relative);
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)?;
        }
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(target)
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!("mklink /J failed: {stderr}")));
        }
        self.junctions.push(link);
        Ok(())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Remove junctions first so teardown never walks into their targets.
        for link in self.junctions.drain(..) {
            let _ = fs::remove_dir(&link);
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A built index over one temporary tree.
struct Indexed {
    root: IndexSourceRoot,
    store: Store,
    reader: Reader,
    _state: TempDir,
}

impl Indexed {
    fn build(repo: &TempDir) -> Result<Self, Box<dyn std::error::Error>> {
        let root = IndexSourceRoot::open(repo.path())?;
        let state = TempDir::new("state")?;
        let db = state.join("atlas.db");
        let (mut store, _) = Store::open(&db, &StoreIdentity::default())?;
        let report = store.cold_build(&root, &BuildOptions::default())?;
        assert!(report.discovery_complete, "cold build must finish");
        let reader = Reader::open(&db)?;
        Ok(Self {
            root,
            store,
            reader,
            _state: state,
        })
    }

    fn find(&self, request: &SearchRequest) -> Result<SearchOutcome, Box<dyn std::error::Error>> {
        Ok(search(&self.reader, &self.root, request)?)
    }

    fn text(&self, query: &str) -> Result<SearchOutcome, Box<dyn std::error::Error>> {
        self.find(&request(query))
    }

    fn reindex(&mut self, path: &str) -> Result<PathOutcome, Box<dyn std::error::Error>> {
        let discovery = walk::discover(&self.root, &WalkOptions::default())?;
        let mut resolver = Resolver::new(discovery.files.iter().map(String::as_str));
        Ok(self.store.index_path(&self.root, &mut resolver, path)?)
    }

    fn conn(&self) -> &Connection {
        self.reader.connection()
    }
}

fn request(query: &str) -> SearchRequest {
    let mut request = SearchRequest::new(query);
    request.deadline = ROOMY;
    request
}

fn kind(query: &str, kind: KindFilter) -> SearchRequest {
    let mut request = request(query);
    request.kind = kind;
    request
}

fn regex(query: &str) -> SearchRequest {
    let mut request = request(query);
    request.mode = QueryMode::Regex;
    request
}

fn describe(hits: &[Hit]) -> String {
    hits.iter()
        .map(|hit| {
            format!(
                "{}:{} {:?} {:?} {:?}",
                hit.path, hit.line, hit.field, hit.match_kind, hit.text
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn assert_no_duplicate_places(hits: &[Hit]) {
    let mut places: Vec<(&str, u32)> = hits
        .iter()
        .filter(|hit| hit.line > 0)
        .map(|hit| (hit.path.as_str(), hit.line))
        .collect();
    let before = places.len();
    places.sort_unstable();
    places.dedup();
    assert_eq!(before, places.len(), "duplicate place:\n{}", describe(hits));
}

/// `sym` rows named `name` in files with a smaller id than the file at
/// `path`: the rows a `LIMIT` would read before reaching it.
fn symbols_before(conn: &Connection, name: &str, path: &str) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM sym s JOIN vocab v ON v.id = s.name
         WHERE v.tok = ?1 AND s.file < (SELECT id FROM files WHERE path = ?2)",
        [name, path],
        |row| row.get(0),
    )
}

// ---------------------------------------------------------------- typo recall

#[test]
fn typo_queries_find_the_intended_identifier_first() -> TestResult {
    let repo = TempDir::new("typo")?;
    repo.write(
        "src/reader.rs",
        "pub struct QueryReader;\n\nimpl QueryReader {\n    pub fn open() {}\n}\n",
    )?;
    repo.write(
        "src/memory.rs",
        "pub fn record(statement: &str, memory: &mut Vec<String>) {\n    memory.push(statement.to_owned());\n}\n",
    )?;
    repo.write(
        "src/scan.js",
        "export function scanWorktreeForLinks(root) {\n  return root;\n}\n",
    )?;
    repo.write(
        "bin/worktree-remove-door.mjs",
        "export const name = 'worktree-remove-door';\n",
    )?;
    repo.write(
        "src/noise.rs",
        "pub fn unrelated() { let queue = 1; let state = 2; let door_bell = 3; }\n",
    )?;
    let index = Indexed::build(&repo)?;

    let outcome = index.text("QueryReder")?;
    let top = outcome.hits.first().ok_or("QueryReder found nothing")?;
    assert!(
        top.text.contains("QueryReader"),
        "{}",
        describe(&outcome.hits)
    );
    assert!(matches!(top.match_kind, MatchKind::Fuzzy { .. }));

    let outcome = index.text("statemnt memry")?;
    let top = outcome.hits.first().ok_or("statemnt memry found nothing")?;
    assert_eq!(top.path, "src/memory.rs", "{}", describe(&outcome.hits));
    assert_eq!(top.terms_matched, 2, "{}", describe(&outcome.hits));
    assert!(top.text.contains("statement") && top.text.contains("memory"));

    let outcome = index.text("scanWorktreForLnks")?;
    let top = outcome
        .hits
        .first()
        .ok_or("scanWorktreForLnks found nothing")?;
    assert!(
        top.text.contains("scanWorktreeForLinks"),
        "{}",
        describe(&outcome.hits)
    );

    let outcome = index.text("worktre remov door")?;
    let top = outcome
        .hits
        .first()
        .ok_or("worktre remov door found nothing")?;
    assert!(
        top.path.contains("worktree-remove-door") || top.text.contains("worktree-remove-door"),
        "{}",
        describe(&outcome.hits)
    );
    assert_eq!(top.terms_matched, 3, "{}", describe(&outcome.hits));
    assert!(outcome.guesses.is_empty());
    Ok(())
}

#[test]
fn an_exact_line_outranks_a_typo_match_in_a_better_field() -> TestResult {
    let repo = TempDir::new("exact-first")?;
    // `QueryReader::new` indexes the joined token and its parts, never
    // `queryreader` alone, so the only token near the query is the typo.
    repo.write(
        "src/call.rs",
        "fn run() {\n    let reader = QueryReader::new();\n}\n",
    )?;
    repo.write("src/decl.rs", "pub struct QueryReadr;\n")?;
    let index = Indexed::build(&repo)?;

    let outcome = index.text("QueryReader")?;
    let top = outcome.hits.first().ok_or("QueryReader found nothing")?;
    assert_eq!(
        (top.path.as_str(), top.line, top.match_kind),
        ("src/call.rs", 2, MatchKind::Exact),
        "{}",
        describe(&outcome.hits)
    );
    let typo = outcome
        .hits
        .iter()
        .position(|hit| hit.path == "src/decl.rs" && hit.field == HitField::Symbol)
        .ok_or_else(|| format!("typo symbol missing:\n{}", describe(&outcome.hits)))?;
    assert!(typo > 0);
    assert!(matches!(
        outcome.hits[typo].match_kind,
        MatchKind::Fuzzy { .. }
    ));
    Ok(())
}

#[test]
fn a_renamed_word_left_in_vocab_still_falls_back_to_the_new_spelling() -> TestResult {
    let repo = TempDir::new("dead-vocab")?;
    repo.write("src/lib.rs", "pub fn statemnt() -> u32 {\n    1\n}\n")?;
    repo.write("src/other.rs", "pub fn other() {}\n")?;
    let mut index = Indexed::build(&repo)?;
    assert_eq!(index.text("statemnt")?.hits.len(), 1);

    repo.write("src/lib.rs", "pub fn statement() -> u32 {\n    1\n}\n")?;
    assert!(matches!(
        index.reindex("src/lib.rs")?,
        PathOutcome::Indexed(_)
    ));
    // Precondition: the old spelling's row stays behind with no postings.
    let dead = index
        .reader
        .token_id("statemnt")?
        .ok_or("the removed word's vocab row is gone; counterexample not built")?;
    assert_eq!(index.reader.effective_df(dead)?, 0);

    let outcome = index.text("statemnt")?;
    assert!(
        !outcome.hits.is_empty(),
        "a dead row answered with zero hits; guesses: {}",
        describe(&outcome.guesses)
    );
    assert!(
        outcome
            .hits
            .iter()
            .all(|hit| hit.text.contains("statement") && hit.match_kind != MatchKind::Guess),
        "{}",
        describe(&outcome.hits)
    );
    assert!(matches!(
        outcome.hits[0].match_kind,
        MatchKind::Fuzzy { .. }
    ));
    Ok(())
}

// ------------------------------------------- symbol row caps and qualifiers

/// More definitions of `new` and `open` than one token's symbol read holds,
/// each sorted before the one a qualified query wants, plus a token many
/// files mention but one file defines.
fn crowded_repo() -> Result<TempDir, Box<dyn std::error::Error>> {
    let repo = TempDir::new("crowded")?;
    for i in 0..530 {
        repo.write(
            &format!("a/widget_{i:03}.rs"),
            &format!(
                "pub struct Widget{i:03};\n\nimpl Widget{i:03} {{\n    pub fn new() -> Self {{\n        Widget{i:03}\n    }}\n}}\n\npub fn open() {{}}\n"
            ),
        )?;
    }
    for i in 0..70 {
        repo.write(
            &format!("b/caller_{i:02}.rs"),
            &format!("pub fn caller_{i:02}() {{\n    rarelydefined();\n}}\n"),
        )?;
    }
    repo.write("c/defines.rs", "pub fn rarelydefined() {}\n")?;
    repo.write(
        "z/query_reader.rs",
        "pub struct QueryReader;\n\nimpl QueryReader {\n    pub fn new() -> Self {\n        QueryReader\n    }\n}\n",
    )?;
    repo.write("z/store.rs", "pub fn open() -> u32 {\n    7\n}\n")?;
    Ok(repo)
}

#[test]
fn symbol_queries_past_the_row_cap_stay_honest() -> TestResult {
    let repo = crowded_repo()?;
    let index = Indexed::build(&repo)?;
    // Preconditions: the wanted definitions really sort past one read.
    assert!(symbols_before(index.conn(), "new", "z/query_reader.rs")? > 512);
    assert!(symbols_before(index.conn(), "open", "z/store.rs")? > 512);

    let outcome = index.find(&kind("QueryReader::new", KindFilter::Symbol))?;
    assert_eq!(
        outcome
            .hits
            .iter()
            .map(|hit| (hit.path.as_str(), hit.line, hit.field))
            .collect::<Vec<_>>(),
        [("z/query_reader.rs", 4, HitField::Symbol)],
        "{}",
        describe(&outcome.hits)
    );
    assert!(!outcome.omitted_at_least);
    assert_eq!(outcome.files_unread, 0);
    assert!(!outcome.stopped_early());

    let outcome = index.find(&kind("store::open", KindFilter::Symbol))?;
    assert_eq!(
        outcome
            .hits
            .iter()
            .map(|hit| (hit.path.as_str(), hit.line))
            .collect::<Vec<_>>(),
        [("z/store.rs", 1)],
        "{}",
        describe(&outcome.hits)
    );
    assert!(!outcome.omitted_at_least && !outcome.stopped_early());

    // A plain name defined more often than one read holds must say so.
    let outcome = index.find(&kind("new", KindFilter::Symbol))?;
    assert!(!outcome.hits.is_empty());
    assert!(
        outcome.omitted_at_least,
        "a capped read claimed completeness"
    );
    assert!(outcome.stopped_early());
    assert!(outcome.hits.iter().all(|hit| hit.field == HitField::Symbol));

    // Text mentions never count as unread symbol candidates.
    let outcome = index.find(&kind("rarelydefined", KindFilter::Symbol))?;
    assert_eq!(
        outcome
            .hits
            .iter()
            .map(|hit| hit.path.as_str())
            .collect::<Vec<_>>(),
        ["c/defines.rs"]
    );
    assert_eq!(outcome.files_unread, 0);
    assert!(!outcome.stopped_early(), "{outcome:?}");

    // The same mentions do exceed the confirmation cap for a text search.
    let outcome = index.find(&kind("rarelydefined", KindFilter::Text))?;
    assert!(outcome.files_unread > 0 && outcome.stopped_early());
    Ok(())
}

// ---------------------------------------------------------- regex anchors

#[test]
fn regex_anchors_reach_untrigrammed_and_case_folded_tokens() -> TestResult {
    let digest = format!(
        "{}cafe1234{}",
        "9f86d081884c7d659a2feaa0", "c55ad015b0f00a08d1a2b3c4d5e6f7a8"
    );
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
    let long_hex: String = format!(
        "{}deadbeefcafe{}",
        "0123456789".repeat(8),
        "9876543210".repeat(7)
    );
    assert!(long_hex.len() > 128);

    // One unbroken run of letters: a single token past the trigram cap.
    let long_run = "markerzqx".repeat(7);
    assert!(long_run.len() > 48 && long_run.len() <= 128);

    let repo = TempDir::new("regex")?;
    repo.write(
        "src/digest.rs",
        &format!("pub const SUM: &str = \"sha256:{digest}\";\n"),
    )?;
    repo.write("src/other_sha.rs", "pub fn sha256_of() {}\n")?;
    repo.write("src/short.rs", "pub fn zqxmarkerzqx_short() {}\n")?;
    repo.write(
        "src/long.rs",
        &format!("pub const LONG: &str = \"{long_run}\";\n"),
    )?;
    repo.write("src/upper.rs", "pub const MIXEDCASEMARKER: u32 = 1;\n")?;
    repo.write("src/marker.rs", "pub fn deadbeefcafe_marker() {}\n")?;
    repo.write(
        "src/blob.rs",
        &format!("pub const BLOB: &str = \"{long_hex}\";\n"),
    )?;
    let index = Indexed::build(&repo)?;
    assert!(index.reader.token_id(&digest)?.is_none());
    assert!(index.reader.token_id(&long_run)?.is_some());

    // The digest's own pieces are digits or hex letters and never narrow;
    // its label does, and the 64-byte token is confirmed by the expression.
    let outcome = index.find(&regex("sha256:[0-9a-f]{64}"))?;
    assert_eq!(outcome.source, HitSource::Index, "{outcome:?}");
    assert_eq!(
        outcome
            .hits
            .iter()
            .map(|hit| (hit.path.as_str(), hit.match_kind))
            .collect::<Vec<_>>(),
        [("src/digest.rs", MatchKind::Regex)],
        "{}",
        describe(&outcome.hits)
    );
    // Alone, the digest's pieces anchor nothing, so the tree is scanned.
    let outcome = index.find(&regex("cafe1234[0-9a-f]{4}"))?;
    assert_eq!(outcome.scan_reason, Some(ScanReason::NoLiteralAnchor));
    assert!(outcome.hits.iter().any(|hit| hit.path == "src/digest.rs"));

    // The piece narrows through the short token's trigrams; the long run
    // holding it is not trigrammed and must still be a candidate.
    let outcome = index.find(&regex("zqxmarkerzqx"))?;
    assert_eq!(outcome.source, HitSource::Index, "{outcome:?}");
    let paths: Vec<&str> = outcome.hits.iter().map(|hit| hit.path.as_str()).collect();
    assert!(
        paths.contains(&"src/long.rs") && paths.contains(&"src/short.rs"),
        "untrigrammed token dropped:\n{}",
        describe(&outcome.hits)
    );

    let outcome = index.find(&regex("(?i)mixedCaseMarker"))?;
    assert_eq!(outcome.source, HitSource::Index);
    assert_eq!(
        outcome
            .hits
            .iter()
            .map(|hit| hit.path.as_str())
            .collect::<Vec<_>>(),
        ["src/upper.rs"]
    );
    // Without `(?i)` the expression is case-sensitive and the line differs.
    let outcome = index.find(&regex("mixedCaseMarker"))?;
    assert!(outcome.hits.is_empty(), "{}", describe(&outcome.hits));

    // `deadbeefcafe` is hex letters alone and sits inside a run longer than
    // the token cap: it must not narrow to the one short token holding it.
    let outcome = index.find(&regex("deadbeefcafe"))?;
    let paths: Vec<&str> = outcome.hits.iter().map(|hit| hit.path.as_str()).collect();
    assert!(
        paths.contains(&"src/blob.rs") && paths.contains(&"src/marker.rs"),
        "{}",
        describe(&outcome.hits)
    );
    Ok(())
}

// ------------------------------------------------ literals and phrases

#[test]
fn punctuated_literals_and_phrases_are_confirmed_from_the_index() -> TestResult {
    let repo = TempDir::new("literals")?;
    repo.write(
        "src/lit.rs",
        "use crate::cache::connection;\n\nfn go(&self) {\n    self.conn.run();\n}\n\nconst STATUS: u32 = 0xC0000142;\n// the quoted phrase lives here\n",
    )?;
    repo.write(
        "src/decoy.rs",
        "use crate::cache;\nfn other(conn: u8, run: u8) {\n    let me = self_ref(conn, run);\n}\n// phrase, then quoted, apart\nmod connection;\n",
    )?;
    repo.write(
        "src/near.rs",
        "pub fn nopee(invalid: u8, missing: u8) -> u8 {\n    invalid + missing\n}\n",
    )?;
    let index = Indexed::build(&repo)?;

    for (query, needle) in [
        ("self.conn.run", "self.conn.run"),
        ("0xC0000142", "0xc0000142"),
        ("crate::cache::connection", "crate::cache::connection"),
        ("\"quoted phrase\"", "quoted phrase"),
    ] {
        let outcome = index.text(query)?;
        assert_eq!(outcome.source, HitSource::Index, "{query}");
        assert!(outcome.scan_reason.is_none(), "{query}");
        assert!(
            outcome.hits.iter().any(|hit| hit.path == "src/lit.rs"
                && hit.line > 0
                && hit.text.to_lowercase().contains(needle)),
            "{query} not confirmed:\n{}",
            describe(&outcome.hits)
        );
        assert!(
            outcome.hits.iter().all(|hit| hit.path != "src/decoy.rs"
                && hit.source == HitSource::Index
                && hit.match_kind != MatchKind::Guess),
            "{query} matched a decoy:\n{}",
            describe(&outcome.hits)
        );
        assert!(outcome.guesses.is_empty(), "{query}");
    }

    let outcome = index.text("nope.invalid/missing")?;
    assert!(outcome.hits.is_empty(), "{}", describe(&outcome.hits));
    assert!(
        !outcome.guesses.is_empty(),
        "no labelled guess for a near spelling"
    );
    assert!(
        outcome
            .guesses
            .iter()
            .all(|guess| guess.match_kind == MatchKind::Guess && guess.terms_matched == 0)
    );
    Ok(())
}

#[test]
fn a_declaration_line_is_one_symbol_hit() -> TestResult {
    let repo = TempDir::new("dedup")?;
    repo.write(
        "src/dedup.rs",
        "pub fn dedupmarker(value: u32) -> u32 {\n    value\n}\n\nfn caller() -> u32 {\n    dedupmarker(2)\n}\n",
    )?;
    let index = Indexed::build(&repo)?;

    let outcome = index.text("dedupmarker")?;
    assert_no_duplicate_places(&outcome.hits);
    let on_declaration: Vec<&Hit> = outcome
        .hits
        .iter()
        .filter(|hit| hit.path == "src/dedup.rs" && hit.line == 1)
        .collect();
    assert_eq!(on_declaration.len(), 1, "{}", describe(&outcome.hits));
    assert_eq!(on_declaration[0].field, HitField::Symbol);
    assert!(
        outcome
            .hits
            .iter()
            .any(|hit| hit.line == 6 && hit.field == HitField::Body),
        "{}",
        describe(&outcome.hits)
    );

    let outcome = index.text("dedupmarker value")?;
    assert_no_duplicate_places(&outcome.hits);
    assert!(
        outcome.hits.iter().all(
            |hit| !(hit.line == 1 && matches!(hit.field, HitField::Signature | HitField::Body))
        )
    );
    Ok(())
}

// -------------------------------------------- live scan and the deadline

#[test]
fn unnarrowable_queries_scan_the_tree_and_say_why() -> TestResult {
    let repo = TempDir::new("live")?;
    repo.write(
        "src/arrow.rs",
        "pub fn arrow() -> u32 {\n    livescanmarker()\n}\n",
    )?;
    repo.write("src/plain.rs", "pub fn plain() {}\n")?;
    let index = Indexed::build(&repo)?;

    let outcome = index.text("->")?;
    assert_eq!(outcome.source, HitSource::LiveScan);
    assert_eq!(outcome.scan_reason, Some(ScanReason::NoIndexableTerms));
    assert_eq!(
        outcome
            .hits
            .iter()
            .map(|hit| (hit.path.as_str(), hit.line, hit.source))
            .collect::<Vec<_>>(),
        [("src/arrow.rs", 1, HitSource::LiveScan)]
    );
    assert!(!outcome.stopped_early());

    let outcome = index.find(&regex(".*"))?;
    assert_eq!(outcome.source, HitSource::LiveScan);
    assert_eq!(outcome.scan_reason, Some(ScanReason::NoLiteralAnchor));
    assert!(outcome.hits.iter().any(|hit| hit.path == "src/plain.rs"));
    assert!(
        outcome
            .hits
            .iter()
            .all(|hit| hit.source == HitSource::LiveScan)
    );

    // The same indexable word goes through the index.
    let outcome = index.text("livescanmarker")?;
    assert_eq!(outcome.source, HitSource::Index);
    assert!(outcome.scan_reason.is_none());
    Ok(())
}

#[test]
fn a_cold_index_scans_and_symbol_searches_admit_they_cannot_answer() -> TestResult {
    let repo = TempDir::new("cold")?;
    repo.write("src/lib.rs", "pub fn coldscanmarker() {}\n")?;
    let root = IndexSourceRoot::open(repo.path())?;
    let state = TempDir::new("cold-state")?;
    let db = state.join("atlas.db");
    let (store, _) = Store::open(&db, &StoreIdentity::default())?;
    let reader = Reader::open(&db)?;
    let committed: i64 = store
        .connection()
        .query_row("SELECT count(*) FROM files", [], |row| row.get(0))?;
    assert_eq!(committed, 0);

    let outcome = search(&reader, &root, &request("coldscanmarker"))?;
    assert_eq!(outcome.source, HitSource::LiveScan);
    assert_eq!(outcome.scan_reason, Some(ScanReason::ColdIndex));
    assert_eq!(
        outcome
            .hits
            .iter()
            .map(|hit| (hit.path.as_str(), hit.line))
            .collect::<Vec<_>>(),
        [("src/lib.rs", 1)]
    );

    let outcome = search(&reader, &root, &kind("coldscanmarker", KindFilter::Symbol))?;
    assert!(outcome.hits.is_empty());
    assert!(
        outcome.stopped_early(),
        "a cold symbol search claimed it saw everything"
    );
    Ok(())
}

#[test]
fn a_zero_deadline_stops_cleanly_on_both_paths() -> TestResult {
    let repo = TempDir::new("deadline")?;
    for i in 0..5 {
        repo.write(
            &format!("src/f{i}.rs"),
            &format!("pub fn f{i}() -> u32 {{\n    deadlinemarker()\n}}\n"),
        )?;
    }
    let index = Indexed::build(&repo)?;

    let mut indexed = request("deadlinemarker");
    indexed.deadline = Duration::ZERO;
    let outcome = index.find(&indexed)?;
    assert_eq!(outcome.source, HitSource::Index);
    assert!(outcome.deadline_reached && outcome.stopped_early());
    assert!(outcome.omitted_at_least);
    assert!(outcome.files_unread > 0, "{outcome:?}");

    let mut scanned = request("->");
    scanned.deadline = Duration::ZERO;
    let outcome = index.find(&scanned)?;
    assert_eq!(outcome.source, HitSource::LiveScan);
    assert!(outcome.deadline_reached && outcome.stopped_early());
    assert!(outcome.omitted_at_least);
    Ok(())
}

// ------------------------------------------------ custody and policy

const SECRET: &str = "custodysecrettoken";
const OUTSIDE: &str = "outsideleaktoken";

fn assert_no_leak(outcome: &SearchOutcome, what: &str) {
    for hit in outcome.hits.iter().chain(&outcome.guesses) {
        let text = hit.text.to_lowercase();
        assert!(
            !text.contains(SECRET) && !text.contains(OUTSIDE),
            "{what} leaked: {hit:?}"
        );
        assert!(
            !hit.path.ends_with(".env")
                && !hit.path.ends_with("secrets.yaml")
                && !hit.path.starts_with("escaped"),
            "{what} returned a guarded path: {hit:?}"
        );
    }
}

#[test]
fn policy_denied_files_never_reach_the_index_or_a_scan() -> TestResult {
    let repo = TempDir::new("policy")?;
    repo.write(".gitignore", "!.env\n!secrets.yaml\n")?;
    repo.write(".env", &format!("API => {SECRET}\n"))?;
    repo.write("config/secrets.yaml", &format!("key: {SECRET} => 1\n"))?;
    repo.write("src/ok.rs", "pub fn ok() {\n    let pair = 1 => 2;\n}\n")?;
    let index = Indexed::build(&repo)?;
    assert!(index.reader.token_id(SECRET)?.is_none(), "secret indexed");

    let outcome = index.text(SECRET)?;
    assert!(outcome.hits.is_empty() && outcome.guesses.is_empty());
    assert_no_leak(&outcome, "index search");

    let outcome = index.text("=>")?;
    assert_eq!(outcome.source, HitSource::LiveScan);
    assert_eq!(
        outcome
            .hits
            .iter()
            .map(|hit| hit.path.as_str())
            .collect::<Vec<_>>(),
        ["src/ok.rs"]
    );
    assert_no_leak(&outcome, "operator scan");

    let outcome = index.find(&regex("custodysecret.*"))?;
    assert_eq!(outcome.source, HitSource::LiveScan);
    assert!(outcome.hits.is_empty(), "{}", describe(&outcome.hits));
    assert_no_leak(&outcome, "regex scan");

    // A cold index scans the same tree under the same policy.
    let state = TempDir::new("policy-cold")?;
    let db = state.join("atlas.db");
    let _cold = Store::open(&db, &StoreIdentity::default())?;
    let outcome = search(&Reader::open(&db)?, &index.root, &request(SECRET))?;
    assert_eq!(outcome.scan_reason, Some(ScanReason::ColdIndex));
    assert!(outcome.hits.is_empty(), "{}", describe(&outcome.hits));
    assert_no_leak(&outcome, "cold scan");
    Ok(())
}

/// A tree with an indexed file that is then swapped for a link out of the
/// root, and a linked directory, built before the swap.
fn custody_repo() -> Result<(TempDir, TempDir), Box<dyn std::error::Error>> {
    let outside = TempDir::new("outside")?;
    outside.write(
        "leaked.rs",
        &format!("pub fn {OUTSIDE}() => stalefootoken\n"),
    )?;
    let repo = TempDir::new("custody")?;
    repo.write("src/foo.rs", "pub fn stalefootoken() {\n    1 => 2\n}\n")?;
    repo.write(
        "src/bar.rs",
        "pub fn stalebartoken() {\n    stalebartoken()\n}\n",
    )?;
    repo.write("src/safe.rs", "pub fn safe() {\n    3 => 4\n}\n")?;
    repo.write(".env", &format!("{SECRET} => 5\n"))?;
    Ok((outside, repo))
}

fn assert_refused_confirmation(index: &Indexed, query: &str, path: &str) -> TestResult {
    let outcome = index.find(&kind(query, KindFilter::Text))?;
    assert!(outcome.files_refused >= 1, "{query}: {outcome:?}");
    assert!(
        outcome.hits.iter().all(|hit| hit.path != path),
        "{query} confirmed a line through a link:\n{}",
        describe(&outcome.hits)
    );
    assert_no_leak(&outcome, query);
    let outcome = index.text(query)?;
    assert!(outcome.files_refused >= 1, "{query}: {outcome:?}");
    assert!(
        outcome.hits.iter().all(|hit| hit.path != path
            || hit.field == HitField::Symbol
            || hit.field == HitField::Path),
        "{query} read a line through a link:\n{}",
        describe(&outcome.hits)
    );
    assert_no_leak(&outcome, query);
    Ok(())
}

fn assert_scan_stays_inside(index: &Indexed) -> TestResult {
    let outcome = index.text("=>")?;
    assert_eq!(outcome.source, HitSource::LiveScan);
    assert!(outcome.hits.iter().any(|hit| hit.path == "src/safe.rs"));
    assert!(
        outcome
            .hits
            .iter()
            .all(|hit| hit.path != "src/foo.rs" && hit.path != "src/bar.rs"),
        "{}",
        describe(&outcome.hits)
    );
    assert_no_leak(&outcome, "operator scan");
    let outcome = index.text(OUTSIDE)?;
    assert!(outcome.hits.is_empty(), "{}", describe(&outcome.hits));
    assert_no_leak(&outcome, "outside token");
    Ok(())
}

#[cfg(windows)]
#[test]
fn replaced_leaves_and_junctions_leak_nothing_on_windows() -> TestResult {
    let (outside, mut repo) = custody_repo()?;
    repo.add_junction("escaped_dir", outside.path())?;
    let mut index = Indexed::build(&repo)?;
    assert!(
        index.reader.token_id(OUTSIDE)?.is_none(),
        "junction indexed"
    );
    assert_eq!(index.text("stalefootoken")?.files_refused, 0);

    fs::remove_file(repo.join("src/foo.rs"))?;
    repo.add_junction("src/foo.rs", outside.path())?;
    assert_refused_confirmation(&index, "stalefootoken", "src/foo.rs")?;

    // A file link to a policy-denied file inside the root, when this host
    // lets the test create one.
    fs::remove_file(repo.join("src/bar.rs"))?;
    let linked = std::os::windows::fs::symlink_file(repo.join(".env"), repo.join("src/bar.rs"));
    if linked.is_ok() {
        assert_refused_confirmation(&index, "stalebartoken", "src/bar.rs")?;
    } else {
        repo.write("src/bar.rs", "pub fn stalebartoken() {}\n")?;
    }
    assert_scan_stays_inside(&index)?;
    if linked.is_ok() {
        fs::remove_file(repo.join("src/bar.rs"))?;
    }
    assert!(matches!(
        index.reindex("src/foo.rs")?,
        PathOutcome::Refused { removed: true }
    ));
    let outcome = index.text("stalefootoken")?;
    assert!(outcome.hits.iter().all(|hit| hit.path != "src/foo.rs"));
    assert_no_leak(&outcome, "after re-index");
    Ok(())
}

#[cfg(unix)]
#[test]
fn replaced_leaves_and_symlinks_leak_nothing_on_unix() -> TestResult {
    use std::os::unix::fs::symlink;

    let (outside, repo) = custody_repo()?;
    symlink(outside.path(), repo.join("escaped_dir"))?;
    let mut index = Indexed::build(&repo)?;
    assert!(index.reader.token_id(OUTSIDE)?.is_none(), "symlink indexed");
    assert_eq!(index.text("stalefootoken")?.files_refused, 0);

    fs::remove_file(repo.join("src/foo.rs"))?;
    symlink(outside.join("leaked.rs"), repo.join("src/foo.rs"))?;
    assert_refused_confirmation(&index, "stalefootoken", "src/foo.rs")?;

    fs::remove_file(repo.join("src/bar.rs"))?;
    symlink(repo.join(".env"), repo.join("src/bar.rs"))?;
    assert_refused_confirmation(&index, "stalebartoken", "src/bar.rs")?;

    assert_scan_stays_inside(&index)?;
    assert!(matches!(
        index.reindex("src/foo.rs")?,
        PathOutcome::Refused { removed: true }
    ));
    let outcome = index.text("stalefootoken")?;
    assert!(outcome.hits.iter().all(|hit| hit.path != "src/foo.rs"));
    assert_no_leak(&outcome, "after re-index");
    Ok(())
}
