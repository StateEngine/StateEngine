//! Regex narrowing keeps every file a match could live in: a joined name is
//! found inside a longer compound token, and a hex-digit piece never narrows
//! away a hex run longer than the token cap.
use se_atlas_index::{
    custody::IndexSourceRoot,
    store::{BuildOptions, Reader, Store, StoreIdentity},
};
use se_atlas_search::{HitSource, QueryMode, SearchOutcome, SearchRequest, search};
use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "se-atlas-regex-review-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn write(&self, relative: &str, text: &str) -> io::Result<()> {
        let full = relative.split('/').fold(self.0.clone(), |p, s| p.join(s));
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(full, text)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn regex_paths(
    files: &[(&str, &str)],
    pattern: &str,
) -> Result<SearchOutcome, Box<dyn std::error::Error>> {
    let repo = TempDir::new("repo")?;
    for (path, text) in files {
        repo.write(path, text)?;
    }
    let state = TempDir::new("state")?;
    let root = IndexSourceRoot::open(&repo.0)?;
    let db = state.0.join("atlas.db");
    let (mut store, _) = Store::open(&db, &StoreIdentity::default())?;
    assert!(
        store
            .cold_build(&root, &BuildOptions::default())?
            .discovery_complete
    );
    let reader = Reader::open(&db)?;
    let mut request = SearchRequest::new(pattern);
    request.deadline = Duration::from_secs(60);
    request.mode = QueryMode::Regex;
    Ok(search(&reader, &root, &request)?)
}

fn paths(outcome: &SearchOutcome) -> Vec<&str> {
    let mut paths: Vec<&str> = outcome.hits.iter().map(|h| h.path.as_str()).collect();
    paths.sort_unstable();
    paths.dedup();
    paths
}

#[test]
fn joined_name_narrows_into_a_longer_compound_token() -> TestResult {
    let outcome = regex_paths(
        &[
            ("src/call.rs", "pub fn run() { my_parse_with_options(); }\n"),
            (
                "src/parts.rs",
                "pub fn parse() {}\npub fn with() {}\npub fn options() {}\n",
            ),
            ("src/plain.rs", "pub fn unrelated() {}\n"),
        ],
        "parse_with_options",
    )?;
    assert_eq!(outcome.source, HitSource::Index, "{outcome:?}");
    assert_eq!(paths(&outcome), ["src/call.rs"], "{outcome:?}");
    Ok(())
}

#[test]
fn hex_digit_piece_keeps_a_hex_run_past_the_token_cap() -> TestResult {
    let blob = format!("{}cafe1234{}", "ab".repeat(40), "cd".repeat(40));
    assert!(blob.len() > 128 && blob.bytes().all(|b| b.is_ascii_hexdigit()));
    let outcome = regex_paths(
        &[
            (
                "src/blob.rs",
                &format!("pub const BLOB: &str = \"{blob}\";\n"),
            ),
            ("src/marker.rs", "pub fn cafe1234_marker() {}\n"),
        ],
        "cafe1234",
    )?;
    assert_eq!(
        paths(&outcome),
        ["src/blob.rs", "src/marker.rs"],
        "{outcome:?}"
    );
    Ok(())
}
