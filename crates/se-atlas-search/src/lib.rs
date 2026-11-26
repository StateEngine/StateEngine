//! Typo-tolerant code search over the Atlas v5 index, confirmed against the
//! files.
//!
//! The index answers first. Each query word resolves to vocabulary tokens
//! (exact, separator-stripped, then typo matches; see [`fuzzy`]); punctuated
//! words and quoted phrases are literals that narrow the files by their
//! identifier parts. The best `<= 50` candidate files are then read through
//! [`IndexSourceRoot`] custody and only lines that really contain a match
//! become hits; symbol definitions come straight from the index. Every
//! SQLite read runs inside one [`Reader::snapshot`].
//!
//! The whole tree is scanned only when the index cannot narrow the query: a
//! cold index with nothing committed yet, a regex with no literal anchor, or
//! a query of operators alone. That scan is bounded by the soft deadline and
//! a byte cap and returns what it found with `deadline_reached` set.
//!
//! No hit is invented: a literal that is not confirmed yields nothing, and
//! close spellings found when nothing matched come back separately as
//! [`MatchKind::Guess`].
#![forbid(unsafe_code)]

mod confirm;
mod fuzzy;
mod index;
mod live;
mod query;
mod rank;
mod read;
mod regex;
mod symbols;

pub use confirm::{FileRead, LiteralLines, hit_text};
pub use fuzzy::spellings;
use query::Parsed;
use rusqlite::OptionalExtension;
use se_atlas_index::{
    IndexError, Result,
    custody::IndexSourceRoot,
    extract::{LanguageTag, SymbolKind},
    store::Reader,
    walk::WalkOptions,
};
use std::time::{Duration, Instant};

pub const DEFAULT_LIMIT: usize = 20;
pub const MAX_LIMIT: usize = 200;
pub const DEFAULT_MAX_BYTES: usize = 16_384;
pub const MAX_MAX_BYTES: usize = 262_144;
/// The soft deadline: past it, a search returns what it has.
pub const DEFAULT_DEADLINE: Duration = Duration::from_millis(250);
/// Candidate files read to confirm matches.
pub const MAX_CONFIRM_FILES: usize = 50;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum QueryMode {
    /// Words, punctuated literals and `"quoted phrases"`.
    #[default]
    Text,
    /// A regular expression, matched case-sensitively unless it says `(?i)`.
    Regex,
}

/// Which hits a search returns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KindFilter {
    #[default]
    All,
    /// Symbol definitions only.
    Symbol,
    /// Lines of text, including declaration lines.
    Text,
    /// File paths only.
    Path,
}

#[derive(Clone, Debug)]
pub struct SearchRequest {
    pub query: String,
    pub mode: QueryMode,
    pub kind: KindFilter,
    /// Root-relative path prefixes, matched on whole components; empty
    /// searches everywhere.
    pub in_paths: Vec<String>,
    /// Languages to keep; empty keeps all.
    pub languages: Vec<LanguageTag>,
    /// Hits per page, at most [`MAX_LIMIT`]; zero means the default.
    pub limit: usize,
    /// Bytes of paths and text per page, at most [`MAX_MAX_BYTES`]; zero
    /// means the default.
    pub max_bytes: usize,
    pub deadline: Duration,
    /// Discovery rules for a live scan; pass the ones the index was built with.
    pub walk: WalkOptions,
}

impl SearchRequest {
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            mode: QueryMode::Text,
            kind: KindFilter::All,
            in_paths: Vec::new(),
            languages: Vec::new(),
            limit: DEFAULT_LIMIT,
            max_bytes: DEFAULT_MAX_BYTES,
            deadline: DEFAULT_DEADLINE,
            walk: WalkOptions::default(),
        }
    }

    fn limit(&self) -> usize {
        match self.limit {
            0 => DEFAULT_LIMIT,
            n => n.min(MAX_LIMIT),
        }
    }

    fn max_bytes(&self) -> usize {
        match self.max_bytes {
            0 => DEFAULT_MAX_BYTES,
            n => n.min(MAX_MAX_BYTES),
        }
    }
}

/// Where a hit came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HitSource {
    /// Index candidates, confirmed in the file where a line is shown.
    #[default]
    Index,
    /// A bounded scan of the tree.
    LiveScan,
}

/// The part of a file a hit matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HitField {
    Symbol,
    Path,
    Signature,
    Body,
}

impl HitField {
    pub fn penalty(self) -> u8 {
        match self {
            Self::Symbol => 0,
            Self::Path => 5,
            Self::Signature => 10,
            Self::Body => 15,
        }
    }
}

/// How the query matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchKind {
    Exact,
    /// The same token once `-`, `_`, `.` and `:` are removed.
    Compact,
    /// A typo match `distance` edits away.
    Fuzzy {
        distance: u8,
    },
    /// The word starts, or is a subsequence of, the matched token.
    Partial,
    /// A punctuated literal or phrase, confirmed in the line.
    Literal,
    Regex,
    /// A close spelling offered when nothing matched; never a real hit.
    Guess,
}

impl MatchKind {
    pub fn evidence(self) -> u8 {
        match self {
            Self::Exact | Self::Literal | Self::Regex => 100,
            Self::Compact => 95,
            Self::Fuzzy { distance } => 70u8.saturating_sub(distance.saturating_mul(5)),
            Self::Partial => 60,
            Self::Guess => 0,
        }
    }

    fn distance(self) -> u8 {
        match self {
            Self::Fuzzy { distance } => distance,
            _ => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub path: String,
    /// 1-based; 0 when the hit is the file's path.
    pub line: u32,
    pub field: HitField,
    pub symbol_kind: Option<SymbolKind>,
    /// The line, the declaration header, or the path. For a guess, the
    /// suggested spelling.
    pub text: String,
    pub match_kind: MatchKind,
    pub terms_matched: usize,
    pub terms: usize,
    pub score: i64,
    pub source: HitSource,
}

/// Why the page stopped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PageEnd {
    /// Every ranked hit is on the page.
    #[default]
    Complete,
    Limit,
    Bytes,
}

/// One search answer. Counts of files not read are kept apart by reason.
#[derive(Clone, Debug, Default)]
pub struct SearchOutcome {
    pub hits: Vec<Hit>,
    /// Close spellings, only when `hits` is empty.
    pub guesses: Vec<Hit>,
    pub source: HitSource,
    pub page_end: PageEnd,
    /// Ranked hits left off the page.
    pub omitted: usize,
    /// True when hits may exist beyond those ranked, because the search
    /// stopped early: see [`SearchOutcome::stopped_early`].
    pub omitted_at_least: bool,
    /// Files the index named as candidates (after the scope filter where
    /// it was checked).
    pub candidate_files: usize,
    /// Files read to confirm or scan.
    pub files_read: usize,
    /// Candidates not read: past the confirmation cap or the deadline.
    pub files_unread: usize,
    /// Indexed files no longer present.
    pub files_absent: usize,
    /// Files the policy or custody refused to open.
    pub files_refused: usize,
    pub files_read_failed: usize,
    /// Files read only in part: past the full-read limit or a line cap.
    pub files_partly_read: usize,
    pub deadline_reached: bool,
    /// A live scan stopped before the end of the tree, or its walk was
    /// incomplete.
    pub scan_incomplete: bool,
    /// Why the tree was scanned instead of the index, for a live scan.
    pub scan_reason: Option<ScanReason>,
}

/// Why a search scanned the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanReason {
    /// Nothing has been committed to the index yet.
    ColdIndex,
    /// The query holds no word or identifier the index could look up.
    NoIndexableTerms,
    /// A regex none of whose required literals narrows the files.
    NoLiteralAnchor,
    /// A cold build is still publishing, so the trigrams a regex needs are
    /// not written yet.
    TrigramsPending,
    /// Vocabulary supplementation hit the search deadline; scanned live instead.
    VocabBudgetExceeded,
}

impl SearchOutcome {
    /// Whether the search left something unexamined: the deadline, unread
    /// candidates, partly read files, a stopped scan, or a symbol row cap.
    pub fn stopped_early(&self) -> bool {
        self.deadline_reached
            || self.files_unread > 0
            || self.files_partly_read > 0
            || self.scan_incomplete
            || self.omitted_at_least
    }
}

/// Search the index behind `reader`, reading candidate files through `root`.
pub fn search(
    reader: &Reader,
    root: &IndexSourceRoot,
    request: &SearchRequest,
) -> Result<SearchOutcome> {
    let budget = Budget::start(request.deadline);
    let parsed = query::parse(&request.query, request.mode)?;
    if request.mode == QueryMode::Regex
        && matches!(request.kind, KindFilter::Symbol | KindFilter::Path)
    {
        return Err(IndexError::Invalid(
            "a regex search matches lines of text; search with kind all or text",
        ));
    }
    let snapshot = reader.snapshot()?;
    let reason = if index_is_cold(snapshot.connection())? {
        ScanReason::ColdIndex
    } else {
        match &parsed {
            Parsed::Text { .. } if !parsed.indexable() => ScanReason::NoIndexableTerms,
            Parsed::Text { words, literals } => {
                return index::text(&snapshot, root, request, words, literals, &budget);
            }
            Parsed::Regex { pattern, pieces } => {
                match regex::search(&snapshot, root, request, pattern, pieces, &budget)? {
                    Ok(outcome) => return Ok(outcome),
                    Err(reason) => reason,
                }
            }
        }
    };
    drop(snapshot);
    let mut outcome = live::scan(root, request, &parsed, &budget)?;
    outcome.scan_reason = Some(reason);
    Ok(outcome)
}

/// Whether `kind` keeps a hit on `field`.
pub(crate) fn keeps(kind: KindFilter, field: HitField) -> bool {
    match kind {
        KindFilter::All => true,
        KindFilter::Symbol => field == HitField::Symbol,
        KindFilter::Text => matches!(field, HitField::Signature | HitField::Body),
        KindFilter::Path => field == HitField::Path,
    }
}

/// Nothing has been committed and discovery has not finished.
fn index_is_cold(conn: &rusqlite::Connection) -> Result<bool> {
    let complete: Option<i64> = conn
        .prepare_cached("SELECT discovery_complete FROM meta WHERE singleton=1")?
        .query_row([], |row| row.get(0))
        .optional()?;
    let any_file: bool = conn
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM files)")?
        .query_row([], |row| row.get(0))?;
    Ok(complete.unwrap_or(0) == 0 && !any_file)
}

/// The soft deadline shared by every phase of one search.
pub struct Budget {
    /// `None` when the deadline is too far away to represent.
    until: Option<Instant>,
}

impl Budget {
    pub fn start(deadline: Duration) -> Self {
        Self {
            until: Instant::now().checked_add(deadline),
        }
    }

    pub fn expired(&self) -> bool {
        self.until.is_some_and(|until| Instant::now() >= until)
    }

    /// The instant the deadline falls, for work that checks it itself.
    pub fn until(&self) -> Option<Instant> {
        self.until
    }
}

/// The path and language scope of one request.
pub(crate) struct Scope {
    prefixes: Vec<String>,
    languages: Vec<LanguageTag>,
}

impl Scope {
    pub fn new(request: &SearchRequest) -> Self {
        let prefixes = request
            .in_paths
            .iter()
            .map(|prefix| {
                prefix
                    .replace('\\', "/")
                    .trim_start_matches("./")
                    .trim_matches('/')
                    .to_owned()
            })
            .filter(|prefix| !prefix.is_empty() && prefix != ".")
            .collect();
        Self {
            prefixes,
            languages: request.languages.clone(),
        }
    }

    pub fn filters(&self) -> bool {
        !self.prefixes.is_empty() || !self.languages.is_empty()
    }

    pub fn admits(&self, path: &str, lang: &str) -> bool {
        let in_path = self.prefixes.is_empty()
            || self.prefixes.iter().any(|prefix| {
                path.strip_prefix(prefix.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
            });
        let in_language =
            self.languages.is_empty() || self.languages.iter().any(|tag| tag.as_str() == lang);
        in_path && in_language
    }
}
