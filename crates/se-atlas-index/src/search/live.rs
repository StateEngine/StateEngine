//! The bounded live scan, used only when the index cannot narrow a query:
//! nothing committed yet, a regex without a literal anchor, or operators
//! alone. Discovery and every read go through the same custody and policy
//! as indexing. The scan stops at the soft deadline, a byte cap or a hit
//! cap, and says so; it never turns a stop into an error.
use super::{
    Budget, HitField, HitSource, KindFilter, MatchKind, Scope, SearchOutcome, SearchRequest,
    confirm,
    confirm::{Covers, FileRead, LineText, Pattern},
    keeps,
    query::Parsed,
    rank::{self, Candidate, Candidates, TermHit},
};
use crate::{Result, custody::IndexSourceRoot, extract::LanguageTag, walk};

/// Bytes read before the scan stops.
const BYTE_CAP: u64 = 64 << 20;
/// Matching lines collected before the scan stops.
const HIT_CAP: usize = 2_000;

/// What a scanned line must satisfy.
struct Matching {
    matcher: grep_regex::RegexMatcher,
    /// Empty for a regex, whose matcher is the whole test.
    patterns: Vec<Pattern>,
    /// Literal term indexes every line must hold.
    required: Vec<usize>,
    terms: usize,
}

impl Matching {
    fn new(parsed: &Parsed) -> Result<Self> {
        match parsed {
            Parsed::Regex { pattern, .. } => Ok(Self {
                matcher: confirm::regex(pattern)?,
                patterns: Vec::new(),
                required: Vec::new(),
                terms: 1,
            }),
            Parsed::Text { words, literals } => {
                let mut patterns = Vec::new();
                for (term, word) in words.iter().enumerate() {
                    patterns.push(Pattern::new(
                        &word.text,
                        Covers::Term(term),
                        hit(MatchKind::Exact),
                        false,
                    ));
                }
                let mut required = Vec::new();
                for (offset, literal) in literals.iter().enumerate() {
                    let term = words.len() + offset;
                    required.push(term);
                    patterns.push(Pattern::new(
                        &literal.text,
                        Covers::Term(term),
                        hit(MatchKind::Literal),
                        false,
                    ));
                }
                Ok(Self {
                    matcher: confirm::prefilter(&patterns)?,
                    patterns,
                    required,
                    terms: words.len() + literals.len(),
                })
            }
        }
    }

    /// A candidate for `text` at `line`, if it matches.
    fn judge(
        &self,
        file: i64,
        path: &str,
        line: u32,
        field: HitField,
        text: &str,
    ) -> Option<Candidate> {
        let mut candidate = Candidate::new(file, path, line, field, self.terms);
        if self.patterns.is_empty() {
            candidate.record(0, hit(MatchKind::Regex));
        } else {
            let line_text = LineText::new(text);
            for pattern in &self.patterns {
                if let Covers::Term(term) = pattern.covers
                    && line_text.contains(pattern)
                {
                    candidate.record(term, pattern.hit);
                }
            }
            let satisfied = self
                .required
                .iter()
                .all(|&term| candidate.terms.get(term).is_some_and(Option::is_some));
            if !satisfied {
                return None;
            }
        }
        candidate.text = if field == HitField::Path {
            text.to_owned()
        } else {
            confirm::hit_text(text)
        };
        Some(candidate)
    }
}

/// Scan one file's lines; returns the bytes read.
fn scan_file(
    root: &IndexSourceRoot,
    matching: &Matching,
    searcher: &mut grep_searcher::Searcher,
    file: i64,
    path: &str,
    outcome: &mut SearchOutcome,
    candidates: &mut Candidates,
) -> u64 {
    let mut found = Vec::new();
    let read = confirm::read_lines(root, path, &matching.matcher, searcher, |line, text| {
        let before = found.len();
        found.extend(matching.judge(file, path, line, HitField::Body, text));
        found.len() > before
    });
    read.tally(outcome);
    found
        .into_iter()
        .for_each(|candidate| candidates.add(candidate));
    match read {
        FileRead::Done { bytes, .. } => bytes,
        _ => 0,
    }
}

fn hit(kind: MatchKind) -> TermHit {
    TermHit {
        kind,
        evidence: kind.evidence(),
        idf: 0,
    }
}

pub(crate) fn scan(
    root: &IndexSourceRoot,
    request: &SearchRequest,
    parsed: &Parsed,
    budget: &Budget,
) -> Result<SearchOutcome> {
    let mut outcome = SearchOutcome {
        source: HitSource::LiveScan,
        ..SearchOutcome::default()
    };
    if request.kind == KindFilter::Symbol {
        // Symbols exist only in the index: a scan cannot say there are none.
        outcome.scan_incomplete = true;
        return Ok(outcome);
    }
    let matching = Matching::new(parsed)?;
    let discovery = walk::discover(root, &request.walk)?;
    let scope = Scope::new(request);
    outcome.scan_incomplete = !discovery.complete;
    let read_text = request.kind != KindFilter::Path;
    let mut candidates = Candidates::default();
    let mut searcher = confirm::searcher();
    let mut bytes = 0u64;
    let mut stopped = false;
    for (ordinal, path) in discovery.files.iter().enumerate() {
        if !scope.admits(path, LanguageTag::detect(path).as_str()) {
            continue;
        }
        if budget.expired() || bytes >= BYTE_CAP || candidates.len() >= HIT_CAP {
            outcome.deadline_reached = budget.expired();
            stopped = true;
            break;
        }
        let file = i64::try_from(ordinal).unwrap_or(i64::MAX);
        if !matching.patterns.is_empty()
            && let Some(found) = matching.judge(file, path, 0, HitField::Path, path)
        {
            candidates.add(found);
        }
        if read_text {
            bytes += scan_file(
                root,
                &matching,
                &mut searcher,
                file,
                path,
                &mut outcome,
                &mut candidates,
            );
        }
    }
    outcome.scan_incomplete |= stopped;
    let ranked = candidates.into_ranked(|candidate| keeps(request.kind, candidate.field));
    let (hits, end, omitted) = rank::page(
        ranked,
        request.limit(),
        request.max_bytes(),
        HitSource::LiveScan,
    );
    outcome.omitted_at_least = outcome.stopped_early();
    outcome.hits = hits;
    outcome.page_end = end;
    outcome.omitted = omitted;
    Ok(outcome)
}
