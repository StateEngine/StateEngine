//! Scoring, de-duplication and paging of search candidates.
//!
//! Each candidate records the best evidence it holds for every query term.
//! Order is: more terms matched first, then fewer typo-matched terms (so an
//! exact match always outranks a typo match covering the same terms), then
//! score, then path and line. The score adds per-term evidence and live idf,
//! subtracts a field penalty, and adds bonuses for a full separator-stripped
//! match and for matching every term.
use crate::{Hit, HitField, HitSource, MatchKind, PageEnd};
use se_atlas_index::extract::SymbolKind;
use std::collections::HashMap;

const FULL_COMPACT_BONUS: i64 = 500;
const ALL_TERMS_BONUS: i64 = 300;
const COVERAGE_BONUS: i64 = 100;
/// Bytes charged per hit beyond its path and text.
const HIT_OVERHEAD: usize = 32;

/// The evidence one term has at one place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TermHit {
    pub kind: MatchKind,
    pub evidence: u8,
    /// Live inverse document frequency, scaled by 20.
    pub idf: u16,
}

impl TermHit {
    fn better_than(self, other: Self) -> bool {
        (self.evidence, self.idf) > (other.evidence, other.idf)
    }

    fn typo(self) -> bool {
        self.evidence < MatchKind::Compact.evidence()
    }
}

/// Inverse document frequency points for a token in `df` of `files` files.
pub(crate) fn idf(files: u64, df: usize) -> u16 {
    let ratio = files.max(1) as f64 / df.max(1) as f64;
    ((1.0 + ratio).ln() * 20.0)
        .round()
        .clamp(0.0, f64::from(u16::MAX)) as u16
}

/// One place a query may have matched, before paging.
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    /// Index file id, or a scan ordinal for live hits.
    pub file: i64,
    pub path: String,
    pub line: u32,
    pub field: HitField,
    pub symbol_kind: Option<SymbolKind>,
    pub text: String,
    pub terms: Vec<Option<TermHit>>,
    pub full_compact: bool,
}

impl Candidate {
    pub fn new(file: i64, path: &str, line: u32, field: HitField, terms: usize) -> Self {
        Self {
            file,
            path: path.to_owned(),
            line,
            field,
            symbol_kind: None,
            text: String::new(),
            terms: vec![None; terms],
            full_compact: false,
        }
    }

    pub fn record(&mut self, term: usize, hit: TermHit) {
        if let Some(slot) = self.terms.get_mut(term)
            && slot.is_none_or(|known| hit.better_than(known))
        {
            *slot = Some(hit);
        }
    }

    fn matched(&self) -> usize {
        self.terms.iter().flatten().count()
    }

    fn typos(&self) -> usize {
        self.terms.iter().flatten().filter(|hit| hit.typo()).count()
    }

    fn score(&self) -> i64 {
        let total = self.terms.len().max(1) as i64;
        let matched = self.matched() as i64;
        let evidence: i64 = self
            .terms
            .iter()
            .flatten()
            .map(|hit| i64::from(hit.evidence) * 10 + i64::from(hit.idf))
            .sum();
        let mut score = evidence - i64::from(self.field.penalty()) * 10;
        score += COVERAGE_BONUS * matched / total;
        if matched == total {
            score += ALL_TERMS_BONUS;
        }
        if self.full_compact {
            score += FULL_COMPACT_BONUS;
        }
        score
    }

    /// The weakest evidence among matched terms names the match.
    fn match_kind(&self) -> MatchKind {
        self.terms
            .iter()
            .flatten()
            .min_by_key(|hit| (hit.evidence, std::cmp::Reverse(hit.kind.distance())))
            .map_or(MatchKind::Exact, |hit| hit.kind)
    }

    /// Fold another candidate for the same place into this one, keeping the
    /// richer field (a symbol over a plain line) and each term's best hit.
    fn absorb(&mut self, other: Self) {
        if other.field.penalty() < self.field.penalty() {
            self.field = other.field;
            self.symbol_kind = other.symbol_kind;
            if !other.text.is_empty() {
                self.text = other.text;
            }
        } else if self.text.is_empty() {
            self.text = other.text;
        }
        for (term, hit) in other.terms.into_iter().enumerate() {
            if let Some(hit) = hit {
                self.record(term, hit);
            }
        }
        self.full_compact |= other.full_compact;
    }
}

/// Candidates keyed by `(file, line)`; adding one twice merges them.
#[derive(Default)]
pub(crate) struct Candidates {
    by_place: HashMap<(i64, u32), Candidate>,
}

impl Candidates {
    pub fn add(&mut self, candidate: Candidate) {
        if candidate.matched() == 0 {
            return;
        }
        match self.by_place.entry((candidate.file, candidate.line)) {
            std::collections::hash_map::Entry::Occupied(mut known) => {
                known.get_mut().absorb(candidate);
            }
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(candidate);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.by_place.len()
    }

    pub fn into_ranked(self, keep: impl Fn(&Candidate) -> bool) -> Vec<Candidate> {
        let mut ranked: Vec<(usize, usize, i64, Candidate)> = self
            .by_place
            .into_values()
            .filter(|candidate| keep(candidate))
            .map(|candidate| {
                let key = (candidate.matched(), candidate.typos(), candidate.score());
                (key.0, key.1, key.2, candidate)
            })
            .collect();
        ranked.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then(a.1.cmp(&b.1))
                .then(b.2.cmp(&a.2))
                .then_with(|| a.3.path.cmp(&b.3.path))
                .then(a.3.line.cmp(&b.3.line))
        });
        ranked
            .into_iter()
            .map(|(.., candidate)| candidate)
            .collect()
    }
}

/// The page that fits `limit` hits and `max_bytes`, and how it ended.
pub(crate) fn page(
    ranked: Vec<Candidate>,
    limit: usize,
    max_bytes: usize,
    source: HitSource,
) -> (Vec<Hit>, PageEnd, usize) {
    let total = ranked.len();
    let mut hits = Vec::new();
    let mut bytes = 0usize;
    let mut end = PageEnd::Complete;
    for candidate in ranked {
        if hits.len() == limit {
            end = PageEnd::Limit;
            break;
        }
        let cost = candidate.path.len() + candidate.text.len() + HIT_OVERHEAD;
        if bytes + cost > max_bytes && !hits.is_empty() {
            end = PageEnd::Bytes;
            break;
        }
        bytes += cost;
        hits.push(to_hit(candidate, source));
    }
    let omitted = total - hits.len();
    (hits, end, omitted)
}

pub(crate) fn to_hit(candidate: Candidate, source: HitSource) -> Hit {
    Hit {
        score: candidate.score(),
        match_kind: candidate.match_kind(),
        terms_matched: candidate.matched(),
        terms: candidate.terms.len(),
        path: candidate.path,
        line: candidate.line,
        field: candidate.field,
        symbol_kind: candidate.symbol_kind,
        text: candidate.text,
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(kind: MatchKind) -> TermHit {
        TermHit {
            kind,
            evidence: kind.evidence(),
            idf: 40,
        }
    }

    fn candidate(path: &str, line: u32, field: HitField, terms: &[Option<MatchKind>]) -> Candidate {
        let mut out = Candidate::new(i64::from(line), path, line, field, terms.len());
        for (term, kind) in terms.iter().enumerate() {
            if let Some(kind) = kind {
                out.record(term, hit(*kind));
            }
        }
        out
    }

    fn order(list: Vec<Candidate>) -> Vec<(String, u32)> {
        let mut all = Candidates::default();
        for item in list {
            all.add(item);
        }
        all.into_ranked(|_| true)
            .into_iter()
            .map(|c| (c.path, c.line))
            .collect()
    }

    #[test]
    fn exact_beats_typo_even_in_a_better_field() {
        let typo = MatchKind::Fuzzy { distance: 1 };
        let ranked = order(vec![
            candidate("a.rs", 1, HitField::Symbol, &[Some(typo)]),
            candidate("z.rs", 9, HitField::Body, &[Some(MatchKind::Exact)]),
        ]);
        assert_eq!(ranked[0], ("z.rs".into(), 9));
    }

    #[test]
    fn coverage_then_field_then_path_and_line_break_ties() {
        let exact = Some(MatchKind::Exact);
        let typo = Some(MatchKind::Fuzzy { distance: 2 });
        let ranked = order(vec![
            candidate("b.rs", 4, HitField::Body, &[exact, None]),
            candidate("c.rs", 2, HitField::Body, &[typo, exact]),
            candidate("a.rs", 7, HitField::Body, &[exact, None]),
            candidate("a.rs", 3, HitField::Body, &[exact, None]),
            candidate("d.rs", 5, HitField::Symbol, &[exact, None]),
        ]);
        let paths: Vec<_> = ranked.iter().map(|(p, l)| format!("{p}:{l}")).collect();
        assert_eq!(paths, ["c.rs:2", "d.rs:5", "a.rs:3", "a.rs:7", "b.rs:4"]);
    }

    #[test]
    fn a_line_and_its_symbol_merge_into_the_symbol_hit() {
        let mut line = candidate(
            "a.rs",
            3,
            HitField::Signature,
            &[None, Some(MatchKind::Exact)],
        );
        line.text = "pub fn open(path: &Path)".into();
        let mut symbol = candidate("a.rs", 3, HitField::Symbol, &[Some(MatchKind::Exact), None]);
        symbol.symbol_kind = Some(SymbolKind::Function);
        symbol.text = "pub fn open(path: &Path)".into();
        let mut all = Candidates::default();
        all.add(line);
        all.add(symbol);
        let ranked = all.into_ranked(|_| true);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].field, HitField::Symbol);
        assert_eq!(ranked[0].matched(), 2);
        let (hits, end, omitted) = page(ranked, 20, 16_384, HitSource::Index);
        assert_eq!((hits.len(), end, omitted), (1, PageEnd::Complete, 0));
        assert_eq!(hits[0].symbol_kind, Some(SymbolKind::Function));
    }

    #[test]
    fn idf_rewards_rare_tokens() {
        assert!(idf(2_000, 1) > idf(2_000, 1_000));
        assert_eq!(idf(0, 0), idf(1, 1));
    }
}
