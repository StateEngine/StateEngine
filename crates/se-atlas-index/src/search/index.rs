//! The index-first pipeline: resolve terms, rank candidate files, confirm
//! the best of them line by line, and add symbol and path hits.
use super::{
    Budget, HitField, HitSource, KindFilter, MAX_CONFIRM_FILES, MatchKind, Scope, SearchOutcome,
    SearchRequest, confirm,
    confirm::{Covers, LineText, Pattern},
    fuzzy::{self, TokenMatch},
    keeps,
    query::{Literal, Word},
    rank::{self, Candidate, Candidates, TermHit, idf},
};
use crate::{
    Result,
    custody::IndexSourceRoot,
    extract::{SymbolKind, tokens},
    store::ReadSnapshot,
};
use rusqlite::{Connection, OptionalExtension};
use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};

/// Anchor tokens intersected per literal, rarest first.
const ANCHORS_USED: usize = 4;
/// Symbol rows read per matched token.
const SYMBOLS_PER_TOKEN: i64 = 512;
const SCOPED_SYMBOLS_PER_TOKEN: i64 = 8_192;
/// Separator-stripped spellings tried for words written as one identifier.
const JOINED_LIMIT: i64 = 8;
const SYMBOL_FILE_BOOST: u32 = 200;
const ALL_TERMS_FILE_BOOST: u32 = 300;
const WHOLE_TOKEN_BOOST: u32 = 500;

/// Everything the index said about the query's terms.
#[derive(Default)]
struct Plan {
    /// Plain words, then literals.
    terms: usize,
    words: usize,
    patterns: Vec<Pattern>,
    /// Per term, each candidate file's best weight.
    term_files: Vec<HashMap<i64, u32>>,
    /// Files holding every literal's anchors, when the query has literals.
    required: Option<HashSet<i64>>,
    /// Term indexes every hit must satisfy.
    literal_terms: Vec<usize>,
    symbol_tokens: Vec<(i64, Covers, TermHit, bool)>,
    near: Vec<TokenMatch>,
    query_compact: String,
}

impl Plan {
    fn weigh(&mut self, term: usize, files: impl Iterator<Item = i64>, hit: TermHit) {
        let weight = u32::from(hit.evidence) * 10 + u32::from(hit.idf);
        let slot = &mut self.term_files[term];
        for file in files {
            let best = slot.entry(file).or_insert(0);
            *best = (*best).max(weight);
        }
    }

    fn pattern(&mut self, text: &str, covers: Covers, hit: TermHit) -> bool {
        let full = tokens::compact(text) == self.query_compact;
        self.patterns.push(Pattern::new(text, covers, hit, full));
        full
    }

    fn apply(&self, candidate: &mut Candidate, covers: Covers, hit: TermHit) {
        match covers {
            Covers::Term(term) => candidate.record(term, hit),
            Covers::Words => (0..self.words).for_each(|term| candidate.record(term, hit)),
        }
    }

    fn satisfied(&self, candidate: &Candidate) -> bool {
        self.literal_terms
            .iter()
            .all(|&term| candidate.terms.get(term).is_some_and(Option::is_some))
    }

    /// Record every pattern found in `text` on `candidate`.
    fn match_text(&self, text: &str, candidate: &mut Candidate) {
        let text = LineText::new(text);
        for pattern in &self.patterns {
            if text.contains(pattern) {
                self.apply(candidate, pattern.covers, pattern.hit);
                candidate.full_compact |= pattern.full;
            }
        }
    }
}

/// An indexed file's path and language, cached for one search.
pub(super) struct FileRow {
    pub path: String,
    lang: String,
}

pub(super) struct FileRows<'c> {
    conn: &'c Connection,
    known: HashMap<i64, Option<Rc<FileRow>>>,
}

impl<'c> FileRows<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self {
            conn,
            known: HashMap::new(),
        }
    }

    fn get(&mut self, id: i64) -> Result<Option<Rc<FileRow>>> {
        if let Some(known) = self.known.get(&id) {
            return Ok(known.clone());
        }
        let row = self
            .conn
            .prepare_cached("SELECT path, lang FROM files WHERE id=?1")?
            .query_row([id], |row| {
                Ok(FileRow {
                    path: row.get(0)?,
                    lang: row.get(1)?,
                })
            })
            .optional()?
            .map(Rc::new);
        self.known.insert(id, row.clone());
        Ok(row)
    }

    fn admitted(&mut self, id: i64, scope: &Scope) -> Result<Option<Rc<FileRow>>> {
        Ok(self
            .get(id)?
            .filter(|row| scope.admits(&row.path, &row.lang)))
    }
}

pub(crate) fn text(
    snapshot: &ReadSnapshot<'_>,
    root: &IndexSourceRoot,
    request: &SearchRequest,
    words: &[Word],
    literals: &[Literal],
    budget: &Budget,
) -> Result<SearchOutcome> {
    let conn = snapshot.connection();
    let plan = plan_text(snapshot, &request.query, words, literals)?;
    let scope = Scope::new(request);
    let mut rows = FileRows::new(conn);
    let mut outcome = SearchOutcome::default();
    let mut candidates = Candidates::default();
    let symbols = plan.literal_terms.is_empty()
        && matches!(request.kind, KindFilter::All | KindFilter::Symbol);
    let symbol_files = if symbols {
        symbol_hits(conn, &plan, &scope, &mut rows, &mut candidates)?
    } else {
        HashSet::new()
    };
    let ranked = rank_files(&plan, &symbol_files);
    let chosen = choose(&ranked, &scope, &mut rows, budget, &mut outcome)?;
    if matches!(request.kind, KindFilter::All | KindFilter::Path) {
        let mut seen = HashSet::new();
        for file in chosen.iter().map(|(id, _)| *id).chain(symbol_files) {
            if seen.insert(file)
                && let Some(row) = rows.get(file)?
            {
                path_hit(&plan, file, &row, &mut candidates);
            }
        }
    }
    if matches!(request.kind, KindFilter::All | KindFilter::Text) {
        confirm_lines(
            conn,
            root,
            &plan,
            &chosen,
            budget,
            &mut outcome,
            &mut candidates,
        )?;
    }
    page_into(request, &mut outcome, candidates);
    if outcome.hits.is_empty() {
        outcome.guesses = guesses(conn, &plan.near, plan.terms, &scope, &mut rows)?;
    }
    Ok(outcome)
}

fn plan_text(
    snapshot: &ReadSnapshot<'_>,
    query: &str,
    words: &[Word],
    literals: &[Literal],
) -> Result<Plan> {
    let files = file_count(snapshot.connection())?;
    let terms = words.len() + literals.len();
    let mut plan = Plan {
        terms,
        words: words.len(),
        term_files: vec![HashMap::new(); terms],
        query_compact: tokens::compact(&query.split_whitespace().collect::<String>())
            .to_lowercase(),
        ..Plan::default()
    };
    for (term, word) in words.iter().enumerate() {
        plan_word(snapshot, files, term, word, &mut plan)?;
    }
    if words.len() >= 2 {
        plan_joined(snapshot, files, words, &mut plan)?;
    }
    for (offset, literal) in literals.iter().enumerate() {
        plan_literal(snapshot, files, words.len() + offset, literal, &mut plan)?;
    }
    Ok(plan)
}

fn plan_word(
    snapshot: &ReadSnapshot<'_>,
    files: u64,
    term: usize,
    word: &Word,
    plan: &mut Plan,
) -> Result<()> {
    let resolution = fuzzy::resolve(snapshot, &word.text)?;
    for found in &resolution.matches {
        let postings = snapshot.read_postings(found.id)?;
        let hit = TermHit {
            kind: found.kind,
            evidence: found.evidence,
            idf: idf(files, postings.len()),
        };
        let full = plan.pattern(&found.text, Covers::Term(term), hit);
        plan.weigh(term, postings.iter().map(|(file, _)| *file), hit);
        plan.symbol_tokens
            .push((found.id, Covers::Term(term), hit, full));
    }
    // `QueryReader::new` indexes `query` and `reader` but not `queryreader`:
    // files holding every part may hold the word inside a longer token, so
    // they are candidates too, and the word as written is always confirmed
    // as an exact match wherever a line holds it.
    let holders = if word.parts.len() >= 2 {
        files_with_all(snapshot, &word.parts)?.unwrap_or_default()
    } else {
        HashSet::new()
    };
    let hit = TermHit {
        kind: MatchKind::Exact,
        evidence: MatchKind::Exact.evidence(),
        idf: idf(files, holders.len()),
    };
    if !resolution.has_exact() {
        plan.pattern(&word.text, Covers::Term(term), hit);
    }
    plan.weigh(term, holders.into_iter(), hit);
    plan.near.extend(resolution.near);
    Ok(())
}

/// Plain words that together spell one identifier (`worktree remove door`
/// for `worktreeRemoveDoor` or `worktree-remove-door`).
fn plan_joined(
    snapshot: &ReadSnapshot<'_>,
    files: u64,
    words: &[Word],
    plan: &mut Plan,
) -> Result<()> {
    let joined: String = words.iter().map(|word| word.text.as_str()).collect();
    let mut select = snapshot
        .connection()
        .prepare_cached("SELECT id, tok FROM vocab WHERE compact=?1 ORDER BY id LIMIT ?2")?;
    let rows = select.query_map(
        rusqlite::params![tokens::compact(&joined), JOINED_LIMIT],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    )?;
    for row in rows {
        let (id, text) = row?;
        let postings = snapshot.read_postings(id)?;
        let kind = if text == joined {
            MatchKind::Exact
        } else {
            MatchKind::Compact
        };
        let hit = TermHit {
            kind,
            evidence: kind.evidence(),
            idf: idf(files, postings.len()),
        };
        let full = plan.pattern(&text, Covers::Words, hit);
        for term in 0..words.len() {
            plan.weigh(term, postings.iter().map(|(file, _)| *file), hit);
        }
        plan.symbol_tokens.push((id, Covers::Words, hit, full));
    }
    Ok(())
}

fn plan_literal(
    snapshot: &ReadSnapshot<'_>,
    files: u64,
    term: usize,
    literal: &Literal,
    plan: &mut Plan,
) -> Result<()> {
    plan.literal_terms.push(term);
    let mut hit = TermHit {
        kind: MatchKind::Literal,
        evidence: MatchKind::Literal.evidence(),
        idf: 0,
    };
    if literal.anchor_sets.is_empty() {
        // An operator narrows lines, never files.
        plan.pattern(&literal.text, Covers::Term(term), hit);
        return Ok(());
    }
    let mut holders = HashSet::new();
    let mut indexed = false;
    for set in &literal.anchor_sets {
        if let Some(found) = files_with_all(snapshot, set)? {
            indexed = true;
            holders.extend(found);
        }
    }
    if !indexed {
        for anchor in &literal.anchor_sets[0] {
            if snapshot.token_id(anchor)?.is_none() {
                let close = fuzzy::resolve(snapshot, anchor)?.matches;
                plan.near.extend(close.into_iter().take(3));
            }
        }
    }
    hit.idf = idf(files, holders.len());
    plan.pattern(&literal.text, Covers::Term(term), hit);
    plan.weigh(term, holders.iter().copied(), hit);
    // A file indexing the literal as one whole token surely holds it, so it
    // is read before files that only hold its parts.
    if let Some(id) = snapshot.token_id(&literal.text)? {
        let weights = &mut plan.term_files[term];
        for (file, _) in snapshot.read_postings(id)? {
            if let Some(weight) = weights.get_mut(&file) {
                *weight += WHOLE_TOKEN_BOOST;
            }
        }
    }
    plan.required = Some(match plan.required.take() {
        Some(required) => required.intersection(&holders).copied().collect(),
        None => holders,
    });
    Ok(())
}

/// Files indexing every one of `parts` exactly, or `None` when one is not
/// indexed anywhere. Intersects the rarest few.
fn files_with_all(snapshot: &ReadSnapshot<'_>, parts: &[String]) -> Result<Option<HashSet<i64>>> {
    let mut ids = Vec::new();
    for part in parts {
        let Some(id) = snapshot.token_id(part)? else {
            return Ok(None);
        };
        ids.push((snapshot.effective_df(id)?, id));
    }
    ids.sort_unstable();
    ids.dedup_by_key(|(_, id)| *id);
    let mut holders: Option<HashSet<i64>> = None;
    for (_, id) in ids.into_iter().take(ANCHORS_USED) {
        let files = snapshot
            .read_postings(id)?
            .into_iter()
            .map(|(file, _)| file);
        holders = Some(match holders {
            None => files.collect(),
            Some(known) => files.filter(|file| known.contains(file)).collect(),
        });
    }
    Ok(holders)
}

fn file_count(conn: &Connection) -> Result<u64> {
    let count: i64 = conn
        .prepare_cached("SELECT count(*) FROM files")?
        .query_row([], |row| row.get(0))?;
    Ok(count.max(0) as u64)
}

/// Symbol definitions named by a matched token. Returns the files holding one.
fn symbol_hits(
    conn: &Connection,
    plan: &Plan,
    scope: &Scope,
    rows: &mut FileRows<'_>,
    candidates: &mut Candidates,
) -> Result<HashSet<i64>> {
    let mut files = HashSet::new();
    let mut select = conn.prepare_cached(
        "SELECT file, line, kind, sig FROM sym WHERE name=?1 ORDER BY file, line LIMIT ?2",
    )?;
    // The limit applies before the scope filter, so a filtered search reads
    // further to find definitions inside its scope.
    let limit = if scope.filters() {
        SCOPED_SYMBOLS_PER_TOKEN
    } else {
        SYMBOLS_PER_TOKEN
    };
    for &(id, covers, hit, full) in &plan.symbol_tokens {
        let found = select.query_map(rusqlite::params![id, limit], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })?;
        for symbol in found {
            let (file, line, kind, sig) = symbol?;
            let Some(row) = rows.admitted(file, scope)? else {
                continue;
            };
            let line = u32::try_from(line).unwrap_or(0);
            let mut candidate = Candidate::new(file, &row.path, line, HitField::Symbol, plan.terms);
            plan.apply(&mut candidate, covers, hit);
            candidate.symbol_kind = SymbolKind::from_code(kind);
            candidate.text = sig.unwrap_or_default();
            candidate.full_compact = full;
            candidates.add(candidate);
            files.insert(file);
        }
    }
    Ok(files)
}

/// Candidate files, best first: summed term weights, a boost for holding
/// every term and for defining a matched symbol; ties by file id.
fn rank_files(plan: &Plan, symbol_files: &HashSet<i64>) -> Vec<i64> {
    let files: HashSet<i64> = match &plan.required {
        Some(required) => required.clone(),
        None => plan
            .term_files
            .iter()
            .flat_map(|files| files.keys().copied())
            .chain(symbol_files.iter().copied())
            .collect(),
    };
    let mut scored: Vec<(u32, i64)> = files
        .into_iter()
        .map(|file| {
            let mut score = 0u32;
            let mut present = 0usize;
            for files in &plan.term_files {
                if let Some(weight) = files.get(&file) {
                    score += weight;
                    present += 1;
                }
            }
            if present == plan.terms {
                score += ALL_TERMS_FILE_BOOST;
            }
            if symbol_files.contains(&file) {
                score += SYMBOL_FILE_BOOST;
            }
            (score, file)
        })
        .collect();
    scored.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored.into_iter().map(|(_, file)| file).collect()
}

/// The files to read, in rank order, and the candidate counts.
pub(super) fn choose(
    ranked: &[i64],
    scope: &Scope,
    rows: &mut FileRows<'_>,
    budget: &Budget,
    outcome: &mut SearchOutcome,
) -> Result<Vec<(i64, Rc<FileRow>)>> {
    let mut chosen = Vec::new();
    let mut unread = 0usize;
    for (index, &file) in ranked.iter().enumerate() {
        // Past the cap only a scope filter needs each row; at the deadline
        // the rest are counted unread whatever their scope.
        let full = chosen.len() == MAX_CONFIRM_FILES;
        if full && (!scope.filters() || budget.expired()) {
            outcome.deadline_reached |= scope.filters();
            unread += ranked.len() - index;
            break;
        }
        let Some(row) = rows.admitted(file, scope)? else {
            continue;
        };
        if chosen.len() < MAX_CONFIRM_FILES {
            chosen.push((file, row));
        } else {
            unread += 1;
        }
    }
    outcome.candidate_files = chosen.len() + unread;
    outcome.files_unread = unread;
    Ok(chosen)
}

fn path_hit(plan: &Plan, file: i64, row: &FileRow, candidates: &mut Candidates) {
    let mut candidate = Candidate::new(file, &row.path, 0, HitField::Path, plan.terms);
    plan.match_text(&row.path, &mut candidate);
    if plan.satisfied(&candidate) {
        candidate.text.clone_from(&row.path);
        candidates.add(candidate);
    }
}

fn confirm_lines(
    conn: &Connection,
    root: &IndexSourceRoot,
    plan: &Plan,
    chosen: &[(i64, Rc<FileRow>)],
    budget: &Budget,
    outcome: &mut SearchOutcome,
    candidates: &mut Candidates,
) -> Result<()> {
    if plan.patterns.is_empty() {
        return Ok(());
    }
    let matcher = confirm::prefilter(&plan.patterns)?;
    let judge = |file: i64, path: &str, line: u32, field: HitField, text: &str| {
        let mut candidate = Candidate::new(file, path, line, field, plan.terms);
        plan.match_text(text, &mut candidate);
        plan.satisfied(&candidate).then(|| {
            candidate.text = confirm::hit_text(text);
            candidate
        })
    };
    let reads = Reads {
        conn,
        root,
        matcher: &matcher,
        budget,
    };
    reads.confirm(chosen, outcome, candidates, judge)
}

/// What one confirmation pass reads with.
pub(super) struct Reads<'a> {
    pub conn: &'a Connection,
    pub root: &'a IndexSourceRoot,
    pub matcher: &'a grep_regex::RegexMatcher,
    pub budget: &'a Budget,
}

impl Reads<'_> {
    /// Read each chosen file in order until the deadline, turning the lines
    /// the matcher finds into candidates through `judge`.
    pub fn confirm(
        &self,
        chosen: &[(i64, Rc<FileRow>)],
        outcome: &mut SearchOutcome,
        candidates: &mut Candidates,
        judge: impl Fn(i64, &str, u32, HitField, &str) -> Option<Candidate>,
    ) -> Result<()> {
        let mut searcher = confirm::searcher();
        for (index, (file, row)) in chosen.iter().enumerate() {
            if self.budget.expired() {
                outcome.deadline_reached = true;
                outcome.files_unread += chosen.len() - index;
                break;
            }
            let declared = symbol_lines(self.conn, *file)?;
            let mut found = Vec::new();
            let read = confirm::read_lines(
                self.root,
                &row.path,
                self.matcher,
                &mut searcher,
                |line, text| {
                    let field = if declared.contains(&line) {
                        HitField::Signature
                    } else {
                        HitField::Body
                    };
                    let before = found.len();
                    found.extend(judge(*file, &row.path, line, field, text));
                    found.len() > before
                },
            );
            read.tally(outcome);
            found
                .into_iter()
                .for_each(|candidate| candidates.add(candidate));
        }
        Ok(())
    }
}

pub(super) fn symbol_lines(conn: &Connection, file: i64) -> Result<HashSet<u32>> {
    let mut select = conn.prepare_cached("SELECT line FROM sym WHERE file=?1")?;
    let lines = select.query_map([file], |row| row.get::<_, i64>(0))?;
    let mut out = HashSet::new();
    for line in lines {
        out.insert(u32::try_from(line?).unwrap_or(0));
    }
    Ok(out)
}

/// Rank the candidates the request's kind keeps and page them into `outcome`.
pub(super) fn page_into(
    request: &SearchRequest,
    outcome: &mut SearchOutcome,
    candidates: Candidates,
) {
    let ranked = candidates.into_ranked(|candidate| keeps(request.kind, candidate.field));
    let (hits, end, omitted) = rank::page(
        ranked,
        request.limit(),
        request.max_bytes(),
        HitSource::Index,
    );
    outcome.hits = hits;
    outcome.page_end = end;
    outcome.omitted = omitted;
    outcome.omitted_at_least |= outcome.stopped_early();
}

/// Up to three labelled close spellings, each placed at its first symbol
/// definition or first file in scope.
fn guesses(
    conn: &Connection,
    near: &[TokenMatch],
    terms: usize,
    scope: &Scope,
    rows: &mut FileRows<'_>,
) -> Result<Vec<super::Hit>> {
    let mut out: Vec<super::Hit> = Vec::new();
    let mut seen = HashSet::new();
    let mut symbols = conn.prepare_cached(
        "SELECT file, line, kind FROM sym WHERE name=?1 ORDER BY file, line LIMIT 16",
    )?;
    for token in near {
        if out.len() == 3 || !seen.insert(token.id) {
            continue;
        }
        let mut place = None;
        let found = symbols.query_map([token.id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        for symbol in found {
            let (file, line, kind) = symbol?;
            if let Some(row) = rows.admitted(file, scope)? {
                let line = u32::try_from(line).unwrap_or(0);
                place = Some((row, line, HitField::Symbol, SymbolKind::from_code(kind)));
                break;
            }
        }
        if place.is_none() {
            place =
                first_file(conn, token.id, scope, rows)?.map(|row| (row, 0, HitField::Path, None));
        }
        if let Some((row, line, field, symbol_kind)) = place {
            out.push(super::Hit {
                path: row.path.clone(),
                line,
                field,
                symbol_kind,
                text: token.text.clone(),
                match_kind: MatchKind::Guess,
                terms_matched: 0,
                terms,
                score: 0,
                source: HitSource::Index,
            });
        }
    }
    Ok(out)
}

fn first_file(
    conn: &Connection,
    token: i64,
    scope: &Scope,
    rows: &mut FileRows<'_>,
) -> Result<Option<Rc<FileRow>>> {
    for (file, _) in crate::store::read::read_postings(conn, token)? {
        if let Some(row) = rows.admitted(file, scope)? {
            return Ok(Some(row));
        }
    }
    Ok(None)
}
