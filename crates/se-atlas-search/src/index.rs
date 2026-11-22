//! The index-first pipeline: resolve terms, rank candidate files, confirm
//! the best of them line by line, and add symbol and path hits.
use crate::{
    Budget, HitField, KindFilter, MatchKind, Scope, SearchOutcome, SearchRequest, confirm,
    confirm::{Covers, LineText, Pattern},
    fuzzy::{self, TokenMatch},
    query::{Literal, Word},
    rank::{Candidate, Candidates, TermHit, idf},
    read::{FileRow, FileRows, Reads, choose, page_into, tf_points},
    symbols,
};
use rusqlite::Connection;
use se_atlas_index::{Result, custody::IndexSourceRoot, extract::tokens, store::ReadSnapshot};
use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};

/// Anchor tokens intersected per literal, rarest first.
const ANCHORS_USED: usize = 4;
/// Separator-stripped spellings tried for words written as one identifier.
const JOINED_LIMIT: i64 = 8;
const SYMBOL_FILE_BOOST: u32 = 200;
const ALL_TERMS_FILE_BOOST: u32 = 300;
const WHOLE_TOKEN_BOOST: u32 = 500;

/// A vocab token whose symbol definitions are hits for the query.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SymbolToken {
    pub id: i64,
    pub covers: Covers,
    pub hit: TermHit,
    /// The token equals the whole query once separators are removed.
    pub full: bool,
}

/// Everything the index said about the query's terms.
#[derive(Default)]
pub(crate) struct Plan {
    /// Plain words, then literals.
    pub terms: usize,
    pub words: usize,
    pub patterns: Vec<Pattern>,
    /// Per term, each candidate file's best weight.
    term_files: Vec<HashMap<i64, u32>>,
    /// Files holding every literal's anchors, when the query has literals.
    required: Option<HashSet<i64>>,
    /// Term indexes every hit must satisfy.
    pub literal_terms: Vec<usize>,
    pub symbol_tokens: Vec<SymbolToken>,
    pub near: Vec<TokenMatch>,
    query_compact: String,
}

impl Plan {
    /// Weigh each `(file, tf)` for `term`, keeping a file's best weight.
    fn weigh(&mut self, term: usize, files: impl Iterator<Item = (i64, u32)>, hit: TermHit) {
        let weight = u32::from(hit.evidence) * 10 + u32::from(hit.idf);
        let slot = &mut self.term_files[term];
        for (file, tf) in files {
            let best = slot.entry(file).or_insert(0);
            *best = (*best).max(weight + tf_points(tf));
        }
    }

    fn pattern(&mut self, text: &str, covers: Covers, hit: TermHit) -> bool {
        let full = tokens::compact(text) == self.query_compact;
        self.patterns.push(Pattern::new(text, covers, hit, full));
        full
    }

    pub fn apply(&self, candidate: &mut Candidate, covers: Covers, hit: TermHit) {
        match covers {
            Covers::Term(term) => candidate.record(term, hit),
            Covers::Words => (0..self.words).for_each(|term| candidate.record(term, hit)),
        }
    }

    pub fn satisfied(&self, candidate: &Candidate) -> bool {
        self.literal_terms
            .iter()
            .all(|&term| candidate.terms.get(term).is_some_and(Option::is_some))
    }

    /// Record every pattern found in `text` on `candidate`.
    pub fn match_text(&self, text: &str, candidate: &mut Candidate) {
        let text = LineText::new(text);
        for pattern in &self.patterns {
            if text.contains(pattern) {
                self.apply(candidate, pattern.covers, pattern.hit);
                candidate.full_compact |= pattern.full;
            }
        }
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
    let symbol_files = match request.kind {
        KindFilter::All | KindFilter::Symbol if plan.literal_terms.is_empty() => {
            symbols::token_hits(conn, &plan, &scope, &mut rows, &mut candidates)?
        }
        KindFilter::All | KindFilter::Symbol => symbols::literal_hits(
            snapshot,
            &plan,
            literals,
            &scope,
            &mut rows,
            &mut candidates,
        )?,
        KindFilter::Text | KindFilter::Path => HashSet::new(),
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
        outcome.guesses = symbols::guesses(snapshot, &plan, &scope, &mut rows)?;
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
        let covers = Covers::Term(term);
        let full = plan.pattern(&found.text, covers, hit);
        plan.weigh(term, postings.into_iter(), hit);
        plan.symbol_tokens.push(SymbolToken {
            id: found.id,
            covers,
            hit,
            full,
        });
    }
    // `QueryReader::new` indexes `query` and `reader` but not `queryreader`:
    // files holding every part may hold the word inside a longer token, so
    // they are candidates too, and the word as written is always confirmed
    // as an exact match wherever a line holds it.
    let holders = if word.parts.len() >= 2 {
        files_with_all(snapshot, &word.parts)?.unwrap_or_default()
    } else {
        HashMap::new()
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
        if !fuzzy::is_live(snapshot, id)? {
            continue;
        }
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
            plan.weigh(term, postings.iter().copied(), hit);
        }
        plan.symbol_tokens.push(SymbolToken {
            id,
            covers: Covers::Words,
            hit,
            full,
        });
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
    let mut holders: HashMap<i64, u32> = HashMap::new();
    let mut indexed = false;
    for set in &literal.anchor_sets {
        if let Some(found) = files_with_all(snapshot, set)? {
            indexed = true;
            for (file, tf) in found {
                let known = holders.entry(file).or_insert(0);
                *known = (*known).max(tf);
            }
        }
    }
    if !indexed {
        for anchor in &literal.anchor_sets[0] {
            if posted_token(snapshot, anchor)?.is_none() {
                let close = fuzzy::resolve(snapshot, anchor)?.matches;
                plan.near.extend(close.into_iter().take(3));
            }
        }
    }
    hit.idf = idf(files, holders.len());
    plan.pattern(&literal.text, Covers::Term(term), hit);
    plan.weigh(term, holders.iter().map(|(file, tf)| (*file, *tf)), hit);
    // A file indexing the literal as one whole token surely holds it, so it
    // is read before files that only hold its parts.
    if let Some((id, _)) = posted_token(snapshot, &literal.text)? {
        let weights = &mut plan.term_files[term];
        for (file, _) in snapshot.read_postings(id)? {
            if let Some(weight) = weights.get_mut(&file) {
                *weight += WHOLE_TOKEN_BOOST;
            }
        }
    }
    let holders: HashSet<i64> = holders.into_keys().collect();
    plan.required = Some(match plan.required.take() {
        Some(required) => required.intersection(&holders).copied().collect(),
        None => holders,
    });
    Ok(())
}

/// The vocab id and live document frequency of `token`, when some file
/// still holds it. A removed word's row stays in vocab with no postings.
fn posted_token(snapshot: &ReadSnapshot<'_>, token: &str) -> Result<Option<(i64, u64)>> {
    let Some(id) = snapshot.token_id(token)? else {
        return Ok(None);
    };
    let df = snapshot.effective_df(id)?;
    Ok((df > 0).then_some((id, df)))
}

/// Files indexing every one of `parts` exactly, each with the smallest tf
/// among the parts intersected, or `None` when one part is held nowhere.
/// Intersects the rarest few.
fn files_with_all(
    snapshot: &ReadSnapshot<'_>,
    parts: &[String],
) -> Result<Option<HashMap<i64, u32>>> {
    let mut ids = Vec::new();
    for part in parts {
        let Some((id, df)) = posted_token(snapshot, part)? else {
            return Ok(None);
        };
        ids.push((df, id));
    }
    ids.sort_unstable();
    ids.dedup_by_key(|(_, id)| *id);
    let mut holders: Option<HashMap<i64, u32>> = None;
    for (_, id) in ids.into_iter().take(ANCHORS_USED) {
        let postings = snapshot.read_postings(id)?.into_iter();
        holders = Some(match holders {
            None => postings.collect(),
            Some(known) => postings
                .filter_map(|(file, tf)| known.get(&file).map(|held| (file, tf.min(*held))))
                .collect(),
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

/// Candidate files, best first: summed term weights (evidence, idf and tf),
/// a boost for holding every term and for defining a matched symbol; ties by
/// file id.
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
