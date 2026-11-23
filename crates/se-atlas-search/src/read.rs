//! The reading and paging layer the index-backed searches share: cached file
//! rows, choosing which candidate files to read, confirming their lines
//! through custody, and paging the ranked hits.
use crate::{
    Budget, HitField, HitSource, MAX_CONFIRM_FILES, Scope, SearchOutcome, SearchRequest, confirm,
    keeps,
    rank::{self, Candidate, Candidates},
};
use rusqlite::{Connection, OptionalExtension};
use se_atlas_index::{Result, custody::IndexSourceRoot};
use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
};

/// An indexed file's path and language, cached for one search.
pub(crate) struct FileRow {
    pub path: String,
    lang: String,
}

pub(crate) struct FileRows<'c> {
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

    pub fn get(&mut self, id: i64) -> Result<Option<Rc<FileRow>>> {
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

    pub fn admitted(&mut self, id: i64, scope: &Scope) -> Result<Option<Rc<FileRow>>> {
        Ok(self
            .get(id)?
            .filter(|row| scope.admits(&row.path, &row.lang)))
    }
}

/// The files to read, in rank order, and the candidate counts.
pub(crate) fn choose(
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

/// What one confirmation pass reads with.
pub(crate) struct Reads<'a> {
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

fn symbol_lines(conn: &Connection, file: i64) -> Result<HashSet<u32>> {
    let mut select = conn.prepare_cached("SELECT line FROM sym WHERE file=?1")?;
    let lines = select.query_map([file], |row| row.get::<_, i64>(0))?;
    let mut out = HashSet::new();
    for line in lines {
        out.insert(u32::try_from(line?).unwrap_or(0));
    }
    Ok(out)
}

/// Rank the candidates the request's kind keeps and page them into `outcome`.
pub(crate) fn page_into(
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

/// Tf points for ranking candidate files: a file that uses a matched token
/// often is read before one that mentions it once.
pub(crate) fn tf_points(tf: u32) -> u32 {
    const MAX_TF_POINTS: f64 = 100.0;
    ((1.0 + f64::from(tf)).ln() * 20.0)
        .round()
        .clamp(0.0, MAX_TF_POINTS) as u32
}
