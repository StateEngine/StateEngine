//! Index changes since a point: a relative duration, an observed time, or a
//! commit the working tree was observed at (a full id or a prefix of at
//! least seven hex digits).
//!
//! Pages run oldest first through `(generation, ordinal)` and stop at the
//! generation that was newest when the first page was read, so later edits
//! never shift a page. A cursor carries that bound, its position and a
//! digest of the request; a relative start is fixed by the first page, so
//! `--since 10m` pages stay stable however long the reader takes.
//!
//! History older than the oldest retained generation is gone. A start
//! before it returns every retained change with `pruned` set and the
//! retention floor named, rather than refusing.
use rusqlite::{OptionalExtension, params};
use se_atlas_index::{
    IndexError, Result,
    store::{ChangeKind, Reader},
};

pub const DEFAULT_LIMIT: usize = 50;
pub const MAX_LIMIT: usize = 500;
const MIN_COMMIT_PREFIX: usize = 7;
const MAX_CURSOR: usize = 24;

/// Where the changes start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Since {
    /// This many milliseconds before the first page was read.
    RelativeMillis(u64),
    /// Changes observed at or after this Unix time in milliseconds.
    ObservedUnixMillis(i64),
    /// Changes after the working tree was observed at this commit: 40 or 64
    /// hex digits, or a unique prefix of at least seven.
    Commit(String),
    /// Changes after this generation, through `through` when it is given
    /// (a delivered range's fence), else through the newest one.
    AfterGeneration { after: i64, through: Option<i64> },
}

#[derive(Clone, Debug)]
pub struct ChangesRequest {
    pub since: Since,
    /// Changes per page, at most [`MAX_LIMIT`]; zero means the default.
    pub limit: usize,
    /// `next_cursor` of the previous page of the same request.
    pub cursor: Option<String>,
}

impl ChangesRequest {
    pub fn new(since: Since) -> Self {
        Self {
            since,
            limit: DEFAULT_LIMIT,
            cursor: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeEntry {
    pub generation: i64,
    pub ordinal: i64,
    pub observed_unix_ms: i64,
    /// `None` for a kind this version does not know; `kind_text` keeps it.
    pub kind: Option<ChangeKind>,
    pub kind_text: String,
    pub path: Option<String>,
    pub symbol: Option<String>,
    pub symbol_kind: Option<String>,
    pub line: Option<u32>,
    /// The index was rebuilt here; diffs never span this change.
    pub baseline_reset: bool,
    /// A summarised change's details, as stored.
    pub bulk_json: Option<String>,
}

/// The oldest generation still held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionFloor {
    pub generation: i64,
    pub observed_unix_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangesAnswer {
    Found(Changes),
    /// No retained generation observed this commit. The caller may diff the
    /// commit against the tree itself.
    CommitNotObserved {
        commit: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub entries: Vec<ChangeEntry>,
    pub next_cursor: Option<String>,
    /// The newest generation these pages cover.
    pub through_generation: i64,
    pub retention_floor: Option<RetentionFloor>,
    /// The start lies before the retention floor: changes before it are not
    /// known, and the entries begin at the floor.
    pub pruned: bool,
}

/// Read one page of changes.
pub fn changes(reader: &Reader, request: &ChangesRequest) -> Result<ChangesAnswer> {
    let digest = request_digest(&request.since);
    let snapshot = reader.snapshot()?;
    let conn = snapshot.connection();
    let floor: Option<RetentionFloor> = conn
        .prepare_cached(
            "SELECT generation, observed_unix_ms FROM generations ORDER BY generation LIMIT 1",
        )?
        .query_row([], |row| {
            Ok(RetentionFloor {
                generation: row.get(0)?,
                observed_unix_ms: row.get(1)?,
            })
        })
        .optional()?;
    let (through, after, pruned) = match &request.cursor {
        Some(cursor) => {
            let (through, generation, ordinal) = parse_cursor(cursor, &digest)?;
            let pruned = floor.is_some_and(|floor| generation < floor.generation);
            (through, (generation, ordinal), pruned)
        }
        None => match first_page(conn, &request.since, floor)? {
            Ok(bounds) => bounds,
            Err(unobserved) => return Ok(unobserved),
        },
    };
    let limit = super::page_limit(request.limit, DEFAULT_LIMIT, MAX_LIMIT);
    let mut select = conn.prepare_cached(
        "SELECT c.generation, c.ordinal, g.observed_unix_ms, c.kind, c.path, c.pointer_json,
           c.baseline_reset, c.bulk_json
         FROM changes c JOIN generations g ON g.generation = c.generation
         WHERE (c.generation, c.ordinal) > (?1, ?2) AND c.generation <= ?3
         ORDER BY c.generation, c.ordinal LIMIT ?4",
    )?;
    let rows = select.query_map(
        params![after.0, after.1, through, limit as i64 + 1],
        entry_row,
    )?;
    let mut entries = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    let next_cursor = if entries.len() > limit {
        entries.truncate(limit);
        entries
            .last()
            .map(|last| cursor(through, last.generation, last.ordinal, &digest))
    } else {
        None
    };
    Ok(ChangesAnswer::Found(Changes {
        entries,
        next_cursor,
        through_generation: through,
        retention_floor: floor,
        pruned,
    }))
}

/// The newest generation, the position after which, and whether history
/// before the start was pruned.
type Bounds = (i64, (i64, i64), bool);

/// Where a first page starts, or the answer for a commit never observed.
fn first_page(
    conn: &rusqlite::Connection,
    since: &Since,
    floor: Option<RetentionFloor>,
) -> Result<std::result::Result<Bounds, ChangesAnswer>> {
    let newest: i64 = conn
        .prepare_cached("SELECT coalesce(max(generation), 0) FROM generations")?
        .query_row([], |row| row.get(0))?;
    let through = match since {
        Since::AfterGeneration {
            through: Some(fence),
            ..
        } => newest.min(*fence),
        _ => newest,
    };
    let start = match since {
        Since::RelativeMillis(ms) => {
            let ms = i64::try_from(*ms).unwrap_or(i64::MAX);
            Start::Time(se_atlas_index::store::now_unix_ms().saturating_sub(ms))
        }
        Since::ObservedUnixMillis(at) => Start::Time(*at),
        Since::AfterGeneration { after, .. } => Start::After(*after),
        Since::Commit(commit) => match commit_generation(conn, commit)? {
            Some(generation) => Start::After(generation),
            None => {
                return Ok(Err(ChangesAnswer::CommitNotObserved {
                    commit: commit.clone(),
                }));
            }
        },
    };
    let (first, pruned) = match start {
        Start::Time(at) => {
            let first: Option<i64> = conn
                .prepare_cached(
                    "SELECT min(generation) FROM generations WHERE observed_unix_ms >= ?1",
                )?
                .query_row([at], |row| row.get(0))?;
            let pruned = floor.is_some_and(|floor| at < floor.observed_unix_ms);
            (first.unwrap_or(through + 1), pruned)
        }
        Start::After(generation) => {
            let pruned = floor.is_some_and(|floor| generation + 1 < floor.generation);
            (generation + 1, pruned)
        }
    };
    Ok(Ok((through, (first - 1, i64::MAX), pruned)))
}

enum Start {
    Time(i64),
    After(i64),
}

fn entry_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChangeEntry> {
    let kind_text: String = row.get(3)?;
    let pointer: Option<serde_json::Value> = row
        .get::<_, Option<String>>(5)?
        .and_then(|json| serde_json::from_str(&json).ok());
    let field = |name: &str| pointer.as_ref().and_then(|p| p.get(name).cloned());
    Ok(ChangeEntry {
        generation: row.get(0)?,
        ordinal: row.get(1)?,
        observed_unix_ms: row.get(2)?,
        kind: ChangeKind::parse(&kind_text),
        kind_text,
        path: row.get(4)?,
        symbol: field("name").and_then(|v| v.as_str().map(str::to_owned)),
        symbol_kind: field("kind").and_then(|v| v.as_str().map(str::to_owned)),
        line: field("line")
            .and_then(|v| v.as_u64())
            .and_then(|line| u32::try_from(line).ok()),
        baseline_reset: row.get(6)?,
        bulk_json: row.get(7)?,
    })
}

/// The first generation that observed the commit a full id or unique
/// prefix names, or `None` when no retained generation observed it.
fn commit_generation(conn: &rusqlite::Connection, commit: &str) -> Result<Option<i64>> {
    let commit = commit.trim();
    let hex = commit.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex || commit.len() < MIN_COMMIT_PREFIX || commit.len() > 64 {
        return Err(IndexError::Invalid(
            "a commit is 7 to 64 hex digits (a full id or a unique prefix)",
        ));
    }
    let mut select = conn.prepare_cached(
        "SELECT hex(oid), min(generation) FROM observed_commits
         WHERE substr(hex(oid), 1, ?2) = ?1 GROUP BY oid LIMIT 2",
    )?;
    let upper = commit.to_ascii_uppercase();
    let rows = select.query_map(params![upper, upper.len() as i64], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let found = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    match found.as_slice() {
        [] => Ok(None),
        [(_, generation)] => Ok(Some(*generation)),
        _ => Err(IndexError::Invalid(
            "the commit prefix matches several observed commits; give more digits",
        )),
    }
}

/// Four base-36 digits naming the request, so a cursor is never replayed
/// against a different one. A relative start hashes its duration, not the
/// time it resolved to, so it stays the same across pages.
fn request_digest(since: &Since) -> String {
    let identity = match since {
        Since::RelativeMillis(ms) => format!("relative:{ms}"),
        Since::ObservedUnixMillis(at) => format!("observed:{at}"),
        Since::Commit(commit) => format!("commit:{}", commit.trim().to_ascii_lowercase()),
        Since::AfterGeneration { after, through } => format!("after:{after}:{through:?}"),
    };
    let digest = blake3::hash(identity.as_bytes());
    let value = u32::from_le_bytes([
        digest.as_bytes()[0],
        digest.as_bytes()[1],
        digest.as_bytes()[2],
        0,
    ]);
    let mut text = base36(u64::from(value % 1_679_616));
    while text.len() < 4 {
        text.insert(0, '0');
    }
    text
}

fn cursor(through: i64, generation: i64, ordinal: i64, digest: &str) -> String {
    let part = |value: i64| base36(u64::try_from(value).unwrap_or(0));
    format!(
        "{}.{}.{}.{digest}",
        part(through),
        part(generation),
        part(ordinal)
    )
}

fn parse_cursor(cursor: &str, digest: &str) -> Result<(i64, i64, i64)> {
    let invalid = IndexError::Invalid("the changes cursor is not one this query returned");
    if cursor.len() > MAX_CURSOR {
        return Err(invalid);
    }
    let parts: Vec<&str> = cursor.split('.').collect();
    let [through, generation, ordinal, tag] = parts.as_slice() else {
        return Err(invalid);
    };
    if *tag != digest {
        return Err(IndexError::Invalid(
            "the changes cursor belongs to a different request",
        ));
    }
    let number = |text: &str| {
        u64::from_str_radix(text, 36)
            .ok()
            .and_then(|value| i64::try_from(value).ok())
    };
    match (number(through), number(generation), number(ordinal)) {
        (Some(through), Some(generation), Some(ordinal)) => Ok((through, generation, ordinal)),
        _ => Err(invalid),
    }
}

fn base36(mut value: u64) -> String {
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    loop {
        out.push(DIGITS[(value % 36) as usize]);
        value /= 36;
        if value == 0 {
            break;
        }
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{Repo, TestResult};

    fn page(reader: &Reader, since: Since, cursor: Option<String>) -> Result<Changes> {
        let request = ChangesRequest {
            since,
            limit: 2,
            cursor,
        };
        match changes(reader, &request)? {
            ChangesAnswer::Found(found) => Ok(found),
            ChangesAnswer::CommitNotObserved { .. } => Err(IndexError::Invalid("unobserved")),
        }
    }

    #[test]
    fn each_committed_edit_is_a_change_and_pages_stay_stable() -> TestResult {
        let mut repo = Repo::build(&[("src/a.js", "export function one() { return 1; }\n")])?;
        repo.store.record_commit(&[0xab; 20])?;
        let two = "export function one() { return 2; }\nexport function two() {}\n";
        repo.edit("src/a.js", two)?;
        repo.edit("src/b.js", "export const b = 1;\n")?;
        let reader = repo.reader()?;
        let mut cursor = None;
        let mut seen = Vec::new();
        loop {
            let found = page(&reader, Since::RelativeMillis(60_000), cursor.take())?;
            assert!(found.entries.len() <= 2);
            seen.extend(
                found
                    .entries
                    .iter()
                    .map(|entry| (entry.kind, entry.symbol.clone(), entry.path.clone())),
            );
            let Some(next) = found.next_cursor else {
                break;
            };
            assert!(next.len() <= MAX_CURSOR);
            repo.edit("src/c.js", "export const late = 1;\n")?;
            cursor = Some(next);
        }
        let a = Some("src/a.js".to_owned());
        assert_eq!(seen[0].0, Some(ChangeKind::Bulk), "the cold build");
        let body = (
            Some(ChangeKind::BodyChanged),
            Some("one".to_owned()),
            a.clone(),
        );
        assert_eq!(seen[1], body);
        assert_eq!(
            seen[2],
            (Some(ChangeKind::Added), Some("two".to_owned()), a)
        );
        assert_eq!(seen[3].0, Some(ChangeKind::Added));
        assert_eq!(seen[3].2.as_deref(), Some("src/b.js"));
        assert_eq!(seen.len(), 5, "later edits stay off pages already bounded");

        let since_commit = page(&reader, Since::Commit("ABABABA".into()), None)?;
        assert_eq!(since_commit.entries.len(), 2);
        assert_eq!(since_commit.entries[0].symbol.as_deref(), Some("one"));
        let replayed = since_commit.next_cursor.clone();
        assert!(page(&reader, Since::RelativeMillis(1), replayed).is_err());

        let old = page(&reader, Since::ObservedUnixMillis(0), None)?;
        assert!(old.pruned, "a start before the oldest generation says so");
        assert!(old.retention_floor.is_some());
        Ok(())
    }
}
