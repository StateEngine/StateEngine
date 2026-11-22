//! Code history written by the single writer. Every committed batch that
//! changed the index opens a generation stamped with the time it was
//! observed, and lists its file and symbol changes in `changes` in the same
//! transaction, so a reader sees an edit as soon as its batch commits.
//!
//! Old generations are pruned past [`RETAINED_GENERATIONS`]; readers report
//! the oldest retained generation instead of pretending history is complete.
use crate::{IndexError, Result, extract::SymbolKind};
use rusqlite::{OptionalExtension, Transaction, params};

/// Generations kept; older ones are pruned with their changes.
pub const RETAINED_GENERATIONS: i64 = 4096;
/// Pruning runs on every generation divisible by this.
const PRUNE_EVERY: i64 = 256;
/// Symbol rows listed per file and batch; the rest are counted.
pub(crate) const MAX_SYMBOL_ROWS: usize = 256;

/// What one `changes` row records; stored as its `kind` text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    SignatureChanged,
    BodyChanged,
    /// The file's content changed but none of its symbols did.
    FileOnly,
    /// A batch summarised rather than listed, such as a cold build.
    Bulk,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Added => "Added",
            Self::Removed => "Removed",
            Self::SignatureChanged => "SignatureChanged",
            Self::BodyChanged => "BodyChanged",
            Self::FileOnly => "FileOnly",
            Self::Bulk => "Bulk",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::Added,
            Self::Removed,
            Self::SignatureChanged,
            Self::BodyChanged,
            Self::FileOnly,
            Self::Bulk,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == text)
    }
}

/// One symbol that changed in a batch.
pub(crate) struct SymbolChange {
    pub key: [u8; 32],
    pub kind: ChangeKind,
    pub name: String,
    pub symbol_kind: Option<SymbolKind>,
    pub line: u32,
    pub end_line: u32,
}

/// Everything one file contributed to a batch. A hash is `None` when the
/// file did not exist on that side.
pub(crate) struct FileChange<'a> {
    pub path: &'a str,
    pub key: [u8; 16],
    pub previous: Option<[u8; 32]>,
    pub current: Option<[u8; 32]>,
    pub symbols: Vec<SymbolChange>,
}

/// Record one file's changes under a new generation. Returns `None`, and
/// writes nothing, when neither the content nor any symbol changed.
pub(crate) fn record(tx: &Transaction<'_>, change: &FileChange<'_>) -> Result<Option<i64>> {
    let file_kind = match (change.previous, change.current) {
        (None, _) => Some(ChangeKind::Added),
        (_, None) => Some(ChangeKind::Removed),
        (Some(before), Some(after)) if before != after && change.symbols.is_empty() => {
            Some(ChangeKind::FileOnly)
        }
        _ => None,
    };
    if file_kind.is_none() && change.symbols.is_empty() {
        return Ok(None);
    }
    let generation = open_generation(tx, "Files")?;
    let mut insert = tx.prepare_cached(
        "INSERT INTO changes(generation, ordinal, file_key, symbol_key, path, kind,
           pointer_json, previous_hash, current_hash, dependent_generation, baseline_reset,
           bulk_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?1, 0, ?10)",
    )?;
    let previous = change.previous.as_ref().map(<[u8; 32]>::as_slice);
    let current = change.current.as_ref().map(<[u8; 32]>::as_slice);
    let mut ordinal = 0i64;
    if let Some(kind) = file_kind {
        insert.execute(params![
            generation,
            ordinal,
            change.key.as_slice(),
            None::<&[u8]>,
            change.path,
            kind.as_str(),
            None::<String>,
            previous,
            current,
            None::<String>,
        ])?;
        ordinal += 1;
    }
    for symbol in change.symbols.iter().take(MAX_SYMBOL_ROWS) {
        let pointer = serde_json::json!({
            "name": symbol.name,
            "kind": symbol.symbol_kind.map(SymbolKind::name),
            "line": symbol.line,
            "end_line": symbol.end_line,
        });
        insert.execute(params![
            generation,
            ordinal,
            change.key.as_slice(),
            symbol.key.as_slice(),
            change.path,
            symbol.kind.as_str(),
            pointer.to_string(),
            previous,
            current,
            None::<String>,
        ])?;
        ordinal += 1;
    }
    if change.symbols.len() > MAX_SYMBOL_ROWS {
        let bulk = serde_json::json!({
            "symbol_changes": change.symbols.len(),
            "listed": MAX_SYMBOL_ROWS,
        });
        insert.execute(params![
            generation,
            ordinal,
            change.key.as_slice(),
            None::<&[u8]>,
            change.path,
            ChangeKind::Bulk.as_str(),
            None::<String>,
            previous,
            current,
            bulk.to_string(),
        ])?;
    }
    Ok(Some(generation))
}

/// Record a rebuild of the whole index: one bulk row that resets the
/// baseline, so a reader never diffs across it.
pub(crate) fn record_rebuild(tx: &Transaction<'_>, files: usize) -> Result<i64> {
    let generation = open_generation(tx, "Bulk")?;
    let bulk = serde_json::json!({ "reason": "cold_build", "files": files });
    tx.execute(
        "INSERT INTO changes(generation, ordinal, kind, dependent_generation, baseline_reset,
           bulk_json)
         VALUES (?1, 0, ?2, ?1, 1, ?3)",
        params![generation, ChangeKind::Bulk.as_str(), bulk.to_string()],
    )?;
    Ok(generation)
}

/// Note that the working tree was observed at a commit, so readers can ask
/// for changes since it.
pub(crate) fn record_commit(tx: &Transaction<'_>, oid: &[u8]) -> Result<i64> {
    if oid.len() != 20 && oid.len() != 32 {
        return Err(IndexError::Invalid(
            "a commit id is 20 (SHA-1) or 32 (SHA-256) bytes",
        ));
    }
    let generation = open_generation(tx, "Commit")?;
    tx.execute(
        "INSERT OR IGNORE INTO observed_commits(oid, generation) VALUES (?1, ?2)",
        params![oid, generation],
    )?;
    Ok(generation)
}

/// Bump `meta.generation` and stamp the new generation with the time now,
/// never earlier than the previous stamp, so a clock stepping back cannot
/// reorder generations against their times.
fn open_generation(tx: &Transaction<'_>, batch_kind: &str) -> Result<i64> {
    let previous: Option<i64> = tx
        .prepare_cached(
            "SELECT observed_unix_ms FROM generations ORDER BY generation DESC LIMIT 1",
        )?
        .query_row([], |row| row.get(0))
        .optional()?;
    let observed = now_unix_ms().max(previous.unwrap_or(0));
    let generation: i64 = tx
        .prepare_cached(
            "UPDATE meta SET generation=generation+1 WHERE singleton=1 RETURNING generation",
        )?
        .query_row([], |row| row.get(0))?;
    tx.prepare_cached(
        "INSERT INTO generations(generation, observed_unix_ms, event_serial, batch_kind)
         VALUES (?1, ?2, ?1, ?3)",
    )?
    .execute(params![generation, observed, batch_kind])?;
    if generation % PRUNE_EVERY == 0 {
        prune(tx, generation - RETAINED_GENERATIONS)?;
    }
    Ok(generation)
}

/// Drop every generation older than `cutoff` with what refers to it.
fn prune(tx: &Transaction<'_>, cutoff: i64) -> Result<()> {
    if cutoff <= 0 {
        return Ok(());
    }
    tx.execute(
        "DELETE FROM observed_commits WHERE generation < ?1",
        [cutoff],
    )?;
    tx.execute("DELETE FROM authors WHERE generation < ?1", [cutoff])?;
    tx.execute("DELETE FROM changes WHERE generation < ?1", [cutoff])?;
    tx.execute("DELETE FROM generations WHERE generation < ?1", [cutoff])?;
    Ok(())
}

/// Milliseconds since the Unix epoch, zero for a clock before it.
pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}
