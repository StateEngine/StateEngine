//! Incremental re-index of one file. Only `(tok, file, tf)` rows whose tf
//! changed reach `post_delta` (tf 0 is a tombstone) and only new identifier
//! trigrams reach `gram_delta`; `vocab.df` and `vocab_post` are never written
//! here, only by compaction. Symbols are diffed by stable key, so an edit
//! rewrites only the rows it changed.
use super::{
    Store,
    history::{self, ChangeKind, FileChange, SymbolChange},
    varint,
    write::{self, FileRecord},
};
use crate::{
    IndexError, Result,
    custody::{GuardedRead, IndexSourceRoot, SourceFile},
    extract::{
        self, SymbolKind,
        covers::{self, CoverFile, CoverGraph},
        display_name, file_key,
        imports::Resolver,
        parents_first,
    },
    policy,
};
use rusqlite::{OptionalExtension, Transaction, params};
use std::collections::HashMap;

/// Symbol changes of one update, by stable key.
#[derive(Clone, Debug, Default)]
pub struct SymbolDiff {
    pub added: Vec<[u8; 32]>,
    pub removed: Vec<[u8; 32]>,
    pub signature_changed: Vec<[u8; 32]>,
    pub body_changed: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct UpdateReport {
    pub file: i64,
    pub created: bool,
    pub new_tokens: usize,
    pub delta_rows: usize,
    pub flags: u32,
    pub symbols: SymbolDiff,
    /// The generation this update recorded its changes under; `None` when
    /// nothing changed.
    pub generation: Option<i64>,
}

/// What `index_path` did with one path. `removed` is true when the path had
/// been indexed and its stale rows were dropped.
#[derive(Clone, Debug)]
pub enum PathOutcome {
    Indexed(UpdateReport),
    /// The private-file policy denies the name.
    Denied {
        removed: bool,
    },
    /// Custody refused what the name now denotes (a link, a device, a
    /// directory, a Windows short-name alias).
    Refused {
        removed: bool,
    },
    /// No file exists at the name.
    Absent {
        removed: bool,
    },
}

struct Existing {
    id: i64,
    name: String,
    kind: Option<SymbolKind>,
    parent: Option<i64>,
    line: i64,
    end_line: i64,
    sig_hash: i64,
    body_hash: i64,
}

impl Store {
    /// Read one path through custody and index or remove it.
    pub fn index_path(
        &mut self,
        root: &IndexSourceRoot,
        resolver: &mut Resolver,
        path: &str,
    ) -> Result<PathOutcome> {
        match root.read_guarded_file(path)? {
            GuardedRead::Source(source) => {
                resolver.insert(path);
                self.update_file(resolver, path, &source)
                    .map(PathOutcome::Indexed)
            }
            GuardedRead::Denied => self
                .forget(resolver, path)
                .map(|removed| PathOutcome::Denied { removed }),
            GuardedRead::Refused => self
                .forget(resolver, path)
                .map(|removed| PathOutcome::Refused { removed }),
            GuardedRead::Absent => self
                .forget(resolver, path)
                .map(|removed| PathOutcome::Absent { removed }),
        }
    }

    fn forget(&mut self, resolver: &mut Resolver, path: &str) -> Result<bool> {
        resolver.remove(path);
        self.remove_file(path)
    }

    /// Re-index one file read through custody, in one transaction.
    pub fn update_file(
        &mut self,
        resolver: &Resolver,
        path: &str,
        source: &SourceFile,
    ) -> Result<UpdateReport> {
        if policy::file_denied(path) {
            return Err(IndexError::Invalid("a policy-denied path is never indexed"));
        }
        let extracted = extract::extract(path, &source.bytes, source.prefix_only);
        let mut record = FileRecord::new(path, source, extracted);
        let tx = self.connection_mut().transaction()?;
        record.targets = resolve_targets(&tx, resolver, &record)?;
        let previous = file_hash(&tx, path)?;
        let file = write::upsert_file(&tx, None, &record)?;
        let (new_tokens, delta_rows) = diff_tokens(&tx, file, &record)?;
        let (symbols, changed) = diff_symbols(&tx, file, &record)?;
        sync_imports(&tx, file, &record)?;
        refresh_covers(&tx, file)?;
        let generation = history::record(
            &tx,
            &FileChange {
                path,
                key: file_key(path),
                previous,
                current: Some(record.extracted.hash),
                symbols: changed,
            },
        )?;
        tx.commit()?;
        Ok(UpdateReport {
            file,
            created: previous.is_none(),
            new_tokens,
            delta_rows,
            flags: record.extracted.flags,
            symbols,
            generation,
        })
    }

    /// Drop one file, tombstoning every posting it held.
    pub fn remove_file(&mut self, path: &str) -> Result<bool> {
        let tx = self.connection_mut().transaction()?;
        let Some(file) = file_id(&tx, path)? else {
            return Ok(false);
        };
        let previous = file_hash(&tx, path)?;
        let removed = in_line_order(existing_symbols(&tx, file)?)
            .into_iter()
            .filter_map(|(key, old)| removed_change(&key, old))
            .collect();
        history::record(
            &tx,
            &FileChange {
                path,
                key: file_key(path),
                previous,
                current: None,
                symbols: removed,
            },
        )?;
        let mut tombstone = tx.prepare_cached(
            "INSERT OR REPLACE INTO post_delta(tok, file, tf) VALUES (?1, ?2, 0)",
        )?;
        for (tok, _) in old_tokens(&tx, file)? {
            tombstone.execute(params![tok, file])?;
        }
        drop(tombstone);
        tx.execute("DELETE FROM file_tok WHERE file=?1", [file])?;
        tx.execute("DELETE FROM sym WHERE file=?1", [file])?;
        tx.execute("DELETE FROM imp WHERE file=?1", [file])?;
        tx.execute(
            "UPDATE imp SET target_file=NULL WHERE target_file=?1",
            [file],
        )?;
        tx.execute("DELETE FROM covers WHERE test_file=?1", [file])?;
        tx.execute("DELETE FROM covers WHERE target_file=?1", [file])?;
        tx.execute("DELETE FROM files WHERE id=?1", [file])?;
        tx.commit()?;
        Ok(true)
    }
}

fn file_id(tx: &Transaction<'_>, path: &str) -> Result<Option<i64>> {
    Ok(tx
        .prepare_cached("SELECT id FROM files WHERE path=?1")?
        .query_row([path], |row| row.get(0))
        .optional()?)
}

fn file_hash(tx: &Transaction<'_>, path: &str) -> Result<Option<[u8; 32]>> {
    let hash: Option<Vec<u8>> = tx
        .prepare_cached("SELECT hash FROM files WHERE path=?1")?
        .query_row([path], |row| row.get(0))
        .optional()?;
    hash.map(|hash| {
        <[u8; 32]>::try_from(hash.as_slice())
            .map_err(|_| IndexError::Corrupt("files.hash is not 32 bytes"))
    })
    .transpose()
}

fn resolve_targets(
    tx: &Transaction<'_>,
    resolver: &Resolver,
    record: &FileRecord,
) -> Result<Vec<Option<i64>>> {
    record
        .extracted
        .imports
        .iter()
        .map(|spec| match resolver.resolve(&record.path, spec) {
            Some(target) => file_id(tx, &target),
            None => Ok(None),
        })
        .collect()
}

fn old_tokens(tx: &Transaction<'_>, file: i64) -> Result<Vec<(i64, u32)>> {
    let blob: Option<Vec<u8>> = tx
        .prepare_cached("SELECT toks FROM file_tok WHERE file=?1")?
        .query_row([file], |row| row.get(0))
        .optional()?;
    blob.map_or(Ok(Vec::new()), |blob| varint::decode_pairs(&blob))
}

/// Write only the changed `(tok, file, tf)` rows and the new `file_tok`.
fn diff_tokens(tx: &Transaction<'_>, file: i64, record: &FileRecord) -> Result<(usize, usize)> {
    let old = old_tokens(tx, file)?;
    let mut new = Vec::with_capacity(record.extracted.tokens.len());
    let mut created = 0;
    for (token, tf) in &record.extracted.tokens {
        let (id, fresh) = write::intern_token(tx, token, true)?;
        created += usize::from(fresh);
        new.push((id, *tf));
    }
    new.sort_unstable();
    let mut delta =
        tx.prepare_cached("INSERT OR REPLACE INTO post_delta(tok, file, tf) VALUES (?1, ?2, ?3)")?;
    let mut rows = 0;
    let (mut i, mut j) = (0, 0);
    while i < old.len() || j < new.len() {
        let (tok, before, after) = match (old.get(i), new.get(j)) {
            (Some(o), Some(n)) if o.0 == n.0 => {
                i += 1;
                j += 1;
                (o.0, o.1, n.1)
            }
            (Some(o), Some(n)) if o.0 < n.0 => {
                i += 1;
                (o.0, o.1, 0)
            }
            (Some(o), None) => {
                i += 1;
                (o.0, o.1, 0)
            }
            (_, Some(n)) => {
                j += 1;
                (n.0, 0, n.1)
            }
            (None, None) => break,
        };
        if before != after {
            delta.execute(params![tok, file, after])?;
            rows += 1;
        }
    }
    if old != new {
        tx.prepare_cached("INSERT OR REPLACE INTO file_tok(file, toks) VALUES (?1, ?2)")?
            .execute(params![file, varint::encode_pairs(&new)?])?;
    }
    Ok((created, rows))
}

fn existing_symbols(tx: &Transaction<'_>, file: i64) -> Result<HashMap<Vec<u8>, Existing>> {
    let mut select = tx.prepare_cached(
        "SELECT s.key, s.id, s.parent, s.line, s.end_line, s.sig_hash, s.body_hash, v.tok, s.kind,
           s.sig FROM sym s JOIN vocab v ON v.id = s.name WHERE s.file=?1",
    )?;
    let rows = select.query_map([file], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            Existing {
                id: row.get(1)?,
                parent: row.get(2)?,
                line: row.get(3)?,
                end_line: row.get(4)?,
                sig_hash: row.get(5)?,
                body_hash: row.get(6)?,
                name: display_name(
                    row.get::<_, Option<String>>(9)?.as_deref(),
                    &row.get::<_, String>(7)?,
                ),
                kind: row
                    .get::<_, Option<i64>>(8)?
                    .and_then(SymbolKind::from_code),
            },
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Symbols by line, then id, so removals are recorded in a stable order.
fn in_line_order(symbols: HashMap<Vec<u8>, Existing>) -> Vec<(Vec<u8>, Existing)> {
    let mut symbols: Vec<_> = symbols.into_iter().collect();
    symbols.sort_by_key(|(_, old)| (old.line, old.id));
    symbols
}

/// The history row of a symbol that left the file.
fn removed_change(key: &[u8], old: Existing) -> Option<SymbolChange> {
    Some(SymbolChange {
        key: <[u8; 32]>::try_from(key).ok()?,
        kind: ChangeKind::Removed,
        name: old.name,
        symbol_kind: old.kind,
        line: u32::try_from(old.line).unwrap_or(0),
        end_line: u32::try_from(old.end_line).unwrap_or(0),
    })
}

fn diff_symbols(
    tx: &Transaction<'_>,
    file: i64,
    record: &FileRecord,
) -> Result<(SymbolDiff, Vec<SymbolChange>)> {
    let mut existing = existing_symbols(tx, file)?;
    let mut diff = SymbolDiff::default();
    let mut changed = Vec::new();
    let change = |symbol: &extract::Symbol, kind| SymbolChange {
        key: symbol.key,
        kind,
        name: symbol.name.clone(),
        symbol_kind: Some(symbol.kind),
        line: symbol.line,
        end_line: symbol.end_line,
    };
    let symbols = &record.extracted.symbols;
    let mut ids: Vec<Option<i64>> = vec![None; symbols.len()];
    let accuracy = record.extracted.accuracy as i64;
    let mut insert = tx.prepare_cached(write::INSERT_SYMBOL)?;
    let mut update = tx.prepare_cached(
        "UPDATE sym SET parent=?2, line=?3, end_line=?4, accuracy=?5, exported=?6, sig=?7,
           sig_hash=?8, body_hash=?9 WHERE id=?1",
    )?;
    for index in parents_first(symbols) {
        let symbol = &symbols[index];
        let parent = write::parent_id(symbol, &ids);
        let Some(old) = existing.remove(symbol.key.as_slice()) else {
            let name = write::intern_token(tx, &symbol.name.to_lowercase(), true)?.0;
            write::insert_symbol(&mut insert, symbol, file, parent, name, accuracy)?;
            ids[index] = Some(tx.last_insert_rowid());
            diff.added.push(symbol.key);
            changed.push(change(symbol, ChangeKind::Added));
            continue;
        };
        if old.sig_hash != symbol.sig_hash {
            diff.signature_changed.push(symbol.key);
            changed.push(change(symbol, ChangeKind::SignatureChanged));
        } else if old.body_hash != symbol.body_hash {
            diff.body_changed.push(symbol.key);
            changed.push(change(symbol, ChangeKind::BodyChanged));
        }
        let moved = old.parent != parent
            || old.line != i64::from(symbol.line)
            || old.end_line != i64::from(symbol.end_line);
        if moved || old.sig_hash != symbol.sig_hash || old.body_hash != symbol.body_hash {
            update.execute(params![
                old.id,
                parent,
                symbol.line,
                symbol.end_line,
                accuracy,
                symbol.exported,
                symbol.sig,
                symbol.sig_hash,
                symbol.body_hash
            ])?;
        }
        ids[index] = Some(old.id);
    }
    let mut delete = tx.prepare_cached("DELETE FROM sym WHERE id=?1")?;
    for (key, old) in in_line_order(existing) {
        delete.execute([old.id])?;
        if let Some(removed) = removed_change(&key, old) {
            diff.removed.push(removed.key);
            changed.push(removed);
        }
    }
    Ok((diff, changed))
}

/// Write only the import rows that changed.
fn sync_imports(tx: &Transaction<'_>, file: i64, record: &FileRecord) -> Result<()> {
    let mut select =
        tx.prepare_cached("SELECT spelling, target_file, kind, reexport FROM imp WHERE file=?1")?;
    let mut existing = select
        .query_map([file], |row| {
            Ok((
                row.get::<_, String>(0)?,
                (
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, bool>(3)?,
                ),
            ))
        })?
        .collect::<rusqlite::Result<HashMap<_, _>>>()?;
    let mut upsert = tx.prepare_cached(
        "INSERT OR REPLACE INTO imp(file, spelling, target_file, kind, reexport)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for (spec, target) in record.extracted.imports.iter().zip(&record.targets) {
        let row = (*target, spec.kind as i64, spec.reexport);
        if existing.remove(&spec.spelling) != Some(row) {
            upsert.execute(params![file, spec.spelling, row.0, row.1, row.2])?;
        }
    }
    let mut delete = tx.prepare_cached("DELETE FROM imp WHERE file=?1 AND spelling=?2")?;
    for spelling in existing.into_keys() {
        delete.execute(params![file, spelling])?;
    }
    Ok(())
}

/// Recompute the edges of this file acting as a test, writing only changes.
fn refresh_covers(tx: &Transaction<'_>, file: i64) -> Result<()> {
    let graph = SqlGraph { tx };
    let fresh = match graph.file(file)? {
        Some(test) => covers::covers_for(&test, &graph)?,
        None => Vec::new(),
    };
    let mut select =
        tx.prepare_cached("SELECT target_file, how, via_helper FROM covers WHERE test_file=?1")?;
    let mut existing = select
        .query_map([file], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                (row.get::<_, i64>(1)?, row.get::<_, bool>(2)?),
            ))
        })?
        .collect::<rusqlite::Result<HashMap<_, _>>>()?;
    let changed: Vec<_> = fresh
        .into_iter()
        .filter(|cover| {
            existing.remove(&cover.target_file) != Some((cover.how as i64, cover.via_helper))
        })
        .collect();
    write::insert_covers(tx, &changed)?;
    let mut delete =
        tx.prepare_cached("DELETE FROM covers WHERE test_file=?1 AND target_file=?2")?;
    for target in existing.into_keys() {
        delete.execute(params![file, target])?;
    }
    Ok(())
}

struct SqlGraph<'t, 'c> {
    tx: &'t Transaction<'c>,
}

impl CoverGraph for SqlGraph<'_, '_> {
    fn file(&self, id: i64) -> Result<Option<CoverFile>> {
        let row: Option<(String, u32)> = self
            .tx
            .prepare_cached("SELECT path, flags FROM files WHERE id=?1")?
            .query_row([id], |row| {
                Ok((row.get(0)?, row.get::<_, Option<u32>>(1)?.unwrap_or(0)))
            })
            .optional()?;
        let Some((path, flags)) = row else {
            return Ok(None);
        };
        let mut select = self.tx.prepare_cached(
            "SELECT DISTINCT target_file FROM imp WHERE file=?1 AND target_file IS NOT NULL
             ORDER BY target_file",
        )?;
        let targets = select
            .query_map([id], |row| row.get(0))?
            .collect::<rusqlite::Result<Vec<i64>>>()?;
        Ok(Some(CoverFile {
            id,
            path,
            flags,
            targets,
        }))
    }

    fn id_of(&self, path: &str) -> Result<Option<i64>> {
        file_id(self.tx, path)
    }
}
