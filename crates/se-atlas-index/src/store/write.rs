//! Row writers shared by the cold builder and incremental updates.
use crate::{
    Result,
    custody::SourceFile,
    extract::{Extracted, Symbol, covers::Cover, file_key},
};
use rusqlite::{OptionalExtension, Transaction, params};

/// One extracted file with its resolved import targets, ready to write.
pub(crate) struct FileRecord {
    pub path: String,
    pub size: u64,
    pub mtime_ns: i64,
    pub ident: [u8; 32],
    pub extracted: Extracted,
    /// Target file id per entry of `extracted.imports`.
    pub targets: Vec<Option<i64>>,
}

impl FileRecord {
    pub fn new(path: &str, source: &SourceFile, extracted: Extracted) -> Self {
        Self {
            path: path.to_owned(),
            size: source.size,
            mtime_ns: source.mtime_ns,
            ident: source.ident,
            targets: vec![None; extracted.imports.len()],
            extracted,
        }
    }
}

/// Insert or refresh a `files` row and return its id. `id` pins the id of a
/// new row (cold builds number files by sorted path).
pub(crate) fn upsert_file(
    tx: &Transaction<'_>,
    id: Option<i64>,
    record: &FileRecord,
) -> Result<i64> {
    let size = i64::try_from(record.size).unwrap_or(i64::MAX);
    let id = tx
        .prepare_cached(
            "INSERT INTO files(id, key, path, lang, size, mtime_ns, ident, hash, flags)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(path) DO UPDATE SET lang=excluded.lang, size=excluded.size,
               mtime_ns=excluded.mtime_ns, ident=excluded.ident, hash=excluded.hash,
               flags=excluded.flags
             RETURNING id",
        )?
        .query_row(
            params![
                id,
                file_key(&record.path).as_slice(),
                record.path,
                record.extracted.lang.as_str(),
                size,
                record.mtime_ns,
                record.ident.as_slice(),
                record.extracted.hash.as_slice(),
                record.extracted.flags,
            ],
            |row| row.get(0),
        )?;
    Ok(id)
}

/// Insert every symbol of a new file. `name_id` maps a lowercase name to its
/// vocab id. Parents precede children, so parent ids are already known.
pub(crate) fn insert_symbols(
    tx: &Transaction<'_>,
    file: i64,
    record: &FileRecord,
    mut name_id: impl FnMut(&str) -> Result<i64>,
) -> Result<()> {
    let mut ids: Vec<i64> = Vec::with_capacity(record.extracted.symbols.len());
    let mut insert = tx.prepare_cached(INSERT_SYMBOL)?;
    let accuracy = record.extracted.accuracy as i64;
    for symbol in &record.extracted.symbols {
        let parent = symbol.parent.and_then(|index| ids.get(index).copied());
        let name = name_id(&symbol.name.to_lowercase())?;
        insert_symbol(&mut insert, symbol, file, parent, name, accuracy)?;
        ids.push(tx.last_insert_rowid());
    }
    Ok(())
}

pub(crate) const INSERT_SYMBOL: &str = "INSERT INTO sym(key, file, parent, name, kind, line,
    end_line, accuracy, exported, sig, sig_hash, body_hash)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";

pub(crate) fn insert_symbol(
    insert: &mut rusqlite::Statement<'_>,
    symbol: &Symbol,
    file: i64,
    parent: Option<i64>,
    name: i64,
    accuracy: i64,
) -> Result<()> {
    insert.execute(params![
        symbol.key.as_slice(),
        file,
        parent,
        name,
        symbol.kind.code(),
        symbol.line,
        symbol.end_line,
        accuracy,
        symbol.exported,
        symbol.sig,
        symbol.sig_hash,
        symbol.body_hash,
    ])?;
    Ok(())
}

/// Replace a file's import rows.
pub(crate) fn replace_imports(tx: &Transaction<'_>, file: i64, record: &FileRecord) -> Result<()> {
    tx.prepare_cached("DELETE FROM imp WHERE file=?1")?
        .execute([file])?;
    let mut insert = tx.prepare_cached(
        "INSERT OR REPLACE INTO imp(file, spelling, target_file, kind, reexport)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for (spec, target) in record.extracted.imports.iter().zip(&record.targets) {
        insert.execute(params![
            file,
            spec.spelling,
            target,
            spec.kind as i64,
            spec.reexport
        ])?;
    }
    Ok(())
}

pub(crate) fn insert_covers(tx: &Transaction<'_>, covers: &[Cover]) -> Result<()> {
    let mut insert = tx.prepare_cached(
        "INSERT OR REPLACE INTO covers(test_file, target_file, how, via_helper)
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    for cover in covers {
        insert.execute(params![
            cover.test_file,
            cover.target_file,
            cover.how as i64,
            cover.via_helper
        ])?;
    }
    Ok(())
}

/// The vocab id of a token, inserting it with `df = 0` when new. New tokens
/// also enter `short` (one or two characters) or `gram_delta` (identifiers).
pub(crate) fn intern_token(tx: &Transaction<'_>, token: &str, grams: bool) -> Result<(i64, bool)> {
    let existing = tx
        .prepare_cached("SELECT id FROM vocab WHERE tok=?1")?
        .query_row([token], |row| row.get(0))
        .optional()?;
    if let Some(id) = existing {
        return Ok((id, false));
    }
    tx.prepare_cached("INSERT INTO vocab(tok, compact, df) VALUES (?1, ?2, 0)")?
        .execute(params![token, crate::extract::tokens::compact(token)])?;
    let id = tx.last_insert_rowid();
    index_new_token(tx, id, token, grams)?;
    Ok((id, true))
}

/// Side tables for a token that just entered vocab with a known id.
pub(crate) fn index_new_token(
    tx: &Transaction<'_>,
    id: i64,
    token: &str,
    grams: bool,
) -> Result<()> {
    use crate::extract::tokens;
    if token.len() <= tokens::MAX_SHORT_TOKEN {
        tx.prepare_cached("INSERT OR IGNORE INTO short(tok, vocab_id) VALUES (?1, ?2)")?
            .execute(params![token, id])?;
    } else if grams && tokens::is_gram_token(token) {
        let mut insert =
            tx.prepare_cached("INSERT OR IGNORE INTO gram_delta(g, tok) VALUES (?1, ?2)")?;
        for gram in tokens::trigrams(token) {
            insert.execute(params![gram, id])?;
        }
    }
    Ok(())
}

pub(crate) fn set_state(tx: &Transaction<'_>, state: &serde_json::Value) -> Result<()> {
    tx.execute(
        "UPDATE meta SET state_json=?1 WHERE singleton=1",
        [state.to_string()],
    )?;
    Ok(())
}
