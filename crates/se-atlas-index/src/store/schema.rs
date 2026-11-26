//! The v6 schema, its version stamp, and connection settings.
use super::RebuildReason;
use crate::{Result, extract::EXTRACTOR_VERSION};
use rusqlite::{Connection, OptionalExtension, params};

/// Stored in `PRAGMA user_version`; any other value rebuilds the store.
pub const SCHEMA_VERSION: i64 = 6;
const DDL: &str = include_str!("schema.sql");

/// Who the store belongs to, written once into `meta`. Reopening with a
/// different identity rebuilds the store.
#[derive(Clone, Debug, Default)]
pub struct StoreIdentity {
    pub project: String,
    /// The root as the user named it.
    pub root: String,
    /// The physical root the source custody pinned.
    pub physical_root: String,
}

pub(crate) fn create(conn: &Connection, identity: &StoreIdentity) -> Result<()> {
    // 2 KiB pages halve the WAL bytes of a single-file save (it touches a
    // handful of scattered index leaves) for a few percent more file size.
    conn.pragma_update(None, "page_size", 2048)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(DDL)?;
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });
    conn.execute(
        "INSERT INTO meta(singleton, project, root, physical_root, epoch, extractor_version)
         VALUES (1, ?1, ?2, ?3, ?4, ?5)",
        params![
            identity.project,
            identity.root,
            identity.physical_root,
            epoch,
            EXTRACTOR_VERSION
        ],
    )?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

/// Writer settings: WAL with normal sync and normal locking, never exclusive
/// locking and never sync off, so readers see every committed batch.
pub(crate) fn configure_writer(conn: &Connection) -> Result<()> {
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(crate::IndexError::Invalid("SQLite refused WAL journaling"));
    }
    conn.execute_batch(
        "PRAGMA synchronous=NORMAL;
         PRAGMA locking_mode=NORMAL;
         PRAGMA foreign_keys=ON;
         PRAGMA trusted_schema=OFF;
         PRAGMA temp_store=MEMORY;
         PRAGMA cache_size=-8192;
         PRAGMA journal_size_limit=8388608;",
    )?;
    conn.busy_timeout(std::time::Duration::from_millis(1000))?;
    Ok(())
}

/// Reader settings: query-only with a small page cache and a bounded map.
pub(crate) fn configure_reader(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA query_only=ON;
         PRAGMA trusted_schema=OFF;
         PRAGMA cache_size=-2048;
         PRAGMA mmap_size=67108864;",
    )?;
    conn.busy_timeout(std::time::Duration::from_millis(250))?;
    Ok(())
}

/// Whether an existing file can serve as this version's store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Usable,
    /// Same schema, older extractor: keep history, clear the code index.
    ExtractorChanged,
    Rebuild(RebuildReason),
}

/// Judge an open store against this schema and the expected owner.
pub(crate) fn verdict(conn: &Connection, identity: &StoreIdentity) -> Result<Verdict> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != SCHEMA_VERSION {
        return Ok(Verdict::Rebuild(RebuildReason::Mismatch(
            "schema version differs",
        )));
    }
    let has_meta: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='meta')",
        [],
        |row| row.get(0),
    )?;
    if !has_meta {
        return Ok(Verdict::Rebuild(RebuildReason::Corrupt));
    }
    let meta = conn
        .query_row(
            "SELECT project, root, physical_root, extractor_version FROM meta WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((project, root, physical_root, extractor)) = meta else {
        return Ok(Verdict::Rebuild(RebuildReason::Corrupt));
    };
    if project != identity.project
        || root != identity.root
        || physical_root != identity.physical_root
    {
        return Ok(Verdict::Rebuild(RebuildReason::Mismatch(
            "store identity differs",
        )));
    }
    let check: String = conn.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if check != "ok" {
        return Ok(Verdict::Rebuild(RebuildReason::Corrupt));
    }
    Ok(if extractor == EXTRACTOR_VERSION {
        Verdict::Usable
    } else {
        Verdict::ExtractorChanged
    })
}
