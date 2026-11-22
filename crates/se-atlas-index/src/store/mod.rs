//! The compact v5 store: one writer, any number of read-only connections.
//!
//! Opening refuses nothing it can repair: a missing file, another schema or
//! extractor version, or SQLite corruption is rebuilt empty in a sibling file
//! and swapped in by rename, after which the caller runs a cold build. Other
//! failures (permissions, a locked file) are reported, never "repaired".
mod cold;
mod compact;
mod incremental;
pub mod read;
mod schema;
pub mod varint;
mod write;

pub use cold::{BuildOptions, BuildReport};
pub use compact::{CompactPolicy, CompactReport};
pub use incremental::{PathOutcome, SymbolDiff, UpdateReport};
pub use read::Reader;
pub use schema::{SCHEMA_VERSION, StoreIdentity};

use crate::{IndexError, Result};
use rusqlite::{Connection, ErrorCode, OpenFlags};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Why `open` started from an empty store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RebuildReason {
    Missing,
    Mismatch(&'static str),
    Corrupt,
}

/// The single writer of one store.
pub struct Store {
    conn: Connection,
    path: PathBuf,
}

impl Store {
    /// Open the store at `path`, rebuilding it empty when it is missing, of
    /// another version, or damaged.
    pub fn open(path: &Path, identity: &StoreIdentity) -> Result<(Self, Option<RebuildReason>)> {
        let reason = match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Some(RebuildReason::Missing),
            Err(error) => return Err(error.into()),
            Ok(_) => usable(path)?,
        };
        if reason.is_some() {
            rebuild(path, identity)?;
        }
        let conn = open_connection(path, true)?;
        schema::configure_writer(&conn)?;
        if schema::mismatch(&conn)?.is_some() {
            return Err(IndexError::Corrupt("rebuilt store failed its own check"));
        }
        Ok((
            Self {
                conn,
                path: path.to_path_buf(),
            },
            reason,
        ))
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

/// `None` when the existing file is a usable store of this version.
fn usable(path: &Path) -> Result<Option<RebuildReason>> {
    let checked = open_connection(path, false).and_then(|conn| schema::mismatch(&conn));
    match checked {
        Ok(None) => Ok(None),
        Ok(Some("quick_check failed")) => Ok(Some(RebuildReason::Corrupt)),
        Ok(Some(why)) => Ok(Some(RebuildReason::Mismatch(why))),
        Err(error) if is_corrupt(&error) => Ok(Some(RebuildReason::Corrupt)),
        Err(error) => Err(error),
    }
}

fn is_corrupt(error: &IndexError) -> bool {
    matches!(
        error,
        IndexError::Sqlite(rusqlite::Error::SqliteFailure(failure, _))
            if matches!(failure.code, ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase)
    )
}

/// Open a database through the shared seam: verbatim paths on Windows, owned
/// symlinked ancestors resolved on Unix, and the final name never followed.
pub(crate) fn open_connection(path: &Path, writable: bool) -> Result<Connection> {
    let target = se_proc::sqlite_path(path);
    let verbatim = target != path;
    let target = se_trusted_path::resolve(&target)?;
    let access = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let symlink_guard = if verbatim {
        OpenFlags::empty()
    } else {
        OpenFlags::SQLITE_OPEN_NOFOLLOW
    };
    let flags =
        access | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_EXRESCODE | symlink_guard;
    Ok(Connection::open_with_flags(&target, flags)?)
}

/// The sibling a rebuild is written to before it replaces `path`.
fn rebuild_path(path: &Path) -> PathBuf {
    let stem = path.file_stem().map_or_else(
        || "atlas".into(),
        |stem| stem.to_string_lossy().into_owned(),
    );
    let sibling = path.with_file_name(format!("{stem}.v5.db"));
    if sibling == path {
        path.with_file_name(format!("{stem}.rebuild.db"))
    } else {
        sibling
    }
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn remove_files(paths: impl IntoIterator<Item = PathBuf>) -> io::Result<()> {
    for file in paths {
        match fs::remove_file(&file) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    Ok(())
}

fn sidecars(path: &Path) -> [PathBuf; 2] {
    [sidecar(path, "-wal"), sidecar(path, "-shm")]
}

/// Build an empty store beside `path` and rename it over `path`. The caller
/// is the store's only writer and holds no connection to `path`. The old
/// WAL and shared-memory files go first, so SQLite can never replay a stale
/// log into the new database.
fn rebuild(path: &Path, identity: &StoreIdentity) -> Result<()> {
    let sibling = rebuild_path(path);
    remove_files([sibling.clone()].into_iter().chain(sidecars(&sibling)))?;
    {
        let conn = open_connection(&sibling, true)?;
        schema::create(&conn, identity)?;
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        conn.close().map_err(|(_, error)| error)?;
    }
    remove_files(sidecars(&sibling))?;
    remove_files(sidecars(path))?;
    fs::rename(&sibling, path)?;
    Ok(())
}
