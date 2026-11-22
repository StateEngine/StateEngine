//! The compact v5 store: one writer, any number of read-only connections.
//!
//! Opening refuses nothing it can repair: a missing store, another schema
//! version or owner, or SQLite corruption starts a new empty epoch database
//! that the store pointer then names (see [`files`]); an older extractor
//! keeps the file and its history and clears only the code index. Either way
//! the caller runs a cold build. Other failures (permissions, a refused link,
//! a locked file) are reported, never "repaired".
mod cold;
mod compact;
mod files;
mod incremental;
pub mod read;
mod schema;
pub mod varint;
mod write;

pub use cold::{BuildOptions, BuildReport};
pub use compact::{CompactPolicy, CompactReport};
pub use incremental::{PathOutcome, SymbolDiff, UpdateReport};
pub use read::{ReadSnapshot, Reader};
pub use schema::{SCHEMA_VERSION, StoreIdentity};

use crate::{IndexError, Result, extract::EXTRACTOR_VERSION};
use files::{Pointer, StoreFiles};
use rusqlite::{Connection, ErrorCode, OpenFlags};
use schema::Verdict;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Why `open` left the caller an empty code index to cold-build. Only
/// `Mismatch("extractor version differs")` keeps the file and its history.
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
    /// Open the store named by `path`, starting an empty epoch when it is
    /// missing, of another version or owner, or damaged.
    pub fn open(path: &Path, identity: &StoreIdentity) -> Result<(Self, Option<RebuildReason>)> {
        let files = StoreFiles::new(path)?;
        // Epoch 0 is never published: a rebuild verdict replaces it.
        let (epoch, verdict) = match files.pointer()? {
            Pointer::Epoch(epoch) => (epoch, usable(&files.epoch_path(epoch), identity)?),
            Pointer::Missing => (0, Verdict::Rebuild(RebuildReason::Missing)),
            Pointer::Damaged => (0, Verdict::Rebuild(RebuildReason::Corrupt)),
        };
        let (epoch, reason) = match verdict {
            Verdict::Usable => (epoch, None),
            Verdict::ExtractorChanged => (
                epoch,
                Some(RebuildReason::Mismatch("extractor version differs")),
            ),
            Verdict::Rebuild(reason) => (rebuild(&files, identity)?, Some(reason)),
        };
        let path = files.epoch_path(epoch);
        let mut conn = open_connection(&path, true)?;
        schema::configure_writer(&conn)?;
        if verdict == Verdict::ExtractorChanged {
            let tx = conn.transaction()?;
            write::clear_index(&tx)?;
            tx.execute(
                "UPDATE meta SET extractor_version=?1 WHERE singleton=1",
                [EXTRACTOR_VERSION],
            )?;
            tx.commit()?;
        }
        if schema::verdict(&conn, identity)? != Verdict::Usable {
            return Err(IndexError::Corrupt("opened store failed its own check"));
        }
        // Epochs a draining reader held at the last rebuild go now.
        files.reap(epoch);
        Ok((Self { conn, path }, reason))
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// The epoch database this writer holds.
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn connection_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

/// Judge an existing epoch file without changing it.
fn usable(path: &Path, identity: &StoreIdentity) -> Result<Verdict> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Verdict::Rebuild(RebuildReason::Missing));
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let checked = open_connection(path, false).and_then(|conn| schema::verdict(&conn, identity));
    match checked {
        Err(error) if is_corrupt(&error) => Ok(Verdict::Rebuild(RebuildReason::Corrupt)),
        other => other,
    }
}

fn is_corrupt(error: &IndexError) -> bool {
    matches!(
        error,
        IndexError::Sqlite(rusqlite::Error::SqliteFailure(failure, _))
            if matches!(failure.code, ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase)
    )
}

/// Open a database through the shared seam. Unix resolves owned symlinked
/// ancestors and never follows the final name; Windows hands SQLite a
/// verbatim path after the link and reparse-point checks NOFOLLOW cannot
/// make there. Sidecars are checked on both.
pub(crate) fn open_connection(path: &Path, writable: bool) -> Result<Connection> {
    files::check_leaves(path)?;
    let access = if writable {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    #[cfg(windows)]
    let (target, symlink_guard) = (se_proc::sqlite_path(path), OpenFlags::empty());
    #[cfg(not(windows))]
    let (target, symlink_guard) = (
        se_trusted_path::resolve(path)?,
        OpenFlags::SQLITE_OPEN_NOFOLLOW,
    );
    let flags =
        access | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_EXRESCODE | symlink_guard;
    Ok(Connection::open_with_flags(&target, flags)?)
}

/// Build an empty store in a fresh epoch file and point readers at it; the
/// writer's open reaps superseded epochs. Readers still on an old epoch keep
/// a consistent, if stale, view until they reopen; nothing they hold is
/// replaced.
fn rebuild(files: &StoreFiles, identity: &StoreIdentity) -> Result<u64> {
    let epoch = files.next_epoch()?;
    let path = files.epoch_path(epoch);
    files::check_leaves(&path)?;
    let [wal, shm] = files::sidecars(&path);
    files::remove_files([path.clone(), wal, shm])?;
    {
        let conn = open_connection(&path, true)?;
        schema::create(&conn, identity)?;
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        conn.close().map_err(|(_, error)| error)?;
    }
    files.publish(epoch)?;
    Ok(epoch)
}

/// Resolve the store's current epoch database for a reader.
pub(crate) fn current_database(path: &Path) -> Result<(StoreFiles, u64)> {
    let files = StoreFiles::new(path)?;
    match files.pointer()? {
        Pointer::Epoch(epoch) => Ok((files, epoch)),
        Pointer::Missing => Err(IndexError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "no atlas store has been published here; open it with a writer first",
        ))),
        Pointer::Damaged => Err(IndexError::Corrupt("store pointer is damaged")),
    }
}

/// Whether the pointer still names `epoch`.
pub(crate) fn still_current(files: &StoreFiles, epoch: u64) -> Result<bool> {
    Ok(files.pointer()? == Pointer::Epoch(epoch))
}
