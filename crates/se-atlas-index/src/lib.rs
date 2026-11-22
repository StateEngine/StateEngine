//! The Atlas v5 code index: guarded source discovery, a pure-Rust lexical
//! extractor, and a compact SQLite store with lazy delta compaction.
//!
//! Every source byte this crate reads arrives through [`custody`], which opens
//! descendants relative to retained no-follow directory handles and applies the
//! private-file [`policy`] before any open. Ignore files only decide which
//! names are skipped; they never open anything themselves.
#![forbid(unsafe_code)]

pub mod custody;
pub mod extract;
pub mod policy;
pub mod store;
pub mod walk;

use std::{fmt, io};

/// Why an index operation could not finish.
#[derive(Debug)]
pub enum IndexError {
    /// A source or database file could not be read, written or verified.
    Io(io::Error),
    /// SQLite refused a statement or reported a damaged database.
    Sqlite(rusqlite::Error),
    /// An ignore file holds a pattern the matcher cannot compile.
    IgnoreRule(String),
    /// The store holds data this version cannot interpret.
    Corrupt(&'static str),
    /// A caller passed a value outside the documented bounds.
    Invalid(&'static str),
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "atlas index I/O failed: {error}"),
            Self::Sqlite(error) => write!(f, "atlas index database failed: {error}"),
            Self::IgnoreRule(error) => write!(f, "atlas ignore rule is invalid: {error}"),
            Self::Corrupt(what) => write!(f, "atlas index data is damaged: {what}"),
            Self::Invalid(what) => write!(f, "atlas index request is invalid: {what}"),
        }
    }
}

impl std::error::Error for IndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for IndexError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for IndexError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub type Result<T> = std::result::Result<T, IndexError>;
