//! Code-navigation queries over the Atlas v5 index: target resolution,
//! outlines, references, impact, edit hooks, recent changes and an
//! orientation map.
//!
//! Every answer reads the store inside one [`Reader::snapshot`], so all of
//! its sections come from the same committed state. Only [`refs`] reads
//! source files, and only through [`IndexSourceRoot`] custody; [`hooks`]
//! never touches the disk at all.
//!
//! [`Reader::snapshot`]: se_atlas_index::store::Reader::snapshot
//! [`IndexSourceRoot`]: se_atlas_index::custody::IndexSourceRoot
#![forbid(unsafe_code)]

pub mod changes;
pub mod hooks;
pub mod impact;
pub mod map;
pub mod outline;
pub mod refs;
pub mod target;

pub use target::{FileRef, Resolved, SymbolRef, Target, resolve};

use se_atlas_index::{Result, store::ReadSnapshot};
use std::collections::HashSet;

/// A query's answer about its target. `Refused` (the private-file policy)
/// and `NotFound` (nothing indexed answers to the name) are distinct facts,
/// and neither is an error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer<T> {
    Found(T),
    /// The target names a path the private-file policy never indexes.
    Refused {
        path: String,
    },
    /// Nothing indexed matches; up to three close spellings.
    NotFound {
        suggestions: Vec<String>,
    },
}

impl<T> Answer<T> {
    /// Carry a non-`Found` resolution over to another answer type.
    fn unresolved(resolved: Resolved) -> std::result::Result<TargetOf, Self> {
        match resolved {
            Resolved::File(file) => Ok(TargetOf::File(file)),
            Resolved::Symbols { symbols, capped } => Ok(TargetOf::Symbols { symbols, capped }),
            Resolved::Refused { path } => Err(Self::Refused { path }),
            Resolved::NotFound { suggestions } => Err(Self::NotFound { suggestions }),
        }
    }
}

/// A resolved target: a file, or every definition sharing a name.
#[derive(Clone, Debug)]
pub(crate) enum TargetOf {
    File(FileRef),
    Symbols {
        symbols: Vec<SymbolRef>,
        capped: bool,
    },
}

impl TargetOf {
    /// The files that define the target, in resolution order, deduplicated.
    pub fn files(&self) -> Vec<&FileRef> {
        match self {
            Self::File(file) => vec![file],
            Self::Symbols { symbols, .. } => {
                let mut seen = HashSet::new();
                symbols
                    .iter()
                    .map(|symbol| &symbol.file)
                    .filter(|file| seen.insert(file.id))
                    .collect()
            }
        }
    }

    pub fn symbols(&self) -> &[SymbolRef] {
        match self {
            Self::File(_) => &[],
            Self::Symbols { symbols, .. } => symbols,
        }
    }

    /// The name has more definitions than were resolved.
    pub fn capped(&self) -> bool {
        matches!(self, Self::Symbols { capped: true, .. })
    }
}

/// Up to a cap of items, and how many more matched past it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section<T> {
    pub items: Vec<T>,
    pub more: usize,
    /// A bound stopped the count, so `more` is a floor, not a total.
    pub more_is_floor: bool,
}

impl<T> Default for Section<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            more: 0,
            more_is_floor: false,
        }
    }
}

impl<T> Section<T> {
    fn capped(mut items: Vec<T>, cap: usize) -> Self {
        let more = items.len().saturating_sub(cap);
        items.truncate(cap);
        Self {
            items,
            more,
            more_is_floor: false,
        }
    }
}

/// A page size: zero picks the default, anything else is capped.
pub(crate) fn page_limit(limit: usize, default: usize, max: usize) -> usize {
    match limit {
        0 => default,
        n => n.min(max),
    }
}

/// Files holding the target's name token, from the index alone. Empty when
/// the target is a file or its name was never indexed.
pub(crate) fn name_postings(
    snapshot: &ReadSnapshot<'_>,
    target: &TargetOf,
) -> Result<HashSet<i64>> {
    let Some(symbol) = target.symbols().first() else {
        return Ok(HashSet::new());
    };
    let Some(token) = snapshot.token_id(&symbol.name.to_lowercase())? else {
        return Ok(HashSet::new());
    };
    Ok(snapshot
        .read_postings(token)?
        .into_iter()
        .map(|(file, _)| file)
        .collect())
}

/// Files whose resolved imports name `target`, through `imp_target`.
pub(crate) fn importers(snapshot: &ReadSnapshot<'_>, target: i64) -> Result<Vec<i64>> {
    let mut select = snapshot
        .connection()
        .prepare_cached("SELECT DISTINCT file FROM imp WHERE target_file=?1 ORDER BY file")?;
    let rows = select.query_map([target], |row| row.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// The directory part of a root-relative path, empty at the root.
pub(crate) fn dir_of(path: &str) -> &str {
    path.rfind('/').map_or("", |at| &path[..at])
}

/// A throwaway repository and store for this module's unit tests.
#[cfg(test)]
pub(crate) mod fixture {
    use se_atlas_index::{
        custody::IndexSourceRoot,
        extract::imports::Resolver,
        store::{BuildOptions, Reader, Store, StoreIdentity},
    };
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU32, Ordering},
    };

    pub type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    pub struct Repo {
        dir: PathBuf,
        pub root: IndexSourceRoot,
        pub store: Store,
        db: PathBuf,
        resolver: Resolver,
    }

    impl Repo {
        pub fn build(files: &[(&str, &str)]) -> se_atlas_index::Result<Self> {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "se-atlas-query-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("repo"))?;
            for (path, text) in files {
                write(&dir.join("repo"), path, text)?;
            }
            let root = IndexSourceRoot::open(&dir.join("repo"))?;
            let db = dir.join("atlas.db");
            let (mut store, _) = Store::open(&db, &StoreIdentity::default())?;
            store.cold_build(&root, &BuildOptions::default())?;
            let resolver = Resolver::new(files.iter().map(|(path, _)| *path));
            Ok(Self {
                dir,
                root,
                store,
                db,
                resolver,
            })
        }

        pub fn reader(&self) -> se_atlas_index::Result<Reader> {
            Reader::open(&self.db)
        }

        /// Write a file and index it as the watcher would.
        pub fn edit(&mut self, path: &str, text: &str) -> se_atlas_index::Result<()> {
            write(&self.dir.join("repo"), path, text)?;
            self.store
                .index_path(&self.root, &mut self.resolver, path)?;
            Ok(())
        }

        /// Delete every source file, keeping the store.
        pub fn delete_sources(&self) -> std::io::Result<()> {
            fs::remove_dir_all(self.dir.join("repo"))
        }
    }

    fn write(root: &Path, path: &str, text: &str) -> std::io::Result<()> {
        let path = root.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, text)
    }

    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}
