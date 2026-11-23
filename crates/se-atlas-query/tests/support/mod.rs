#![allow(dead_code)]
//! Shared test fixtures and SQL seed helpers for Atlas query acceptance suites.
use rusqlite::{Connection, params};
use se_atlas_index::{
    Result as IndexResult,
    custody::IndexSourceRoot,
    extract::imports::Resolver,
    store::{BuildOptions, PathOutcome, Reader, Store, StoreIdentity},
};
use std::{
    fmt::Write as _,
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

pub struct TempDir {
    path: PathBuf,
    junctions: Vec<PathBuf>,
}

impl TempDir {
    pub fn new(label: &str) -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "se-atlas-query-accept-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        Ok(Self {
            path,
            junctions: Vec::new(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, relative: &str) -> PathBuf {
        relative
            .split('/')
            .fold(self.path.clone(), |acc, part| acc.join(part))
    }

    pub fn write(&self, relative: &str, text: &str) -> io::Result<()> {
        self.write_bytes(relative, text.as_bytes())
    }

    pub fn write_bytes(&self, relative: &str, bytes: &[u8]) -> io::Result<()> {
        let full = self.join(relative);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(full, bytes)
    }

    #[cfg(windows)]
    pub fn add_junction(&mut self, relative: &str, target: &Path) -> io::Result<PathBuf> {
        let link = self.join(relative);
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)?;
        }
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(target)
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!("mklink /J failed: {stderr}")));
        }
        self.junctions.push(link.clone());
        Ok(link)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Remove junctions first so teardown never traverses external targets.
        for link in self.junctions.drain(..) {
            let _ = fs::remove_dir(&link);
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub struct TestRepo {
    pub repo: TempDir,
    pub state: TempDir,
    pub root: IndexSourceRoot,
    pub store: Store,
    pub db: PathBuf,
    pub resolver: Resolver,
}

impl TestRepo {
    pub fn build(label: &str, files: &[(&str, &str)]) -> IndexResult<Self> {
        let bytes: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(path, text)| (*path, text.as_bytes()))
            .collect();
        Self::build_bytes(label, &bytes)
    }

    pub fn build_bytes(label: &str, files: &[(&str, &[u8])]) -> IndexResult<Self> {
        let repo = TempDir::new(&format!("{label}-repo"))?;
        let state = TempDir::new(&format!("{label}-state"))?;
        for (path, bytes) in files {
            repo.write_bytes(path, bytes)?;
        }
        let root = IndexSourceRoot::open(repo.path())?;
        let db = state.join("atlas.db");
        let (mut store, _) = Store::open(&db, &StoreIdentity::default())?;
        store.cold_build(&root, &BuildOptions::default())?;
        let resolver = Resolver::new(files.iter().map(|(path, _)| *path));
        Ok(Self {
            repo,
            state,
            root,
            store,
            db,
            resolver,
        })
    }

    pub fn reader(&self) -> IndexResult<Reader> {
        Reader::open(&self.db)
    }

    pub fn edit(&mut self, path: &str, text: &str) -> IndexResult<PathOutcome> {
        self.repo.write(path, text)?;
        self.store.index_path(&self.root, &mut self.resolver, path)
    }

    pub fn remove_and_index(&mut self, path: &str) -> IndexResult<PathOutcome> {
        fs::remove_file(self.repo.join(path))?;
        self.store.index_path(&self.root, &mut self.resolver, path)
    }

    pub fn delete_sources(&self) -> io::Result<()> {
        fs::remove_dir_all(self.repo.path())
    }
}

pub fn table_count(conn: &Connection, table: &str) -> rusqlite::Result<i64> {
    let sql = format!("SELECT count(*) FROM {table}");
    conn.query_row(&sql, [], |row| row.get(0))
}

pub fn meta_generation(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT generation FROM meta WHERE singleton=1", [], |row| {
        row.get(0)
    })
}

pub fn generation_timestamp(conn: &Connection, generation: i64) -> rusqlite::Result<i64> {
    conn.query_row(
        "SELECT observed_unix_ms FROM generations WHERE generation=?1",
        [generation],
        |row| row.get(0),
    )
}

pub struct RecordSeed<'a> {
    pub record_id: &'a str,
    pub kind: &'a str,
    pub title: &'a str,
    pub occurred_unix_ms: i64,
    pub visibility: &'a str,
}

pub fn seed_record(conn: &Connection, seed: &RecordSeed<'_>) -> rusqlite::Result<i64> {
    let audience: Option<&[u8]> = if seed.visibility == "restricted" {
        Some(b"\x01")
    } else {
        None
    };
    conn.execute(
        "INSERT INTO records(record_id, kind, actor, occurred_unix_ms, title, source_event,
           body_truncated, visibility, audience)
         VALUES (?1, ?2, 'tester', ?3, ?4, ?5, 0, ?6, ?7)",
        params![
            seed.record_id,
            seed.kind,
            seed.occurred_unix_ms,
            seed.title,
            format!("evt-{}", seed.record_id),
            seed.visibility,
            audience,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

pub fn seed_mention(
    conn: &Connection,
    source_id: i64,
    target_kind: &str,
    target_key: &[u8],
    accuracy: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO mentions(source_kind, source_id, target_kind, target_key, accuracy)
         VALUES ('record', ?1, ?2, ?3, ?4)",
        params![source_id, target_kind, target_key, accuracy],
    )?;
    Ok(())
}

pub struct TouchSeed<'a> {
    pub target_kind: &'a str,
    pub target_key: &'a [u8],
    pub ordinal: i64,
    pub touch_kind: &'a str,
    pub actor: &'a str,
    pub at_unix_ms: i64,
    pub source_record: Option<i64>,
    pub restricted_record: Option<i64>,
}

pub fn seed_touch(conn: &Connection, seed: &TouchSeed<'_>) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO touches(target_kind, target_key, ordinal, touch_kind, actor, at_unix_ms,
           source_record, source_commit, restricted_record)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, ?8)",
        params![
            seed.target_kind,
            seed.target_key,
            seed.ordinal,
            seed.touch_kind,
            seed.actor,
            seed.at_unix_ms,
            seed.source_record,
            seed.restricted_record,
        ],
    )?;
    Ok(())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
