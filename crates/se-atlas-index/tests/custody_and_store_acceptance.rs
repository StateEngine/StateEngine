//! Reviewer acceptance tests for custody boundaries, link/junction refusal,
//! store concurrency and recovery, delta compaction invariants, and extractor
//! edge cases.
use rusqlite::Connection;
use se_atlas_index::{
    IndexError,
    custody::{GuardedOpen, GuardedRead, IndexSourceRoot},
    extract::{EXTRACTOR_VERSION, Extracted, SymbolKind, extract, imports::Resolver},
    store::{
        BuildOptions, CompactPolicy, PathOutcome, Reader, RebuildReason, Store, StoreIdentity,
    },
    walk::{self, Discovery, WalkOptions},
};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
type PostingsByPath = BTreeMap<String, Vec<(String, u32)>>;

struct TempDir {
    path: PathBuf,
    junctions: Vec<PathBuf>,
}

impl TempDir {
    fn new(label: &str) -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "se-atlas-accept-{label}-{}-{}",
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

    fn path(&self) -> &Path {
        &self.path
    }

    fn join(&self, relative: &str) -> PathBuf {
        relative
            .split('/')
            .fold(self.path.clone(), |acc, part| acc.join(part))
    }

    fn write(&self, relative: &str, text: &str) -> io::Result<()> {
        let full = self.join(relative);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(full, text)
    }

    #[cfg(windows)]
    fn add_junction(&mut self, relative: &str, target: &Path) -> io::Result<PathBuf> {
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
        // Remove junctions first so teardown never traverses into targets.
        for link in self.junctions.drain(..) {
            let _ = fs::remove_dir(&link);
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn postings(reader: &Reader, token: &str) -> Result<Vec<(i64, u32)>, IndexError> {
    match reader.token_id(token)? {
        Some(id) => reader.read_postings(id),
        None => Ok(Vec::new()),
    }
}

fn table_rows(conn: &Connection, table: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let sql = format!("SELECT count(*) FROM {table}");
    Ok(conn.query_row(&sql, [], |row| row.get(0))?)
}

fn file_rows(conn: &Connection, path: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let sql = "SELECT count(*) FROM files WHERE path=?1";
    Ok(conn.query_row(sql, [path], |r| r.get(0))?)
}

fn outline(extracted: &Extracted) -> Vec<(SymbolKind, &str, Option<&str>)> {
    extracted
        .symbols
        .iter()
        .map(|s| {
            let parent = s
                .parent
                .and_then(|i| extracted.symbols.get(i))
                .map(|p| p.name.as_str());
            (s.kind, s.name.as_str(), parent)
        })
        .collect()
}

fn wal_path(db: &Path) -> PathBuf {
    let mut name = db.as_os_str().to_owned();
    name.push("-wal");
    PathBuf::from(name)
}

fn logical_postings_by_path(reader: &Reader) -> Result<PostingsByPath, Box<dyn std::error::Error>> {
    let snap = reader.snapshot()?;
    let conn = snap.connection();
    let mut paths = BTreeMap::new();
    let mut fstmt = conn.prepare("SELECT id, path FROM files")?;
    for row in fstmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))? {
        let (id, path) = row?;
        paths.insert(id, path);
    }
    let mut vstmt = conn.prepare("SELECT id, tok, df FROM vocab ORDER BY tok")?;
    let mut out = BTreeMap::new();
    for row in vstmt.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })? {
        let (tok_id, tok, df) = row?;
        let pairs = snap.read_postings(tok_id)?;
        assert_eq!(pairs.len() as i64, df, "vocab.df mismatch for {tok}");
        if pairs.is_empty() {
            continue;
        }
        let mut by_path: Vec<(String, u32)> = pairs
            .into_iter()
            .map(|(fid, tf)| {
                let p = paths
                    .get(&fid)
                    .cloned()
                    .ok_or_else(|| format!("missing file row {fid}"))?;
                Ok::<_, String>((p, tf))
            })
            .collect::<Result<_, _>>()?;
        by_path.sort();
        out.insert(tok, by_path);
    }
    Ok(out)
}

const DENIED_CREDS: [(&str, &str); 12] = [
    ("id_ecdsa_sk", "deniedtok01\n"),
    ("id_ed25519_sk", "deniedtok02\n"),
    ("cert.ppk", "deniedtok03\n"),
    ("auth.p8", "deniedtok04\n"),
    (".docker/config.json", "{\"tok\":\"deniedtok05\"}\n"),
    ("secrets.yaml", "val: deniedtok06\n"),
    ("service-account-prod.json", "{\"k\":\"deniedtok07\"}\n"),
    ("credentials", "deniedtok08\n"),
    ("credentials.env", "KEY=deniedtok09\n"),
    (".pem", "deniedtok10\n"),
    (".key", "deniedtok11\n"),
    ("deploy/secrets/db.yaml", "pw: deniedtok12\n"),
];

const ALLOWED_SOURCES: [(&str, &str, &str); 6] = [
    (
        "windows_journeys/credentials.py",
        "def allowedtok01():\n    return 1\n",
        "allowedtok01",
    ),
    (
        "src/id_map.rs",
        "pub fn allowedtok02() {}\n",
        "allowedtok02",
    ),
    (
        "src/secret_store/mod.rs",
        "pub fn allowedtok03() {}\n",
        "allowedtok03",
    ),
    (
        "src/secrets/provider.rs",
        "pub fn allowedtok04() {}\n",
        "allowedtok04",
    ),
    (
        "config.ts",
        "export const allowedtok05 = 1;\n",
        "allowedtok05",
    ),
    ("settings.py", "ALLOWEDTOK06 = 1\n", "allowedtok06"),
];

fn assert_custody_paths(root: &IndexSourceRoot, discovery: &Discovery) -> TestResult {
    assert!(discovery.complete && discovery.denied >= DENIED_CREDS.len() as u32);
    let mut scan = root.begin_reads()?;
    for (path, _) in DENIED_CREDS {
        assert!(!discovery.files.iter().any(|f| f == path), "{path}");
        assert!(matches!(root.read_guarded_file(path)?, GuardedRead::Denied));
        assert!(matches!(root.open_guarded_file(path)?, GuardedOpen::Denied));
        assert!(matches!(scan.read(path)?, GuardedRead::Denied));
    }
    for (path, _, _) in ALLOWED_SOURCES {
        assert!(discovery.files.iter().any(|f| f == path), "{path}");
        let r = root.read_guarded_file(path)?;
        let o = root.open_guarded_file(path)?;
        assert!(matches!(r, GuardedRead::Source(_)) && matches!(o, GuardedOpen::File(_)));
        assert!(matches!(scan.read(path)?, GuardedRead::Source(_)));
    }
    scan.finish()?;
    Ok(())
}

#[test]
fn credential_counterexamples_across_all_read_paths() -> TestResult {
    let repo = TempDir::new("creds-repo")?;
    // Ignore-file negation must never override the private-file policy.
    repo.write(
        ".gitignore",
        "!secrets.yaml\n!credentials\n!.pem\n!deploy/secrets/db.yaml\n",
    )?;
    for (path, body) in DENIED_CREDS {
        repo.write(path, body)?;
    }
    for (path, body, _) in ALLOWED_SOURCES {
        repo.write(path, body)?;
    }

    let root = IndexSourceRoot::open(repo.path())?;
    let discovery = walk::discover(&root, &WalkOptions::default())?;
    assert_custody_paths(&root, &discovery)?;

    let state = TempDir::new("creds-state")?;
    let db = state.join("atlas.db");
    let (mut store, _) = Store::open(&db, &StoreIdentity::default())?;
    assert!(
        store
            .cold_build(&root, &BuildOptions::default())?
            .discovery_complete
    );

    let mut resolver = Resolver::new(discovery.files.iter().map(String::as_str));
    for (path, _) in DENIED_CREDS {
        let out = store.index_path(&root, &mut resolver, path)?;
        assert!(matches!(out, PathOutcome::Denied { removed: false }));
        assert_eq!(file_rows(store.connection(), path)?, 0, "{path}");
    }

    let reader = Reader::open(&db)?;
    for idx in 1..=DENIED_CREDS.len() {
        let marker = format!("deniedtok{idx:02}");
        assert!(postings(&reader, &marker)?.is_empty(), "leaked: {marker}");
    }
    for (path, _, marker) in ALLOWED_SOURCES {
        assert_eq!(postings(&reader, marker)?.len(), 1, "missing: {path}");
        let out = store.index_path(&root, &mut resolver, path)?;
        assert!(matches!(out, PathOutcome::Indexed(_)));
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_short_name_aliases_are_refused() -> TestResult {
    let repo = TempDir::new("short-names")?;
    repo.write("secrets.yaml", "secret: hiddenvalue\n")?;
    repo.write("notes~backup.txt", "normaltildetoken\n")?;

    let root = IndexSourceRoot::open(repo.path())?;
    let state = TempDir::new("short-state")?;
    let (mut store, _) = Store::open(&state.join("atlas.db"), &StoreIdentity::default())?;
    let mut resolver = Resolver::default();

    for alias in ["SECRE~1.YAM", ".SSH~1/ID_RSA~1", "dir/SUB~12/FILE~1.RS"] {
        let r = root.read_guarded_file(alias)?;
        let o = root.open_guarded_file(alias)?;
        assert!(matches!(r, GuardedRead::Refused) && matches!(o, GuardedOpen::Refused));
        let mut scan = root.begin_reads()?;
        assert!(matches!(scan.read(alias)?, GuardedRead::Refused));
        scan.finish()?;
        let out = store.index_path(&root, &mut resolver, alias)?;
        assert!(matches!(out, PathOutcome::Refused { removed: false }));
    }
    assert!(matches!(
        root.read_guarded_file("notes~backup.txt")?,
        GuardedRead::Source(_)
    ));
    Ok(())
}

fn assert_leaf_link_replacement(
    repo: &mut TempDir,
    root: &IndexSourceRoot,
    discovery: &Discovery,
    outside_token: &str,
    replace_leaf: impl FnOnce(&mut TempDir) -> io::Result<()>,
) -> Result<TempDir, Box<dyn std::error::Error>> {
    let state = TempDir::new("leaf-link-state")?;
    let db = state.join("atlas.db");
    let (mut store, _) = Store::open(&db, &StoreIdentity::default())?;
    store.cold_build(root, &BuildOptions::default())?;

    let reader = Reader::open(&db)?;
    assert_eq!(postings(&reader, "stalefootoken")?.len(), 1);
    assert!(postings(&reader, outside_token)?.is_empty());

    fs::remove_file(repo.join("src/foo.rs"))?;
    replace_leaf(repo)?;
    assert!(matches!(
        root.read_guarded_file("src/foo.rs")?,
        GuardedRead::Refused
    ));
    let mut resolver = Resolver::new(discovery.files.iter().map(String::as_str));
    let outcome = store.index_path(root, &mut resolver, "src/foo.rs")?;
    assert!(matches!(outcome, PathOutcome::Refused { removed: true }));

    assert_eq!(file_rows(store.connection(), "src/foo.rs")?, 0);
    assert!(postings(&reader, "stalefootoken")?.is_empty());
    assert!(postings(&reader, outside_token)?.is_empty());
    let after = walk::discover(root, &WalkOptions::default())?;
    assert!(after.complete && !after.files.iter().any(|p| p == "src/foo.rs"));
    Ok(state)
}

#[cfg(windows)]
#[test]
fn windows_junction_escape_and_leaf_replacement_custody() -> TestResult {
    let outside = TempDir::new("outside-win")?;
    outside.write("leaked.rs", "pub fn outsidejunctiontoken() {}\n")?;

    let mut repo = TempDir::new("repo-win")?;
    repo.write("src/safe.rs", "pub fn safeinsidetoken() {}\n")?;
    repo.write("src/foo.rs", "pub fn stalefootoken() {}\n")?;
    repo.write("sub/keep.rs", "pub fn subkeeptoken() {}\n")?;
    repo.add_junction("escaped_dir", outside.path())?;
    repo.add_junction("sub/.gitignore", outside.path())?;

    let root = IndexSourceRoot::open(repo.path())?;
    let discovery = walk::discover(&root, &WalkOptions::default())?;
    assert!(discovery.complete && discovery.links >= 2 && discovery.unreadable_ignore_files >= 1);
    assert!(!discovery.files.iter().any(|p| p.starts_with("escaped_dir")));
    for path in ["escaped_dir/leaked.rs", "escaped_dir", "sub/.gitignore"] {
        let r = root.read_guarded_file(path)?;
        let o = root.open_guarded_file(path)?;
        assert!(matches!(r, GuardedRead::Refused) && matches!(o, GuardedOpen::Refused));
    }

    let target = outside.path().to_path_buf();
    let state = assert_leaf_link_replacement(
        &mut repo,
        &root,
        &discovery,
        "outsidejunctiontoken",
        |dir| dir.add_junction("src/foo.rs", &target).map(|_| ()),
    )?;

    // Store custody must also refuse a store directory that is a junction.
    let mut store_host = TempDir::new("store-junction")?;
    let linked = store_host.add_junction("linked_store", state.path())?;
    let rejected = Store::open(&linked.join("atlas.db"), &StoreIdentity::default());
    assert!(matches!(
        rejected,
        Err(IndexError::Io(ref err)) if err.kind() == io::ErrorKind::InvalidInput
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn unix_symlink_escape_and_leaf_replacement_custody() -> TestResult {
    use std::os::unix::fs::symlink;

    let outside = TempDir::new("outside-unix")?;
    outside.write("leaked.rs", "pub fn outsidesymlinktoken() {}\n")?;
    outside.write("ignore_all", "*.rs\n")?;

    let mut repo = TempDir::new("repo-unix")?;
    repo.write("src/safe.rs", "pub fn safeinsidetoken() {}\n")?;
    repo.write("src/foo.rs", "pub fn stalefootoken() {}\n")?;
    symlink(outside.path(), repo.join("escaped_dir"))?;
    symlink(outside.join("leaked.rs"), repo.join("escaped_file.rs"))?;
    symlink(outside.join("ignore_all"), repo.join(".gitignore"))?;

    let root = IndexSourceRoot::open(repo.path())?;
    let discovery = walk::discover(&root, &WalkOptions::default())?;
    assert!(discovery.complete && discovery.links >= 2 && discovery.unreadable_ignore_files >= 1);
    assert!(discovery.files.iter().any(|p| p == "src/safe.rs"));
    assert!(!discovery.files.iter().any(|p| p.starts_with("escaped_")));
    for escaped in ["escaped_dir/leaked.rs", "escaped_file.rs"] {
        assert!(matches!(
            root.read_guarded_file(escaped)?,
            GuardedRead::Refused
        ));
    }

    let leaked = outside.join("leaked.rs");
    let _state =
        assert_leaf_link_replacement(&mut repo, &root, &discovery, "outsidesymlinktoken", |dir| {
            symlink(&leaked, dir.join("src/foo.rs"))
        })?;
    Ok(())
}

#[test]
fn concurrent_reader_survives_rebuild_and_reap_preserves_wal() -> TestResult {
    let repo = TempDir::new("reap-repo")?;
    repo.write("src/lib.rs", "pub fn epochonebase() {}\n")?;
    let state = TempDir::new("reap-state")?;
    let db = state.join("atlas.db");

    let id_one = StoreIdentity {
        project: "proj-one".to_owned(),
        root: "/workspace".to_owned(),
        physical_root: "/physical".to_owned(),
    };
    let id_two = StoreIdentity {
        project: "proj-two".to_owned(),
        ..id_one.clone()
    };

    let root = IndexSourceRoot::open(repo.path())?;
    let (mut store, reason) = Store::open(&db, &id_one)?;
    assert_eq!(reason, Some(RebuildReason::Missing));
    store.cold_build(&root, &BuildOptions::default())?;

    // Commit incremental rows to WAL without checkpointing.
    repo.write(
        "src/lib.rs",
        "pub fn epochonebase() { uncheckpointedwal(); }\n",
    )?;
    let mut resolver = Resolver::new(["src/lib.rs"]);
    let outcome = store.index_path(&root, &mut resolver, "src/lib.rs")?;
    assert!(matches!(outcome, PathOutcome::Indexed(_)));
    let epoch1 = store.path().to_path_buf();
    let epoch1_wal = wal_path(&epoch1);
    assert!(epoch1_wal.exists() && fs::metadata(&epoch1_wal)?.len() > 0);

    let reader_e1 = Reader::open(&db)?;
    assert_eq!(postings(&reader_e1, "uncheckpointedwal")?.len(), 1);
    drop(store);

    // Plant a stale pointer temp file that reap_pointer_temps must clean up.
    let stale_tmp = state.join("atlas.v5.current.999999999.tmp");
    fs::write(&stale_tmp, b"atlas.v5.1.db")?;

    // Rebuild to epoch 2 via identity mismatch while epoch 1 reader is live.
    let (store_e2, reason) = Store::open(&db, &id_two)?;
    assert_eq!(
        reason,
        Some(RebuildReason::Mismatch("store identity differs"))
    );
    assert_ne!(store_e2.path(), epoch1.as_path());
    assert!(!stale_tmp.exists(), "stale pointer temp must be reaped");
    assert_eq!(postings(&reader_e1, "uncheckpointedwal")?.len(), 1);
    assert_eq!(postings(&reader_e1, "epochonebase")?.len(), 1);
    #[cfg(windows)]
    assert!(
        epoch1.exists() && epoch1_wal.exists(),
        "reap must not strip -wal while Windows reader holds .db"
    );

    // Force another rebuild via oversized pointer while reader_e1 stays open.
    drop(store_e2);
    fs::write(state.join("atlas.v5.current"), "x".repeat(300))?;
    let (store_e3, reason) = Store::open(&db, &id_two)?;
    assert_eq!(reason, Some(RebuildReason::Corrupt));
    assert_ne!(store_e3.path(), epoch1.as_path());
    assert_eq!(postings(&reader_e1, "uncheckpointedwal")?.len(), 1);

    // Once reader_e1 closes, the next open reaps epoch 1 and its WAL.
    drop(reader_e1);
    drop(store_e3);
    let (_, reason) = Store::open(&db, &id_two)?;
    assert_eq!(reason, None);
    assert!(!epoch1.exists() && !epoch1_wal.exists());
    Ok(())
}

#[test]
fn unclean_wal_shutdown_recovers_on_store_open() -> TestResult {
    let repo = TempDir::new("recover-repo")?;
    repo.write("src/lib.rs", "pub fn initialtoken() {}\n")?;
    let live_state = TempDir::new("recover-live")?;
    let identity = StoreIdentity::default();

    let root = IndexSourceRoot::open(repo.path())?;
    let (mut store, _) = Store::open(&live_state.join("atlas.db"), &identity)?;
    store.cold_build(&root, &BuildOptions::default())?;

    repo.write(
        "src/lib.rs",
        "pub fn initialtoken() { recoveredwaltoken(); }\n",
    )?;
    let mut resolver = Resolver::new(["src/lib.rs"]);
    store.index_path(&root, &mut resolver, "src/lib.rs")?;

    let epoch_file = store.path().to_path_buf();
    let epoch_name = epoch_file
        .file_name()
        .ok_or("epoch file name")?
        .to_os_string();
    let live_wal = wal_path(&epoch_file);
    assert!(live_wal.exists() && fs::metadata(&live_wal)?.len() > 0);

    // Snapshot .db + -wal + pointer without -shm to simulate an unclean shutdown.
    let crash_state = TempDir::new("recover-crash")?;
    let crash_epoch = crash_state.path().join(&epoch_name);
    fs::copy(&epoch_file, &crash_epoch)?;
    fs::copy(&live_wal, wal_path(&crash_epoch))?;
    fs::copy(
        live_state.join("atlas.v5.current"),
        crash_state.join("atlas.v5.current"),
    )?;
    drop(store);

    let crash_db = crash_state.join("atlas.db");
    let (_recovered, reason) = Store::open(&crash_db, &identity)?;
    assert_eq!(reason, None);
    let reader = Reader::open(&crash_db)?;
    assert_eq!(postings(&reader, "recoveredwaltoken")?.len(), 1);
    Ok(())
}

#[test]
fn deferred_snapshot_stays_consistent_across_compaction() -> TestResult {
    let repo = TempDir::new("snap-repo")?;
    repo.write("src/a.rs", "pub fn alphafn() { sharedtok(); }\n")?;
    repo.write("src/b.rs", "pub fn betafn() { sharedtok(); }\n")?;
    let state = TempDir::new("snap-state")?;
    let db = state.join("atlas.db");

    let root = IndexSourceRoot::open(repo.path())?;
    let (mut store, _) = Store::open(&db, &StoreIdentity::default())?;
    store.cold_build(&root, &BuildOptions::default())?;

    repo.write("src/b.rs", "pub fn betafn() { deltaaddedtok(); }\n")?;
    let mut resolver = Resolver::new(["src/a.rs", "src/b.rs"]);
    store.index_path(&root, &mut resolver, "src/b.rs")?;

    let reader = Reader::open(&db)?;
    let snap = reader.snapshot()?;
    let shared_id = snap.token_id("sharedtok")?.ok_or("sharedtok")?;
    let added_id = snap.token_id("deltaaddedtok")?.ok_or("deltaaddedtok")?;
    let pre_shared = snap.read_postings(shared_id)?;
    let pre_added = snap.read_postings(added_id)?;
    let pre_deltas = table_rows(snap.connection(), "post_delta")?;
    assert!(pre_deltas > 0 && pre_shared.len() == 1 && pre_added.len() == 1);

    let compacted = store.compact_deltas(&CompactPolicy::default(), true)?;
    assert!(compacted.tokens > 0 && table_rows(store.connection(), "post_delta")? == 0);

    // Held snapshot still sees pre-compaction deltas and exact pre-compaction postings.
    assert_eq!(table_rows(snap.connection(), "post_delta")?, pre_deltas);
    assert_eq!(snap.read_postings(shared_id)?, pre_shared);
    assert_eq!(snap.read_postings(added_id)?, pre_added);
    assert_eq!(snap.effective_df(shared_id)?, 1);

    // Fresh reader sees post_delta empty and identical logical postings.
    let fresh = Reader::open(&db)?;
    assert_eq!(table_rows(fresh.connection(), "post_delta")?, 0);
    assert_eq!(fresh.read_postings(shared_id)?, pre_shared);
    assert_eq!(fresh.read_postings(added_id)?, pre_added);
    assert_eq!(fresh.effective_df(shared_id)?, 1);

    // Further writes still cannot leak into the held snapshot.
    repo.write("src/a.rs", "pub fn alphafn() { postsnaptok(); }\n")?;
    store.index_path(&root, &mut resolver, "src/a.rs")?;
    assert_eq!(snap.read_postings(shared_id)?, pre_shared);
    assert!(fresh.read_postings(shared_id)?.is_empty());
    Ok(())
}

#[test]
fn extractor_version_bump_clears_code_index_and_preserves_history() -> TestResult {
    let repo = TempDir::new("extver-repo")?;
    repo.write("src/lib.rs", "mod helper;\npub fn entry() {}\n")?;
    repo.write("src/helper.rs", "pub fn assist() {}\n")?;
    let state = TempDir::new("extver-state")?;
    let db = state.join("atlas.db");
    let identity = StoreIdentity::default();

    let root = IndexSourceRoot::open(repo.path())?;
    let (mut store, _) = Store::open(&db, &identity)?;
    store.cold_build(&root, &BuildOptions::default())?;
    assert_eq!(table_rows(store.connection(), "files")?, 2);
    let epoch_path = store.path().to_path_buf();

    store.connection().execute(
        "INSERT INTO changes(generation, ordinal, path, kind, baseline_reset)
         VALUES (7, 0, 'src/lib.rs', 'file_edit', 0)",
        [],
    )?;
    store.connection().execute(
        "INSERT INTO authors(generation, ordinal, resolved_at_generation, hint_json)
         VALUES (7, 0, 7, '{\"source\":\"git\"}')",
        [],
    )?;
    store.connection().execute(
        "UPDATE meta SET extractor_version=?1 WHERE singleton=1",
        [EXTRACTOR_VERSION - 1],
    )?;
    drop(store);

    let (store, reason) = Store::open(&db, &identity)?;
    assert_eq!(
        reason,
        Some(RebuildReason::Mismatch("extractor version differs"))
    );
    assert_eq!(store.path(), epoch_path.as_path());
    let ver: i64 = store.connection().query_row(
        "SELECT extractor_version FROM meta WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(ver, EXTRACTOR_VERSION);

    for table in [
        "files",
        "vocab",
        "vocab_post",
        "post_delta",
        "file_tok",
        "gram",
        "gram_delta",
        "short",
        "sym",
        "imp",
        "covers",
    ] {
        assert_eq!(table_rows(store.connection(), table)?, 0, "{table}");
    }

    let change: (i64, String, String) = store.connection().query_row(
        "SELECT generation, path, kind FROM changes WHERE generation=7 AND ordinal=0",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    assert_eq!(change, (7, "src/lib.rs".to_owned(), "file_edit".to_owned()));
    let author: (i64, String) = store.connection().query_row(
        "SELECT resolved_at_generation, hint_json FROM authors WHERE generation=7 AND ordinal=0",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!(author, (7, "{\"source\":\"git\"}".to_owned()));
    Ok(())
}

fn vocab_base_state(conn: &Connection, tok: &str) -> Result<(i64, Vec<u8>), rusqlite::Error> {
    conn.query_row(
        "SELECT v.df, p.postings FROM vocab v JOIN vocab_post p ON p.tok=v.id WHERE v.tok=?1",
        [tok],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
}

#[test]
fn wal_delta_invariants_hot_token_deferral_and_cold_build_equivalence() -> TestResult {
    let repo = TempDir::new("delta-repo")?;
    for i in 1..=5 {
        repo.write(
            &format!("src/f{i}.rs"),
            &format!("pub fn uniquef{i}() {{ hotmarker(); }}\n"),
        )?;
    }

    let state_a = TempDir::new("delta-state-a")?;
    let db_a = state_a.join("atlas.db");
    let root = IndexSourceRoot::open(repo.path())?;
    let (mut store_a, _) = Store::open(&db_a, &StoreIdentity::default())?;
    store_a.cold_build(&root, &BuildOptions::default())?;

    let base_hot = vocab_base_state(store_a.connection(), "hotmarker")?;
    assert_eq!(base_hot.0, 5);

    // Touch only the single-piece hot token's tf in one file.
    repo.write(
        "src/f1.rs",
        "pub fn uniquef1() { hotmarker(); hotmarker(); }\n",
    )?;
    let mut resolver = Resolver::new([
        "src/f1.rs",
        "src/f2.rs",
        "src/f3.rs",
        "src/f4.rs",
        "src/f5.rs",
    ]);
    let GuardedRead::Source(source) = root.read_guarded_file("src/f1.rs")? else {
        return Err("src/f1.rs must be readable".into());
    };
    let report = store_a.update_file(&resolver, "src/f1.rs", &source)?;
    assert_eq!(report.delta_rows, 1);
    assert_eq!(table_rows(store_a.connection(), "post_delta")?, 1);
    assert_eq!(
        vocab_base_state(store_a.connection(), "hotmarker")?,
        base_hot
    );

    // Only a deferred hot-token row sits in post_delta: compaction_due must stay false.
    let hot_policy = CompactPolicy {
        max_delta_rows: 0,
        idle_after: Duration::ZERO,
        idle_rows: 0,
        tokens_per_transaction: 500,
        hot_df: 3,
        hot_min_deltas: 4,
    };
    assert!(!store_a.compaction_due(&hot_policy, Duration::from_secs(3600))?);
    let non_forced = store_a.compact_deltas(&hot_policy, false)?;
    assert_eq!((non_forced.tokens, non_forced.deferred), (0, 1));
    assert_eq!(table_rows(store_a.connection(), "post_delta")?, 1);
    assert!(!store_a.compaction_due(&hot_policy, Duration::from_secs(3600))?);

    // Apply edits, additions and deletions, force-compact, and match cold build.
    repo.write(
        "src/f2.rs",
        "pub fn uniquef2() { freshalpha(); freshbeta(); }\n",
    )?;
    store_a.index_path(&root, &mut resolver, "src/f2.rs")?;
    repo.write(
        "src/f6.rs",
        "pub fn uniquef6() { freshalpha(); hotmarker(); }\n",
    )?;
    store_a.index_path(&root, &mut resolver, "src/f6.rs")?;
    fs::remove_file(repo.join("src/f3.rs"))?;
    let removed = store_a.index_path(&root, &mut resolver, "src/f3.rs")?;
    assert!(matches!(removed, PathOutcome::Absent { removed: true }));
    repo.write("src/f4.rs", "pub fn replacementf4() {}\n")?;
    store_a.index_path(&root, &mut resolver, "src/f4.rs")?;

    let forced = store_a.compact_deltas(&CompactPolicy::default(), true)?;
    assert!(forced.tokens > 0);
    assert_eq!(table_rows(store_a.connection(), "post_delta")?, 0);
    assert_eq!(table_rows(store_a.connection(), "gram_delta")?, 0);

    let state_b = TempDir::new("delta-state-b")?;
    let db_b = state_b.join("atlas.db");
    let (mut store_b, _) = Store::open(&db_b, &StoreIdentity::default())?;
    store_b.cold_build(&root, &BuildOptions::default())?;

    assert_eq!(
        logical_postings_by_path(&Reader::open(&db_a)?)?,
        logical_postings_by_path(&Reader::open(&db_b)?)?
    );
    Ok(())
}

fn query_sym(conn: &Connection, tok: &str) -> Result<(i64, Option<i64>, Vec<u8>), rusqlite::Error> {
    conn.query_row(
        "SELECT s.id, s.parent, s.key FROM sym s JOIN vocab v ON v.id=s.name WHERE v.tok=?1",
        [tok],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
}

#[test]
fn go_forward_parent_persists_parent_and_order_independent_key() -> TestResult {
    let method_first = "package demo\n\nfunc (s *Server) Start() error {\n\treturn nil\n}\n\ntype Server struct {\n\tName string\n}\n";
    let struct_first = "package demo\n\ntype Server struct {\n\tName string\n}\n\nfunc (s *Server) Start() error {\n\treturn nil\n}\n";
    let ex_a = extract("pkg/server.go", method_first.as_bytes(), false);
    let ex_b = extract("pkg/server.go", struct_first.as_bytes(), false);
    assert_eq!(
        outline(&ex_a),
        [
            (SymbolKind::Method, "Start", Some("Server")),
            (SymbolKind::Struct, "Server", None),
        ]
    );
    assert_eq!(ex_a.symbols[0].key, ex_b.symbols[1].key);
    assert_eq!(ex_a.symbols[1].key, ex_b.symbols[0].key);

    let repo = TempDir::new("go-fwd-repo")?;
    repo.write("pkg/server.go", method_first)?;
    let state = TempDir::new("go-fwd-state")?;
    let (mut store, _) = Store::open(&state.join("atlas.db"), &StoreIdentity::default())?;
    let root = IndexSourceRoot::open(repo.path())?;
    store.cold_build(&root, &BuildOptions::default())?;

    let (server_id, server_parent, server_key) = query_sym(store.connection(), "server")?;
    let (_, start_parent, start_key) = query_sym(store.connection(), "start")?;
    assert_eq!(server_parent, None);
    assert_eq!(start_parent, Some(server_id));
    assert_eq!(server_key.as_slice(), ex_a.symbols[1].key.as_slice());
    assert_eq!(start_key.as_slice(), ex_a.symbols[0].key.as_slice());

    // Incremental update also links forward-declared methods.
    repo.write(
        "pkg/server.go",
        &format!("package demo\n\nfunc (s *Server) Stop() {{}}\n\n{method_first}"),
    )?;
    let mut resolver = Resolver::new(["pkg/server.go"]);
    store.index_path(&root, &mut resolver, "pkg/server.go")?;
    let (server_id_inc, _, _) = query_sym(store.connection(), "server")?;
    let (_, start_parent_inc, start_key_inc) = query_sym(store.connection(), "start")?;
    let (_, stop_parent_inc, _) = query_sym(store.connection(), "stop")?;
    assert_eq!(start_parent_inc, Some(server_id_inc));
    assert_eq!(stop_parent_inc, Some(server_id_inc));
    assert_eq!(start_key_inc.as_slice(), ex_a.symbols[0].key.as_slice());
    Ok(())
}

#[test]
fn extractor_lexer_and_outline_edge_cases() {
    let js = "function outer(a) {\n  const s = `${a ? `}` : \"ok\"}`;\n  return s;\n}\nfunction after() {\n  return 1;\n}\n";
    let js_ex = extract("web/app.js", js.as_bytes(), false);
    assert_eq!(
        outline(&js_ex),
        [
            (SymbolKind::Function, "outer", None),
            (SymbolKind::Function, "after", None),
        ]
    );
    assert_eq!((js_ex.symbols[0].line, js_ex.symbols[0].end_line), (1, 4));
    assert_eq!((js_ex.symbols[1].line, js_ex.symbols[1].end_line), (5, 7));

    let go = "package demo\n\nfunc rawBackslash() string {\n\ts := `\\`\n\t_ = \"}\"\n\treturn s\n}\n\nfunc nextFunc() {}\n";
    let go_ex = extract("pkg/raw.go", go.as_bytes(), false);
    assert_eq!(
        outline(&go_ex),
        [
            (SymbolKind::Function, "rawBackslash", None),
            (SymbolKind::Function, "nextFunc", None),
        ]
    );
    assert_eq!((go_ex.symbols[0].line, go_ex.symbols[0].end_line), (3, 7));
    assert_eq!(go_ex.symbols[1].line, 9);

    let rust = "fn first() {\n    let q = '\\'';\n    let s = cr#\"a\\\" { b\"#;\n    let _ = (q, s);\n}\n\nfn second() {}\n";
    let rust_ex = extract("src/lex_edge.rs", rust.as_bytes(), false);
    assert_eq!(
        outline(&rust_ex),
        [
            (SymbolKind::Function, "first", None),
            (SymbolKind::Function, "second", None),
        ]
    );
    assert_eq!(
        (rust_ex.symbols[0].line, rust_ex.symbols[0].end_line),
        (1, 5)
    );
    assert_eq!(rust_ex.symbols[1].line, 7);

    let kt = "class Service {\n    companion object objectFactory {\n        fun make(): Service = Service()\n    }\n}\n";
    let kt_ex = extract("app/Service.kt", kt.as_bytes(), false);
    assert_eq!(
        outline(&kt_ex),
        [
            (SymbolKind::Class, "Service", None),
            (SymbolKind::Class, "objectFactory", Some("Service")),
            (SymbolKind::Method, "make", Some("objectFactory")),
        ]
    );
}

#[test]
fn extractor_keyword_boundaries_and_reexport_or_merge() -> TestResult {
    let ts = "const enumerable = true;\nexport const fromDate = 'x';\n";
    let ts_ex = extract("web/consts.ts", ts.as_bytes(), false);
    assert_eq!(
        outline(&ts_ex),
        [
            (SymbolKind::Const, "enumerable", None),
            (SymbolKind::Const, "fromDate", None),
        ]
    );
    assert!(ts_ex.symbols[1].exported && ts_ex.imports.is_empty());

    let use_then_pub = "use crate::alpha::One;\npub use crate::alpha::Two;\n";
    let pub_then_use = "pub use crate::alpha::Two;\nuse crate::alpha::One;\n";
    for src in [use_then_pub, pub_then_use] {
        let ex = extract("src/lib.rs", src.as_bytes(), false);
        assert_eq!(ex.imports.len(), 1);
        assert_eq!(ex.imports[0].spelling, "crate::alpha");
        assert!(ex.imports[0].reexport);
    }

    let repo = TempDir::new("reexport-repo")?;
    repo.write("src/lib.rs", use_then_pub)?;
    repo.write("src/alpha.rs", "pub struct One;\npub struct Two;\n")?;
    let state = TempDir::new("reexport-state")?;
    let root = IndexSourceRoot::open(repo.path())?;
    let (mut store, _) = Store::open(&state.join("atlas.db"), &StoreIdentity::default())?;
    store.cold_build(&root, &BuildOptions::default())?;
    let reexport: bool = store.connection().query_row(
        "SELECT reexport FROM imp WHERE spelling='crate::alpha'",
        [],
        |r| r.get(0),
    )?;
    assert!(reexport);
    Ok(())
}
