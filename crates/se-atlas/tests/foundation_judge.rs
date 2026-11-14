//! Independent foundation consumer checks. The native test adapter is not a production
//! custody implementation or a qualification of the proposed SQL overhead profile.
#![cfg(unix)]
#[path = "../../test-support/atlas_clock.rs"]
mod test_clock;
use se_atlas::{
    cache::{connection::*, pointer, prune, *},
    errors::AtlasResult,
    model::*,
    scope::Scope,
};
use se_types::ProjectId;
use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};
fn cache_error(reason: impl std::fmt::Display) -> se_types::SeError {
    se_types::SeError::invalid("judge IO", &reason.to_string())
}
type Check = Result<(), Box<dyn Error>>;
static SERIAL: Mutex<()> = Mutex::new(());
struct Native {
    dir: PathBuf,
}
impl Drop for Native {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
struct Metadata(std::fs::Metadata);
impl DatabaseFile for Metadata {
    fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        Ok(self.0.clone())
    }
    fn identity(&self) -> std::io::Result<DatabaseFileIdentity> {
        use std::os::unix::fs::MetadataExt;
        let mut volume = [0; 16];
        let mut file = [0; 16];
        volume[..8].copy_from_slice(&self.0.dev().to_be_bytes());
        file[..8].copy_from_slice(&self.0.ino().to_be_bytes());
        Ok((volume, file))
    }
}
struct Reservation;
impl GrowthReservation for Reservation {}
impl CacheFiles for Native {
    fn read_pointer(&self) -> AtlasResult<Option<Vec<u8>>> {
        match fs::read(self.dir.join("current.json")) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(cache_error(e)),
        }
    }
    fn replace_pointer(&self, expected: Option<&[u8]>, bytes: &[u8]) -> AtlasResult<()> {
        if self.read_pointer()?.as_deref() != expected {
            return Err(cache_error("pointer CAS"));
        }
        fs::write(self.dir.join("current.json"), bytes).map_err(cache_error)
    }
    fn pin_database(&self, epoch: &CacheEpoch) -> AtlasResult<Option<DatabasePin>> {
        let path = self.dir.join(epoch.as_str());
        match fs::symlink_metadata(&path) {
            Ok(file) => Ok(Some(DatabasePin {
                file: Box::new(Metadata(file)),
                path,
            })),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(cache_error(e)),
        }
    }
    fn reserve_database(&self, epoch: &CacheEpoch) -> AtlasResult<DatabasePin> {
        let path = self.dir.join(epoch.as_str());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(cache_error)?;
        let metadata = file.metadata().map_err(cache_error)?;
        drop(file);
        Ok(DatabasePin {
            file: Box::new(Metadata(metadata)),
            path,
        })
    }
    fn discard_unpublished(&self, pin: &DatabasePin) -> AtlasResult<()> {
        self.validate_database(pin)?;
        for suffix in ["-wal", "-shm", ""] {
            match fs::remove_file(format!("{}{}", pin.path.display(), suffix)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(cache_error(e)),
            }
        }
        Ok(())
    }
    fn validate_database(&self, pin: &DatabasePin) -> AtlasResult<()> {
        use std::os::unix::fs::MetadataExt;
        let path = fs::symlink_metadata(&pin.path).map_err(cache_error)?;
        let held = pin.file.metadata().map_err(cache_error)?;
        if !path.is_file() || path.ino() != held.ino() || path.dev() != held.dev() {
            return Err(cache_error("pin changed"));
        }
        Ok(())
    }
    fn wal_bytes(&self, pin: &DatabasePin) -> AtlasResult<u64> {
        match fs::metadata(format!("{}-wal", pin.path.display())) {
            Ok(m) => Ok(m.len()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(cache_error(e)),
        }
    }
    fn reserve_growth(&self, _: u64) -> AtlasResult<Box<dyn GrowthReservation + '_>> {
        Ok(Box::new(Reservation))
    }
}
fn setup() -> Result<(Native, CacheSeed, SqlProfile), Box<dyn Error>> {
    let dir = std::env::temp_dir().join(format!(
        "se-atlas-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    fs::create_dir(&dir)?;
    let native = Native { dir };
    let scope = Scope::new(
        RootRegistration {
            project: ProjectId::from_parts(1, [1; 10])?,
            root: RootId::from_parts(1, [2; 10])?,
            canonical_source_root: native.dir.clone(),
            cache: CacheLocation {
                directory: native.dir.clone(),
            },
            git_metadata: None,
        },
        [3; 32],
    )?;
    let coverage = serde_json::from_value(
        serde_json::json!({"discovered_files":0,"indexed_files":0,"partial_files":0,"deferred_files":0,"failed_files":0,"discovery_complete":true,"stale_files":0,"resolved_references":0,"name_only_references":0,"watched_directories":0,"unwatched_directories":0,"watch_discovery_complete":true,"watch_stats_started":null,"watch_activation_attempts":0,"watch_limited_activations":0,"reasons":[]}),
    )?;
    let seed = CacheSeed {
        identity: CacheIdentity {
            scope,
            epoch: CacheEpoch::from_parts(1, [4; 10])?,
        },
        extractor_version: "judge".into(),
        ignore_digest: ContentHash([0; 32]),
        coverage,
        state: IndexState::Current,
    };
    Ok((native, seed, SqlProfile::from_qualified_overhead(1)?))
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
#[path = "foundation_judge/history.rs"]
mod history;
#[test]
fn empty_cache_real_consumer_prune() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    assert_eq!(prune::changes(&mut db, 0, 64, deadline())?.deleted, 0);
    assert!(
        !prune::metadata(&mut db, 64, deadline())?,
        "empty metadata must not have pending work"
    );
    assert!(!prune::commits(&mut db, 64, deadline())?);
    Ok(())
}
#[test]
fn read_snapshots_refuse_writes_and_sql_timeout_is_typed() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    assert!(
        db.read(deadline(), |v| {
            v.prepare("DELETE FROM names")?;
            Ok(())
        })
        .is_err()
    );
    let expired = db
        .read(Instant::now(), |_| Ok(()))
        .err()
        .ok_or("deadline accepted")?;
    assert!(matches!(
        expired.body.detail(),
        se_types::Detail::DeadlineExceeded(_)
    ));
    db.write(0, deadline(), |v| {
        v.prepare("INSERT INTO names(text) VALUES('retained')")?
            .execute([])
            .map_err(cache_error)?;
        Ok(())
    })?;
    let n: i64 = db.read(deadline(), |v| {
        v.prepare("SELECT count(*) FROM names")?
            .query_row([], |r| r.get(0))
            .map_err(cache_error)
    })?;
    assert_eq!(n, 1);
    Ok(())
}
#[test]
fn pointer_absence_corruption_scope_and_published_readback() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    assert!(
        pointer::open_current(
            &f,
            &s.identity.scope,
            ConnectionRole::ExternalReader,
            &p,
            deadline()
        )?
        .is_none()
    );
    fs::write(f.dir.join("current.json"), b"{")?;
    assert!(
        pointer::open_current(
            &f,
            &s.identity.scope,
            ConnectionRole::ExternalReader,
            &p,
            deadline()
        )
        .is_err()
    );
    fs::remove_file(f.dir.join("current.json"))?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    let ptr = pointer::publish(&f, &mut db, None, deadline())?;
    assert_eq!(ptr.epoch, s.identity.epoch);
    let reader = pointer::open_current(
        &f,
        &s.identity.scope,
        ConnectionRole::ExternalReader,
        &p,
        deadline(),
    )?
    .ok_or("missing")?;
    assert!(!reader.epoch_retired);
    let mut wrong = s.identity.scope.clone();
    wrong.physical_root = [9; 32];
    assert!(
        pointer::open_current(&f, &wrong, ConnectionRole::ExternalReader, &p, deadline()).is_err()
    );
    Ok(())
}
#[test]
fn transaction_error_rolls_back_native_database() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    let result: AtlasResult<()> = db.write(0, deadline(), |v| {
        v.prepare("INSERT INTO names(text) VALUES('rolled-back')")?
            .execute([])
            .map_err(cache_error)?;
        Err(cache_error("intentional failure"))
    });
    assert!(result.is_err());
    let n: i64 = db.read(deadline(), |v| {
        v.prepare("SELECT count(*) FROM names")?
            .query_row([], |r| r.get(0))
            .map_err(cache_error)
    })?;
    assert_eq!(n, 0);
    Ok(())
}
#[test]
fn portable_paths_reject_windows_aliases_at_shared_ingress() -> Check {
    for bad in [
        "/tmp/a",
        "../a",
        "a/../b",
        "C:/a",
        "a:stream",
        "a/NUL.txt",
        "a/COM¹.rs",
        "a/conin$",
        "a/trailing.",
        "a/trailing ",
        "a\\b",
    ] {
        assert!(RelativePath::new(bad).is_err(), "accepted {bad:?}");
    }
    for good in [
        "src/main.rs",
        "src/CONTEXT.rs",
        "café/代码.rs",
        "tests/complex.name.rs",
    ] {
        RelativePath::new(good)?;
    }
    Ok(())
}

#[test]
fn fts_and_commit_dependents_are_erased_with_native_owner_rows() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    db.write(1_000_000,deadline(),|v|{
  for statement in [
   "INSERT INTO records(id,record_id,kind,occurred_unix_ms,title,source_event,visibility) VALUES(1,'record','message',0,'needle','event','project')",
   "INSERT INTO record_fts(rowid,title,kind) VALUES(1,'needle','message')",
   "INSERT INTO record_text_fts(rowid,body) VALUES(1,'needle')",
   "INSERT INTO mentions VALUES('record',1,'file',x'01','exact')",
   "INSERT INTO touches(target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms,source_record,restricted_record) VALUES('file',x'01',0,'message',NULL,0,1,NULL)",
   "INSERT INTO commits(id,oid,author_unix_ms,author,subject) VALUES(1,x'01',0,'author','subject')",
   "INSERT INTO mentions VALUES('commit',1,'file',x'01','exact')",
   "INSERT INTO touches(target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms,source_record,restricted_record) VALUES('commit',x'01',0,'commit',NULL,0,NULL,NULL)"
  ]{v.prepare(statement)?.execute([]).map_err(cache_error)?;}Ok(())
 })?;
    db.write(1_000_000, deadline(), |v| {
        for statement in [
            "DELETE FROM records WHERE id=1",
            "DELETE FROM commits WHERE id=1",
        ] {
            v.prepare(statement)?.execute([]).map_err(cache_error)?;
        }
        Ok(())
    })?;
    let outside = rusqlite::Connection::open_with_flags(
        f.dir.join(s.identity.epoch.as_str()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    for statement in [
        "SELECT count(*) FROM record_fts WHERE record_fts MATCH 'needle'",
        "SELECT count(*) FROM record_text_fts WHERE record_text_fts MATCH 'needle'",
        "SELECT count(*) FROM mentions",
        "SELECT count(*) FROM touches",
    ] {
        assert_eq!(
            outside.query_row(statement, [], |r| r.get::<_, i64>(0))?,
            0,
            "{statement}"
        );
    }
    Ok(())
}
#[test]
fn populated_prune_uses_production_budget_and_keeps_referenced_commits() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    db.write(1_000_000,deadline(),|v|{
 for statement in [
  "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<20001) INSERT INTO commits(id,oid,author_unix_ms,author,subject) SELECT x,CAST(printf('%040d',x) AS BLOB),x,'author','subject' FROM n",
  "INSERT INTO mentions SELECT 'record',99,'commit',oid,'exact' FROM commits WHERE id=1",
  "WITH RECURSIVE n(x) AS (VALUES(0) UNION ALL SELECT x+1 FROM n WHERE x<14) INSERT INTO touches(target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms,source_record,restricted_record) SELECT 'file',x'01',x,'edit',NULL,x,NULL,NULL FROM n",
  "INSERT INTO names(text) VALUES('orphan')"
 ]{v.prepare(statement)?.execute([]).map_err(cache_error)?;}Ok(())
 })?;
    assert!(!prune::commits(&mut db, 64, deadline())?);
    let _ = prune::metadata(&mut db, 64, deadline())?;
    let outside = rusqlite::Connection::open_with_flags(
        f.dir.join(s.identity.epoch.as_str()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    assert_eq!(
        outside.query_row("SELECT count(*) FROM commits", [], |r| r.get::<_, i64>(0))?,
        20000
    );
    assert_eq!(
        outside.query_row("SELECT count(*) FROM commits WHERE id=1", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        outside.query_row("SELECT count(*) FROM touches", [], |r| r.get::<_, i64>(0))?,
        10
    );
    assert_eq!(
        outside.query_row("SELECT count(*) FROM names", [], |r| r.get::<_, i64>(0))?,
        0
    );
    Ok(())
}
#[test]
fn failed_creation_reaps_unpublished_db_and_preserves_seed_error() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, mut s, p) = setup()?;
    s.extractor_version = String::new();
    let error = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())
        .err()
        .ok_or("invalid seed created")?;
    assert!(error.to_string().contains("seed"), "{error}");
    assert!(f.pin_database(&s.identity.epoch)?.is_none());
    assert!(f.read_pointer()?.is_none());
    Ok(())
}

use se_atlas::{
    lifecycle::{
        AtlasSource, CaseMode, FileIdentity, RevisionTrust, SourceRead, SourceVerification,
    },
    source::{RegisteredSource, SourceAccess, SourceFile},
};
use std::io::{self, Read, Seek, SeekFrom};
struct NativeSource(PathBuf);
struct NativeFile(File);
impl Read for NativeFile {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b)
    }
}
impl Seek for NativeFile {
    fn seek(&mut self, s: SeekFrom) -> io::Result<u64> {
        self.0.seek(s)
    }
}
impl SourceFile for NativeFile {
    fn identity(&self) -> AtlasResult<FileIdentity> {
        use std::os::unix::fs::MetadataExt;
        let m = self.0.metadata().map_err(cache_error)?;
        Ok(FileIdentity {
            volume: (m.dev() as u128).to_be_bytes(),
            file: (m.ino() as u128).to_be_bytes(),
            size: m.len(),
            mtime_unix_nanos: m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
            ctime_unix_nanos: Some(m.ctime() as i128 * 1_000_000_000 + m.ctime_nsec() as i128),
            change_sequence: None,
            sequence_domain: None,
            revision_trust: RevisionTrust::QualifiedCtime,
        })
    }
    fn validate_path(&self) -> AtlasResult<bool> {
        Ok(true)
    }
}
impl SourceAccess for NativeSource {
    fn physical_root(&self) -> AtlasResult<[u8; 32]> {
        Ok([3; 32])
    }
    fn case_mode(&self) -> CaseMode {
        CaseMode::Sensitive
    }
    fn open(&self, p: &RelativePath) -> AtlasResult<Option<Box<dyn SourceFile + '_>>> {
        match File::open(self.0.join(se_types::code::AtlasText::as_str(p))) {
            Ok(f) => Ok(Some(Box::new(NativeFile(f)))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(cache_error(e)),
        }
    }
}
#[test]
fn native_source_absence_hashes_same_size_edits_and_budget_refusal() -> Check {
    let (f, s, _) = setup()?;
    let source = RegisteredSource::new(s.identity.scope, NativeSource(f.dir.clone()))?;
    let path = RelativePath::new("source.rs")?;
    let budget = ParseBudget {
        max_source_bytes: 64,
        max_rows: 100,
        max_work: Duration::from_millis(200),
        reserved_bytes: 64,
    };
    assert!(matches!(source.read(&path, budget)?, SourceRead::Removed));
    assert!(source.read_chunk(&path, 0, 16)?.is_none());
    fs::write(f.dir.join("source.rs"), b"fn alpha() {}")?;
    let SourceRead::Bytes(snapshot) = source.read(&path, budget)? else {
        return Err("expected bytes".into());
    };
    assert_eq!(source.verify(&snapshot)?, SourceVerification::Unchanged);
    let chunk = source.read_chunk(&path, 0, 16)?.ok_or("absent chunk")?;
    assert_eq!(chunk.bytes, snapshot.bytes);
    assert_eq!(chunk.content_revision, Some(snapshot.content_hash));
    let original = fs::metadata(f.dir.join("source.rs"))?.modified()?;
    fs::write(f.dir.join("source.rs"), b"fn bravo() {}")?;
    File::options()
        .write(true)
        .open(f.dir.join("source.rs"))?
        .set_times(fs::FileTimes::new().set_modified(original))?;
    assert_eq!(source.verify(&snapshot)?, SourceVerification::Changed);
    assert!(matches!(
        source
            .read(
                &path,
                ParseBudget {
                    reserved_bytes: 1,
                    ..budget
                }
            )
            .err()
            .ok_or("budget accepted")?
            .body
            .detail(),
        se_types::Detail::AtlasResourceBudget(_)
    ));
    assert!(matches!(
        source.read(
            &path,
            ParseBudget {
                max_source_bytes: 1,
                ..budget
            }
        )?,
        SourceRead::Deferred { .. }
    ));
    fs::remove_file(f.dir.join("source.rs"))?;
    assert_eq!(source.verify(&snapshot)?, SourceVerification::Removed);
    Ok(())
}
#[test]
fn statement_capacity_refusal_releases_arena_and_keeps_connection_usable() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    db.read(deadline(), |v| {
        let mut held = Vec::new();
        for _ in 0..9 {
            match v.prepare("SELECT 1") {
                Ok(statement) => held.push(statement),
                Err(error) => {
                    assert!(matches!(
                        error.body.detail(),
                        se_types::Detail::AtlasResourceBudget(_)
                    ));
                    break;
                }
            }
        }
        assert!(!held.is_empty() && held.len() <= 8);
        let bytes: i32 = held
            .iter()
            .map(|s| s.get_status(rusqlite::StatementStatus::MemUsed))
            .sum();
        assert!(bytes <= 16384, "retained statements exceed 16 KiB: {bytes}");
        assert!(v.prepare("SELECT 2").is_err());
        drop(held);
        v.prepare("SELECT 3")?;
        Ok(())
    })?;
    db.read(deadline(), |v| {
        v.prepare("SELECT 4")?;
        Ok(())
    })?;
    Ok(())
}

#[test]
fn quiet_month_expires_published_changes_but_preserves_unpublished_staging() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    db.write(1_000_000,deadline(),|v|{for statement in [
  "UPDATE meta SET index_generation=2,published_generation=1 WHERE singleton=1",
  "INSERT INTO generations VALUES(1,0,1,'file'),(2,0,2,'file')",
  "INSERT INTO changes(generation,ordinal,kind,baseline_reset) VALUES(1,0,'updated',0),(2,0,'updated',0)"]{v.prepare(statement)?.execute([]).map_err(cache_error)?;}Ok(())})?;
    let report = prune::changes(&mut db, 31 * 24 * 60 * 60 * 1000, 64, deadline())?;
    assert_eq!(report.retention_floor, 1);
    assert_eq!(report.deleted, 1);
    assert!(!report.pending);
    let outside = rusqlite::Connection::open_with_flags(
        f.dir.join(s.identity.epoch.as_str()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    assert_eq!(
        outside.query_row("SELECT retention_floor FROM meta", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        outside.query_row("SELECT generation FROM changes", [], |r| r.get::<_, i64>(0))?,
        2
    );
    Ok(())
}
#[test]
fn file_retirement_removes_contentless_fts_and_record_incoming_mentions() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    db.write(1_000_000,deadline(),|v|{for statement in [
  "INSERT INTO files(id,key,path,path_key,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(1,zeroblob(16),'a.rs','a.rs',0,x'01','{}',0,0,0)",
  "INSERT INTO names(id,text) VALUES(1,'needle')",
  "INSERT INTO symbols(id,key,file,name,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,exported,doc_line) VALUES(1,zeroblob(32),1,1,'function',0,1,1,0,1,1,0,'doc')",
  "INSERT INTO symbol_fts(rowid,name,split_name,path,container,doc_line) VALUES(1,'needle','needle','a.rs','','doc')",
  "INSERT INTO records(id,record_id,kind,occurred_unix_ms,title,source_event,visibility) VALUES(1,'decision/key','decision',0,'title','event','project')",
  "INSERT INTO mentions VALUES('record',2,'record',CAST('decision/key' AS BLOB),'exact')"
 ]{
                v.prepare(statement)?.execute([]).map_err(cache_error)?;}Ok(())})?;
    db.write(1_000_000, deadline(), |v| {
        assert!(se_atlas::cache::write::delete_file(v, FileId([0; 16]))?);
        assert!(!se_atlas::cache::write::delete_file(v, FileId([0; 16]))?);
        v.prepare("DELETE FROM records WHERE id=1")?
            .execute([])
            .map_err(cache_error)?;
        Ok(())
    })?;
    let outside = rusqlite::Connection::open_with_flags(
        f.dir.join(s.identity.epoch.as_str()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    assert_eq!(
        outside.query_row(
            "SELECT count(*) FROM symbol_fts WHERE symbol_fts MATCH 'needle'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    assert_eq!(
        outside.query_row("SELECT count(*) FROM mentions", [], |r| r.get::<_, i64>(0))?,
        0
    );
    Ok(())
}

#[test]
fn file_retirement_repairs_incoming_edges_and_handles_nested_symbols_atomically() -> Check {
    let _serial = SERIAL.lock().map_err(|_| "lock")?;
    let (f, s, p) = setup()?;
    let mut db = CacheConnection::create(&f, &s, ConnectionRole::HostWriter, &p, deadline())?;
    db.write(1_000_000,deadline(),|v|{for statement in [
 "INSERT INTO files(id,key,path,path_key,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(1,zeroblob(16),'a.rs','a.rs',0,x'01','{}',0,0,0)",
 "INSERT INTO files(id,key,path,path_key,bytes,identity,coverage_json,last_code_generation,last_author_generation,baseline_reset) VALUES(2,x'01010101010101010101010101010101','b.rs','b.rs',0,x'02','{}',0,0,0)",
 "INSERT INTO names(id,text) VALUES(1,'needle')",
 "INSERT INTO symbols(id,key,file,parent,name,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,exported,doc_line) VALUES(1,zeroblob(32),1,NULL,1,'function',0,9,1,0,1,9,0,'doc')",
 "INSERT INTO symbols(id,key,file,parent,name,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,exported,doc_line) VALUES(2,x'0101010101010101010101010101010101010101010101010101010101010101',1,1,1,'function',1,8,1,1,1,8,0,'doc')",
 "INSERT INTO refs(file,target,spelling,kind,start_byte,end_byte,start_line,start_column,end_line,end_column,accuracy) VALUES(2,2,1,'call',0,1,1,0,1,1,'Resolved')",
 "INSERT INTO imports(file,spelling,local_name,imported_name,target_file,target_symbol,start_byte,end_byte,resolution) VALUES(2,'a.rs',1,1,1,2,0,1,'Resolved')",
 "INSERT INTO touches(target_kind,target_key,ordinal,touch_kind,actor,at_unix_ms,source_record,restricted_record) VALUES('symbol',zeroblob(32),0,'edit',NULL,0,NULL,NULL),('file',zeroblob(16),0,'edit',NULL,0,NULL,NULL)",
 "INSERT INTO activity VALUES('symbol',zeroblob(32),0,0),('file',zeroblob(16),0,0)"
 ]{v.prepare(statement)?.execute([]).map_err(cache_error)?;}Ok(())})?;
    db.write(1_000_000, deadline(), |v| {
        assert!(se_atlas::cache::write::delete_file(v, FileId([0; 16]))?);
        Ok(())
    })?;
    let outside = rusqlite::Connection::open_with_flags(
        f.dir.join(s.identity.epoch.as_str()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    assert_eq!(
        outside.query_row("SELECT count(*) FROM symbols", [], |r| r.get::<_, i64>(0))?,
        0
    );
    assert_eq!(
        outside.query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        outside.query_row(
            "SELECT count(*) FROM refs WHERE target IS NULL AND accuracy='NameOnly'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        1
    );
    assert_eq!(outside.query_row("SELECT count(*) FROM imports WHERE target_file IS NULL AND target_symbol IS NULL AND resolution='NameOnly'",[],|r|r.get::<_,i64>(0))?,1);
    for query in [
        "SELECT count(*) FROM activity",
        "SELECT count(*) FROM touches",
    ] {
        assert_eq!(outside.query_row(query, [], |r| r.get::<_, i64>(0))?, 0);
    }
    Ok(())
}

#[path = "foundation_judge/counts.rs"]
mod counts;
