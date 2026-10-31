//! Protected online snapshots used by automatic backup and clean close.
use crate::{connection, error::*, open::SqliteReader, *};
use rusqlite::{
    Connection, OpenFlags,
    backup::{Backup, StepResult},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read as _,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
const INDEX: &str = "backup-index.json";
const PENDING: &str = ".se-stage-backup-pending";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: RecordId,
    store: StoreId,
    incarnation: u64,
    schema: u32,
    application: u32,
    through: u64,
    bytes: u64,
    sha256: [u8; 32],
    file: String,
    validated: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    version: u16,
    store: StoreId,
    generations: Vec<Entry>,
}
fn check(deadline: Instant) -> StoreResult<()> {
    if Instant::now() >= deadline {
        Err(fail(
            StoreErrorCode::BackupFailed,
            "backup deadline exhausted",
        ))
    } else {
        Ok(())
    }
}
fn present(files: &dyn StateFiles, path: &Path) -> StoreResult<File> {
    match files.readback(path)? {
        se_types::Read::Present { value } => Ok(value),
        _ => Err(fail(
            StoreErrorCode::BackupFailed,
            format!("protected backup file not present: {}", path.display()),
        )),
    }
}
fn digest(mut file: File, deadline: Instant) -> StoreResult<(u64, [u8; 32])> {
    let mut bytes = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        check(deadline)?;
        let count = file.read(&mut buffer).map_err(invalid)?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| invalid("backup byte length overflow"))?;
        hash.update(&buffer[..count]);
    }
    Ok((bytes, hash.finalize().into()))
}
fn filename(id: RecordId) -> String {
    format!("state-backup-{}.db", uuid::Uuid::from_bytes(*id.as_bytes()))
}
impl Entry {
    fn generation(&self, root: &Path) -> StoreResult<BackupGeneration> {
        if self.file != filename(self.id)
            || self.schema != connection::SCHEMA
            || self.application != connection::APP
            || self.incarnation == 0
            || !self.validated
        {
            return Err(fail(
                StoreErrorCode::BackupFailed,
                "backup manifest has unsupported or inconsistent fields",
            ));
        }
        Ok(BackupGeneration {
            id: self.id,
            through: StorePosition::new_internal(
                self.store.clone(),
                self.incarnation,
                self.through,
            )?,
            schema_version: self.schema,
            bytes: self.bytes,
            sha256: self.sha256,
            path: root.join(&self.file),
        })
    }
}
fn read_index(
    files: &dyn StateFiles,
    root: &Path,
    store: &StoreId,
    deadline: Instant,
) -> StoreResult<(Index, Option<[u8; 32]>)> {
    let file = match files.readback(&root.join(INDEX))? {
        se_types::Read::Absent { .. } => {
            return Ok((
                Index {
                    version: 1,
                    store: store.clone(),
                    generations: Vec::new(),
                },
                None,
            ));
        }
        se_types::Read::Present { value } => value,
        _ => {
            return Err(fail(
                StoreErrorCode::BackupFailed,
                "backup index is unreadable, not absent",
            ));
        }
    };
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes).map_err(invalid)?;
    if bytes.len() > 65536 {
        return Err(fail(
            StoreErrorCode::BackupFailed,
            "backup index exceeds 64 KiB",
        ));
    }
    let index: Index = serde_json::from_slice(&bytes).map_err(invalid)?;
    if index.version != 1 || index.store != *store || index.generations.len() > 2 {
        return Err(fail(
            StoreErrorCode::BackupFailed,
            "backup index version/store/count differs",
        ));
    }
    let mut ids = Vec::new();
    for entry in &index.generations {
        check(deadline)?;
        if entry.store != *store || ids.contains(&entry.id) {
            return Err(fail(
                StoreErrorCode::BackupFailed,
                "backup index contains foreign or duplicate generations",
            ));
        }
        ids.push(entry.id);
        let generation = entry.generation(root)?;
        let (length, hash) = digest(present(files, &generation.path)?, deadline)?;
        if length != entry.bytes || hash != entry.sha256 {
            return Err(fail(
                StoreErrorCode::BackupFailed,
                format!(
                    "retained backup bytes differ: {}",
                    generation.path.display()
                ),
            ));
        }
    }
    Ok((index, Some(Sha256::digest(&bytes).into())))
}
fn refuse_unindexed(
    files: &dyn StateFiles,
    root: &Path,
    index: &Index,
    deadline: Instant,
) -> StoreResult<()> {
    let entries = files.list_owned(root, 4096)?;
    if entries.len() > 4096 {
        return Err(fail(
            StoreErrorCode::BackupFailed,
            "native backup listing exceeded its bound",
        ));
    }
    for path in entries {
        check(deadline)?;
        if path.parent() != Some(root) {
            return Err(fail(
                StoreErrorCode::LocationUnsafe,
                "backup listing escaped the held directory",
            ));
        }
        if let Some(name) = path.file_name().and_then(|s| s.to_str())
            && name.starts_with("state-backup-")
            && name.ends_with(".db")
            && !index.generations.iter().any(|e| e.file == name)
        {
            return Err(fail(
                StoreErrorCode::BackupFailed,
                format!(
                    "unindexed pending generation retained at {}; resolve it before creating another",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}
pub(crate) fn remove_if_present(
    files: &dyn StateFiles,
    path: &Path,
    deadline: Instant,
) -> StoreResult<()> {
    match files.readback(path)? {
        se_types::Read::Absent { .. } => Ok(()),
        se_types::Read::Present { value } => {
            let (_, hash) = digest(value, deadline)?;
            files.remove_owned(path, hash)
        }
        _ => Err(fail(
            StoreErrorCode::BackupFailed,
            format!("owned pending file unreadable: {}", path.display()),
        )),
    }
}
fn cleanup(files: &dyn StateFiles, root: &Path, deadline: Instant) -> StoreResult<()> {
    for suffix in ["-journal", "-wal", "-shm", ""] {
        remove_if_present(files, &root.join(format!("{PENDING}{suffix}")), deadline)?;
    }
    Ok(())
}
fn wal_limit(files: &dyn StateFiles, root: &Path, context: &BackupContext) -> StoreResult<()> {
    if context.state.abort.load(Ordering::Acquire) {
        return Err(fail(
            StoreErrorCode::BackupFailed,
            "backup aborted at the 64 MiB WAL limit",
        ));
    }
    match files.readback(&root.join("state.db-wal"))? {
        se_types::Read::Absent { .. } => Ok(()),
        se_types::Read::Present { value }
            if value.metadata().map_err(invalid)?.len() < 64 * 1024 * 1024 =>
        {
            Ok(())
        }
        se_types::Read::Present { .. } => {
            context.state.abort.store(true, Ordering::Release);
            Err(fail(
                StoreErrorCode::BackupFailed,
                "backup aborted at the 64 MiB WAL limit",
            ))
        }
        _ => Err(fail(
            StoreErrorCode::BackupFailed,
            "WAL length is unreadable, not zero",
        )),
    }
}
fn copy(
    source: Connection,
    files: &dyn StateFiles,
    home: &Path,
    staging: &Path,
    context: &BackupContext,
    deadline: Instant,
) -> StoreResult<StoreInfo> {
    let source_path = home.join("state.db");
    connection::begin_snapshot(&source, &source_path)?;
    let info = connection::info_at(&source, &source_path)?;
    let mut destination = connection::open(
        &staging.join(PENDING),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    destination
        .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL")
        .map_err(sql)?;
    {
        let backup = Backup::new(&source, &mut destination).map_err(sql)?;
        loop {
            check(deadline)?;
            wal_limit(files, home, context)?;
            match backup.step(64).map_err(sql)? {
                StepResult::Done => break,
                StepResult::More => std::thread::yield_now(),
                StepResult::Busy | StepResult::Locked => {
                    return Err(fail(
                        StoreErrorCode::BackupFailed,
                        "online backup is busy; no partial generation published",
                    ));
                }
                _ => {
                    return Err(fail(
                        StoreErrorCode::BackupFailed,
                        "unknown SQLite backup step result",
                    ));
                }
            }
        }
    }
    source.execute_batch("ROLLBACK").map_err(sql)?;
    source.close().map_err(|(_, e)| sql(e))?;
    destination
        .execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL")
        .map_err(sql)?;
    destination.close().map_err(|(_, e)| sql(e))?;
    Ok(info)
}
fn validate(path: &Path, expected: &StoreInfo, deadline: Instant) -> StoreResult<()> {
    check(deadline)?;
    let c = connection::connect(path, false, Duration::ZERO)?;
    c.progress_handler(1000, Some(move || Instant::now() >= deadline))
        .map_err(sql)?;
    let observed = connection::info_at(&c, path)?;
    if observed.id != expected.id
        || observed.incarnation != expected.incarnation
        || observed.schema_version != expected.schema_version
        || observed.state != StoreState::Ready
        || observed.head != expected.head
    {
        return Err(fail(
            StoreErrorCode::BackupFailed,
            "independently reopened backup header/high-water differs",
        ));
    }
    let integrity: String = c
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(sql)?;
    if integrity != "ok" {
        return Err(fail(
            StoreErrorCode::BackupFailed,
            format!("backup integrity failed: {integrity}"),
        ));
    }
    let mut q = c.prepare("PRAGMA foreign_key_check").map_err(sql)?;
    if q.query([]).map_err(sql)?.next().map_err(sql)?.is_some() {
        return Err(fail(
            StoreErrorCode::BackupFailed,
            "backup foreign-key check failed",
        ));
    }
    drop(q);
    c.close().map_err(|(_, e)| sql(e))?;
    check(deadline)
}
pub(crate) fn run(
    options: &StoreOptions,
    lease: &dyn RuntimeLease,
    context: BackupContext,
    duration: Duration,
) -> StoreResult<BackupReport> {
    let deadline = Instant::now()
        .checked_add(duration)
        .ok_or_else(|| invalid("backup deadline overflow"))?;
    check(deadline)?;
    let home = &options.state_directory;
    let root = &home.join("backups");
    let staging = &home.join("staging");
    if home.join("state.db") != context.state.path {
        return Err(fail(
            StoreErrorCode::GenerationChanged,
            "backup options do not name the bound state home",
        ));
    }
    let files = lease.files();
    drop(present(files, &context.state.path)?);
    // Native retirement is also required for crash-left pending artifacts.
    let reader = SqliteReader {
        path: context.state.path.clone(),
        timeout: options.busy_timeout.min(duration),
        slots: context.state.slots.clone(),
    };
    reader
        .slots
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < 2).then_some(n + 1)
        })
        .map_err(|_| {
            fail(
                StoreErrorCode::Backpressure,
                "two finite read snapshots are already in use",
            )
        })?;
    let _slot = Slot(reader.slots.clone());
    (|| {
        let source = reader.connect()?;
        let pre = connection::info_at(&source, &reader.path)?;
        let identity = connection::validate_lease(&pre, lease, LeaseMode::Host)?;
        let pin = context.pin(&pre, &identity, &reader.path)?;
        let mut allocated_stage = None;
        let result = (|| {
            files.prepare_directory(root)?;
            files.prepare_directory(staging)?;
            let (mut index, old_hash) = read_index(files, root, &pre.id, deadline)?;
            refuse_unindexed(files, root, &index, deadline)?;
            cleanup(files, staging, deadline)?;
            let stage = files.create_staging(staging)?;
            let stage_path = stage.path.clone();
            allocated_stage = Some(stage_path.clone());
            drop(stage.file);
            // A fixed reserved pending name makes interrupted copies independently discoverable.
            files.publish_no_replace(&stage_path, &staging.join(PENDING))?;
            let copied = copy(source, files, home, staging, &context, deadline);
            pin.release_reader(); // keep the pending-generation reservation through publication/cleanup.
            let info = copied?;
            validate(&staging.join(PENDING), &info, deadline)?;
            let (bytes, hash) = digest(present(files, &staging.join(PENDING))?, deadline)?;
            let now = connection::now()?;
            let mut entropy = Sha256::new();
            entropy.update(hash);
            entropy.update(
                stage_path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .ok_or_else(|| invalid("native staging name is not ASCII"))?
                    .as_bytes(),
            );
            entropy.update(now.to_be_bytes());
            let random: [u8; 10] = entropy.finalize()[..10].try_into().map_err(invalid)?;
            let id = RecordId::from_parts(u64::try_from(now / 1000).map_err(invalid)?, random)?;
            let entry = Entry {
                id,
                store: info.id.clone(),
                incarnation: info.incarnation,
                schema: info.schema_version,
                application: connection::APP,
                through: info.head.as_ref().map(StorePosition::sequence).unwrap_or(0),
                bytes,
                sha256: hash,
                file: filename(id),
                validated: true,
            };
            let destination = root.join(&entry.file);
            files.publish_no_replace(&staging.join(PENDING), &destination)?;
            // Once the copy is published, failures name it; never delete an unknown winner.
            let published = entry.generation(root)?;
            let old = if index.generations.len() == 2 {
                Some(index.generations.remove(0))
            } else {
                None
            };
            index.generations.push(entry);
            let pointer = serde_json::to_vec(&index).map_err(invalid)?;
            let publication = (|| {
                files.replace_owned(&root.join(INDEX), old_hash, &pointer)?;
                let mut observed = Vec::new();
                present(files, &root.join(INDEX))?
                    .take(65537)
                    .read_to_end(&mut observed)
                    .map_err(invalid)?;
                if observed != pointer {
                    return Err(fail(
                        StoreErrorCode::BackupFailed,
                        "backup index publication readback differs",
                    ));
                }
                Ok(())
            })();
            if let Err(mut error) = publication {
                // The new immutable copy is retained if pointer publication may have happened.
                error.cause.push_str(&format!(
                    "; new generation retained at {}; prior generations retained",
                    published.path.display()
                ));
                return Err(error);
            }
            let mut removed = Vec::new();
            if let Some(old) = old {
                let path = root.join(&old.file);
                files.remove_owned(&path, old.sha256).map_err(|mut error| {
                    error.cause.push_str(&format!(
                        "; new generation published, oldest retained at {}",
                        path.display()
                    ));
                    error
                })?;
                removed.push(old.id);
            }
            let retained = index
                .generations
                .iter()
                .map(|e| e.generation(root))
                .collect::<StoreResult<Vec<_>>>()?;
            Ok(BackupReport {
                published,
                retained,
                removed,
            })
        })();
        let cleanup_result: StoreResult<()> = if result.is_err() {
            let cleanup_deadline = Instant::now() + Duration::from_secs(1);
            (|| {
                cleanup(files, staging, cleanup_deadline)?;
                if let Some(path) = allocated_stage {
                    remove_if_present(files, &path, cleanup_deadline)?;
                }
                Ok(())
            })()
        } else {
            Ok(())
        };
        if let Err(cleanup_error) = cleanup_result {
            return result.map_err(|mut error| {
                error.cause.push_str(&format!(
                    "; pending cleanup refused: {}",
                    cleanup_error.cause
                ));
                error
            });
        }

        result
    })()
}
