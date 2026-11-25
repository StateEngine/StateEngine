//! Owner restore from an automatic backup. The live store is copied to a
//! preserved name and verified before anything is removed; it is never repaired
//! or salvaged. A verified copy of the backup then takes its place under the
//! target identity and a new incarnation, with a keyed recovery fact.
use crate::{connection, error::*, identity, open::SqliteHost, *};
use rusqlite::OptionalExtension;
use se_types::EventId;
use sha2::{Digest, Sha256};
use std::{
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const SIDECARS: [&str; 3] = ["", "-wal", "-shm"];

fn restore_failed(cause: impl Into<String>) -> Box<StoreError> {
    fail(StoreErrorCode::RecoveryIncomplete, cause)
}
fn check(deadline: Instant) -> StoreResult<()> {
    if Instant::now() >= deadline {
        return Err(restore_failed("restore deadline exhausted"));
    }
    Ok(())
}
fn digest(mut file: std::fs::File, deadline: Instant) -> StoreResult<(u64, [u8; 32])> {
    let (mut bytes, mut hash, mut buffer) = (0u64, Sha256::new(), vec![0u8; 65536]);
    loop {
        check(deadline)?;
        let count = file.read(&mut buffer).map_err(invalid)?;
        if count == 0 {
            return Ok((bytes, hash.finalize().into()));
        }
        bytes += count as u64;
        hash.update(&buffer[..count]);
    }
}
fn present(files: &dyn StateFiles, path: &Path) -> StoreResult<Option<std::fs::File>> {
    match files.readback(path)? {
        se_types::Read::Present { value } => Ok(Some(value)),
        se_types::Read::Absent { .. } => Ok(None),
        _ => Err(restore_failed(format!(
            "{} is unreadable, not absent",
            path.display()
        ))),
    }
}
/// Copy one file into a fresh staging file, then publish it at `to`.
fn copy(
    files: &dyn StateFiles,
    from: std::fs::File,
    staging: &Path,
    to: &Path,
    deadline: Instant,
) -> StoreResult<()> {
    let mut staged = files.create_staging(staging)?;
    let mut source = from;
    let mut buffer = vec![0u8; 65536];
    loop {
        check(deadline)?;
        let count = source.read(&mut buffer).map_err(invalid)?;
        if count == 0 {
            break;
        }
        staged.file.write_all(&buffer[..count]).map_err(invalid)?;
    }
    // Publication flushes the staged data before moving its name.
    drop(staged.file);
    files.publish_no_replace(&staged.path, to)
}
/// The backup copy must still match its record and open as a sound store.
/// Returns the owners it registers.
fn verify_backup(
    files: &dyn StateFiles,
    backup: &BackupGeneration,
    deadline: Instant,
) -> StoreResult<Vec<se_types::HumanId>> {
    let file = present(files, &backup.path)?
        .ok_or_else(|| restore_failed("the backup generation is absent"))?;
    if digest(file, deadline)? != (backup.bytes, backup.sha256) {
        return Err(restore_failed(
            "the backup generation no longer matches its recorded digest",
        ));
    }
    let c = connection::connect(&backup.path, false, Duration::ZERO)?;
    let info = connection::info_at(&c, &backup.path)?;
    let (store, incarnation, _) = backup.through.storage_parts();
    let integrity: String = c
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(sql)?;
    // A backup of a store without events records through-sequence 0 for its absent head.
    let same_head = match &info.head {
        Some(head) => head == &backup.through,
        None => backup.through.sequence() == 0,
    };
    if &info.id != store || info.incarnation != incarnation || !same_head || integrity != "ok" {
        return Err(restore_failed(
            "the backup generation does not open as the store it records",
        ));
    }
    let mut owners = Vec::new();
    let mut q = c
        .prepare("SELECT human_id FROM owners ORDER BY human_id LIMIT 17")
        .map_err(sql)?;
    let mut rows = q.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        let id: Vec<u8> = row.get(0).map_err(sql)?;
        owners.push(
            identity::wire(&c, "human", &id, &[0])?
                .parse()
                .map_err(invalid)?,
        );
    }
    if owners.is_empty() && backup.through.sequence() == 0 {
        return Err(restore_failed(
            "the backup was taken before any history was saved and holds nothing to restore",
        ));
    }
    if owners.is_empty() || owners.len() > 16 {
        return Err(restore_failed(
            "the backup generation has no owner registration",
        ));
    }
    Ok(owners)
}
/// The owners a verified backup registers, read before any restore.
pub(crate) fn owners(
    options: &StoreOptions,
    files: &dyn StateFiles,
    backup: &BackupGeneration,
) -> StoreResult<Vec<se_types::HumanId>> {
    let deadline = Instant::now() + options.busy_timeout.max(Duration::from_secs(300));
    verify_backup(files, backup, deadline)
}
struct Preserved {
    info: Option<StoreInfo>,
    evidence: SourceEvidence,
}
/// Copy the live database and its sidecars to a preserved name and verify each
/// copy before the originals are removed. A missing live store is preserved as
/// absent; an unreadable one is still copied byte for byte.
fn preserve(
    files: &dyn StateFiles,
    home: &Path,
    recovery: &RecordId,
    deadline: Instant,
) -> StoreResult<Preserved> {
    let live = home.join("state.db");
    let info = connection::connect(&live, false, Duration::ZERO)
        .and_then(|c| connection::info_at(&c, &live))
        .ok();
    let folder = home.join("preserved");
    files.prepare_directory(&folder)?;
    let name = format!("state-{}.db", uuid::Uuid::from_bytes(*recovery.as_bytes()));
    let mut evidence = SourceEvidence {
        path: None,
        incarnation: Vec::new(),
        offset: 0,
        length: 0,
        sha256: None,
    };
    let mut originals = Vec::new();
    for sidecar in SIDECARS {
        let from = home.join(format!("state.db{sidecar}"));
        let Some(file) = present(files, &from)? else {
            continue;
        };
        let (bytes, hash) = digest(file, deadline)?;
        let to = folder.join(format!("{name}{sidecar}"));
        let file = present(files, &from)?
            .ok_or_else(|| restore_failed("the live store disappeared while being preserved"))?;
        copy(files, file, &home.join("staging"), &to, deadline)?;
        let copied =
            present(files, &to)?.ok_or_else(|| restore_failed("the preserved copy is absent"))?;
        if digest(copied, deadline)? != (bytes, hash) {
            return Err(restore_failed(format!(
                "the preserved copy of {} differs; the live store was kept",
                from.display()
            )));
        }
        if sidecar.is_empty() {
            evidence = SourceEvidence {
                path: Some(se_types::NativePath::from_local(to).map_err(invalid)?),
                incarnation: info
                    .as_ref()
                    .map(|i| i.incarnation.to_be_bytes().to_vec())
                    .unwrap_or_default(),
                offset: 0,
                length: bytes,
                sha256: Some(hash),
            };
        }
        originals.push((from, hash));
    }
    // Every copy is verified before any original is removed.
    for (from, hash) in originals {
        files.remove_owned(&from, hash)?;
    }
    Ok(Preserved { info, evidence })
}
/// Bind the restored copy to its target identity and a new incarnation, so no
/// writer of the replaced store can append to it.
fn rebind(path: &Path, target: &StoreId, incarnation: u64) -> StoreResult<()> {
    let c = connection::connect(path, true, Duration::from_secs(5))?;
    let bytes = crate::identity::canonical(target.as_str())
        .ok_or_else(|| invalid("canonical target store ID required"))?;
    let changed = c
        .execute(
            "UPDATE store_info SET store_id=?,incarnation=?,state='ready' WHERE singleton=1",
            crate::sql_value::sql_params![bytes, incarnation],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(restore_failed("the restored copy has no store header"));
    }
    c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .map_err(sql)?;
    Ok(())
}
/// The facts one restore records, in its receipt and in its recovery event.
struct Recovery {
    id: RecordId,
    random: [u8; 10],
    preserved: Preserved,
    backup: BackupGeneration,
    target: StoreId,
    target_incarnation: u64,
    restored_through: StorePosition,
    loss: RestoreLoss,
}
impl Recovery {
    fn source(&self) -> Option<StoreId> {
        self.preserved.info.as_ref().map(|i| i.id.clone())
    }
    fn source_incarnation(&self) -> Option<u64> {
        self.preserved.info.as_ref().map(|i| i.incarnation)
    }
    fn receipt(&self, request: &RequestIdentity) -> StoreResult<String> {
        let position = |p: &StorePosition| serde_json::json!(p.storage_parts());
        let uuid = |bytes: &[u8; 16]| uuid::Uuid::from_bytes(*bytes).to_string();
        let preserved = (self.preserved.evidence.path.as_ref())
            .map(|p| p.to_local().map(|l| l.display().to_string()))
            .transpose()
            .map_err(invalid)?;
        Ok(serde_json::json!({
            "schema": "se.restore/v1",
            "request_key": request.key.as_str(),
            "recovery": uuid(self.id.as_bytes()),
            "backup": uuid(self.backup.id.as_bytes()),
            "source": self.source().map(|id| id.as_str().to_string()),
            "source_incarnation": self.source_incarnation(),
            "preserved": preserved,
            "target": self.target.as_str(),
            "target_incarnation": self.target_incarnation,
            "restored_through": position(&self.restored_through),
            "lost_after": position(&self.loss.after),
            "prior_head": self.loss.prior_head.as_ref().map(position),
            "state": "restored",
        })
        .to_string())
    }
}
pub(crate) fn restore(
    options: &StoreOptions,
    backup: BackupGeneration,
    request: &RequestIdentity,
    target: StoreId,
    admission: &Admission,
    lease: &dyn RuntimeLease,
) -> StoreResult<RestoreOutcome<SqliteHost>> {
    if lease.identity()?.mode != LeaseMode::Host || !matches!(admission.actor, Actor::Human(_)) {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "restore needs the owner under the exclusive runtime lease",
        ));
    }
    let deadline = Instant::now() + options.busy_timeout.max(Duration::from_secs(300));
    let (files, home) = (lease.files(), &options.state_directory);
    files.prepare_directory(&home.join("staging"))?;
    let owners = verify_backup(files, &backup, deadline)?;
    if !matches!(&admission.actor, Actor::Human(owner) if owners.contains(owner)) {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "the backup does not register this owner",
        ));
    }
    let mut random = [0u8; 10];
    random.copy_from_slice(&se_proc::random_secret().map_err(invalid)?.expose()[..10]);
    let id = RecordId::from_parts(
        u64::try_from(connection::now()? / 1000).map_err(invalid)?,
        random,
    )?;
    let preserved = preserve(files, home, &id, deadline)?;
    let restored: PathBuf = home.join("state.db");
    let copy_source = present(files, &backup.path)?
        .ok_or_else(|| restore_failed("the backup generation is absent"))?;
    copy(
        files,
        copy_source,
        &home.join("staging"),
        &restored,
        deadline,
    )?;
    let (_, backup_incarnation, _) = backup.through.storage_parts();
    // An unreadable source cannot say its incarnation. The current time in
    // seconds then stands in: it exceeds any incarnation an earlier restore
    // assigned, so a second restore from the same backup never reuses one.
    let source_incarnation = match &preserved.info {
        Some(info) => info.incarnation,
        None => u64::try_from(connection::now()? / 1_000_000).map_err(invalid)?,
    };
    let target_incarnation = backup_incarnation.max(source_incarnation) + 1;
    rebind(&restored, &target, target_incarnation)?;
    let mut host = match SqliteFactory::open_host(options, lease)? {
        se_types::Read::Present { value } => value,
        _ => return Err(restore_failed("the restored store did not open")),
    };
    let restored_through = StorePosition::new_internal(
        target.clone(),
        target_incarnation,
        backup.through.sequence(),
    )?;
    let loss = RestoreLoss {
        after: restored_through.clone(),
        prior_head: preserved.info.as_ref().and_then(|i| i.head.clone()),
    };
    let recovery = Recovery {
        id,
        random,
        preserved,
        backup,
        target,
        target_incarnation,
        restored_through,
        loss,
    };
    let receipt = record(&mut host, recovery, request, admission)?;
    Ok(RestoreOutcome { receipt, host })
}
/// Commit the keyed recovery fact that carries the receipt verbatim.
fn record(
    host: &mut SqliteHost,
    recovery: Recovery,
    request: &RequestIdentity,
    admission: &Admission,
) -> StoreResult<RestoreReceipt> {
    let receipt = recovery.receipt(request)?;
    let (source, source_incarnation) = (recovery.source(), recovery.source_incarnation());
    let event = EventId::from_parts(
        u64::try_from(connection::now()? / 1000).map_err(invalid)?,
        recovery.random,
    )
    .map_err(invalid)?;
    let info = connection::info(&host.engine.db)?;
    let batch = AtomicBatch {
        expected_incarnation: info.incarnation,
        admission: Admission {
            scope: Scope::Registry,
            session: None,
            generation: host.engine.identity.generation,
            ..admission.clone()
        },
        request: Some(request.clone()),
        events: vec![NewEvent {
            header: EventHeader {
                event: event.clone(),
                scope: Scope::Registry,
                actor: admission.actor.clone(),
                session: None,
                origin: recovery.target.clone(),
                door: Door::Cli,
                occurred_at_us: connection::now()?,
                cause: None,
                supersedes: None,
            },
            body: EventBody::RecoveryRecorded {
                recovery: recovery.id,
                request_key: request.key.clone(),
                source: source.clone(),
                source_incarnation,
                source_artifact: recovery.preserved.evidence,
                target: recovery.target.clone(),
                target_incarnation: recovery.target_incarnation,
                backup: recovery.backup.id,
                restored_through: recovery.restored_through.clone(),
                loss: recovery.loss.clone(),
                schema_version: recovery.backup.schema_version,
                witnesses: Vec::new(),
                receipt: InputText::Inline(receipt.clone()),
            },
        }],
        import_checkpoint: None,
    };
    let (mut results, _) = host.engine.group(vec![batch], true)?;
    let committed = results
        .pop()
        .ok_or_else(|| invalid("recovery commit returned no receipt"))??;
    Ok(RestoreReceipt {
        original_receipt: receipt,
        request_key: request.key.clone(),
        event,
        backup: recovery.backup.id,
        source,
        source_incarnation,
        target: recovery.target,
        target_incarnation: recovery.target_incarnation,
        restored_through: recovery.restored_through,
        loss: recovery.loss,
        writer: committed.writer,
    })
}
/// The receipt a key already published, verbatim; absent before any restore.
pub(crate) fn receipt(
    options: &StoreOptions,
    request: &RequestIdentity,
    admission: &Admission,
) -> StoreResult<se_types::Read<RestoreReceipt>> {
    let path = options.state_directory.join("state.db");
    let c = connection::connect(&path, false, options.busy_timeout)?;
    let info = connection::info_at(&c, &path)?;
    let actor = crate::identity::key(
        &c,
        admission.actor.kind(),
        admission.actor.wire(),
        &[0],
        false,
    )?;
    let scope = crate::identity::scope_key(&c, &Scope::Registry, false)?;
    let seq: Option<i64> = c
        .query_row(
            "SELECT e.seq FROM operations o JOIN events e ON e.operation_id=o.operation_id WHERE o.scope_key=? AND o.actor_id=? AND o.request_key=? AND e.kind='recovery.recorded'",
            crate::sql_value::sql_params![scope, actor, request.key.as_str()],
            |r| crate::sql_value::value(r, 0),
        )
        .optional()
        .map_err(sql)?;
    let Some(seq) = seq else {
        return Ok(se_types::Read::Absent {
            checked: format!(
                "no restore was published for this request key in {}",
                path.display()
            ),
        });
    };
    let event = crate::read::load_event(&c, seq, &info)?;
    let EventBody::RecoveryRecorded {
        request_key,
        source,
        source_incarnation,
        target,
        target_incarnation,
        backup,
        restored_through,
        loss,
        receipt: StoredText::Present(text),
        ..
    } = event.body
    else {
        return Err(restore_failed(
            "the published recovery fact has no complete receipt",
        ));
    };
    Ok(se_types::Read::Present {
        value: RestoreReceipt {
            original_receipt: text,
            request_key,
            event: event.header.event,
            backup,
            source,
            source_incarnation,
            target,
            target_incarnation,
            restored_through,
            loss,
            writer: event.writer,
        },
    })
}
