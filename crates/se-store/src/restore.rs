//! Owner restore from an automatic backup. The live store is copied to a
//! preserved name and verified before anything is removed; it is never repaired
//! or salvaged. A verified copy of the backup then takes its place under the
//! target identity and a new incarnation, with a keyed recovery fact.
use crate::{connection, error::*, open::SqliteHost, *};
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
    staged.file.sync_all().map_err(invalid)?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, to)
}
/// The backup copy must still match its record and open as a sound store.
fn verify_backup(
    files: &dyn StateFiles,
    backup: &BackupGeneration,
    deadline: Instant,
) -> StoreResult<()> {
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
    if &info.id != store
        || info.incarnation != incarnation
        || info.head.as_ref() != Some(&backup.through)
        || integrity != "ok"
    {
        return Err(restore_failed(
            "the backup generation does not open as the store it records",
        ));
    }
    Ok(())
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
fn receipt_json(fields: &[(&str, serde_json::Value)]) -> String {
    let mut value = serde_json::Map::new();
    value.insert("schema".into(), "se.restore/v1".into());
    for (k, v) in fields {
        value.insert((*k).into(), v.clone());
    }
    serde_json::Value::Object(value).to_string()
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
    verify_backup(files, &backup, deadline)?;
    let mut random = [0u8; 10];
    random.copy_from_slice(&se_proc::random_secret().map_err(invalid)?.expose()[..10]);
    let recovery = RecordId::from_parts(
        u64::try_from(connection::now()? / 1000).map_err(invalid)?,
        random,
    )?;
    let preserved = preserve(files, home, &recovery, deadline)?;
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
    let source_incarnation = preserved.info.as_ref().map(|i| i.incarnation);
    let target_incarnation = backup_incarnation.max(source_incarnation.unwrap_or(0)) + 1;
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
    let position = |p: &StorePosition| serde_json::json!(p.storage_parts());
    let receipt = receipt_json(&[
        ("request_key", request.key.as_str().into()),
        (
            "recovery",
            uuid::Uuid::from_bytes(*recovery.as_bytes())
                .to_string()
                .into(),
        ),
        (
            "backup",
            uuid::Uuid::from_bytes(*backup.id.as_bytes())
                .to_string()
                .into(),
        ),
        (
            "source",
            preserved
                .info
                .as_ref()
                .map(|i| i.id.as_str().to_string())
                .into(),
        ),
        ("source_incarnation", source_incarnation.into()),
        (
            "preserved",
            preserved
                .evidence
                .path
                .as_ref()
                .map(|p| p.to_local().map(|l| l.display().to_string()))
                .transpose()
                .map_err(invalid)?
                .into(),
        ),
        ("target", target.as_str().into()),
        ("target_incarnation", target_incarnation.into()),
        ("restored_through", position(&restored_through)),
        ("lost_after", position(&loss.after)),
        ("prior_head", loss.prior_head.as_ref().map(position).into()),
        ("state", "restored".into()),
    ]);
    let event = EventId::from_parts(
        u64::try_from(connection::now()? / 1000).map_err(invalid)?,
        random,
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
                origin: target.clone(),
                door: Door::Cli,
                occurred_at_us: connection::now()?,
                cause: None,
                supersedes: None,
            },
            body: EventBody::RecoveryRecorded {
                recovery,
                request_key: request.key.clone(),
                source: preserved.info.as_ref().map(|i| i.id.clone()),
                source_incarnation,
                source_artifact: preserved.evidence,
                target: target.clone(),
                target_incarnation,
                backup: backup.id,
                restored_through: restored_through.clone(),
                loss: loss.clone(),
                schema_version: backup.schema_version,
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
    Ok(RestoreOutcome {
        receipt: RestoreReceipt {
            original_receipt: receipt,
            request_key: request.key.clone(),
            event,
            backup: backup.id,
            source: preserved.info.as_ref().map(|i| i.id.clone()),
            source_incarnation,
            target,
            target_incarnation,
            restored_through,
            loss,
            writer: committed.writer,
        },
        host,
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
