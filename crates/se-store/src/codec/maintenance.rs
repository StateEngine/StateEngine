//! Closed maintenance facts; payload text remains in payloads, never aux_data.
use super::*;
fn position(value: &StorePosition) -> Value {
    json!(value.storage_parts())
}
fn read_position(value: &Value) -> StoreResult<StorePosition> {
    let (store, incarnation, sequence): (StoreId, u64, u64) =
        serde_json::from_value(value.clone()).map_err(invalid)?;
    if incarnation == 0 || incarnation > i64::MAX as u64 || sequence > i64::MAX as u64 {
        return Err(invalid("stored position exceeds positive SQLite range"));
    }
    StorePosition::new_internal(store, incarnation, sequence)
}
fn pos_field(value: &Value, key: &str) -> StoreResult<StorePosition> {
    read_position(
        value
            .get(key)
            .ok_or_else(|| invalid("stored position missing"))?,
    )
}
fn recovered(value: &RuntimeRecoveredTransfer) -> Value {
    json!({"transfer":value.transfer,"handover_event":value.handover_event,"activated_custody_sha256":value.activated_custody_sha256,"capture_at":position(&value.capture_at),"queue_cut_sha256":value.queue_cut_sha256})
}
fn read_recovered(v: &Value) -> StoreResult<RuntimeRecoveredTransfer> {
    Ok(RuntimeRecoveredTransfer {
        transfer: field(v, "transfer")?,
        handover_event: field(v, "handover_event")?,
        activated_custody_sha256: field(v, "activated_custody_sha256")?,
        capture_at: pos_field(v, "capture_at")?,
        queue_cut_sha256: field(v, "queue_cut_sha256")?,
    })
}
fn phase(value: RuntimeHandoverPhase) -> &'static str {
    match value {
        RuntimeHandoverPhase::Prepared => "Prepared",
        RuntimeHandoverPhase::Claimed => "Claimed",
        RuntimeHandoverPhase::Finished => "Finished",
        RuntimeHandoverPhase::Aborted => "Aborted",
        RuntimeHandoverPhase::Recovered => "Recovered",
    }
}
fn read_phase(v: &Value) -> StoreResult<RuntimeHandoverPhase> {
    match v.as_str() {
        Some("Prepared") => Ok(RuntimeHandoverPhase::Prepared),
        Some("Claimed") => Ok(RuntimeHandoverPhase::Claimed),
        Some("Finished") => Ok(RuntimeHandoverPhase::Finished),
        Some("Aborted") => Ok(RuntimeHandoverPhase::Aborted),
        Some("Recovered") => Ok(RuntimeHandoverPhase::Recovered),
        _ => Err(invalid("unknown handover phase")),
    }
}
pub(super) fn metadata<T>(body: &EventBody<T>) -> StoreResult<(&'static str, Value)> {
    use EventBody::*;
    Ok(match body {
        RuntimeOwnerEstablished {
            epoch,
            generation,
            expected_owner_generation,
            expected,
            witnesses,
            recovered: recovery,
        } => (
            "runtime.owner",
            json!({"epoch":epoch,"generation":generation,"expected_owner_generation":expected_owner_generation,"expected":expected,"witnesses":witnesses,"recovered":recovery.as_deref().map(recovered)}),
        ),
        RuntimeHandoverRecorded {
            record,
            expected,
            witnesses,
        } => {
            let completion=record.completion.as_deref().map(|v|json!({"activated_custody_sha256":v.activated_custody_sha256,"capture_at":position(&v.capture_at),"queue_cut_sha256":v.queue_cut_sha256,"source_closed_sha256":v.source_closed_sha256}));
            (
                "runtime.handover",
                json!({"record":{"transfer":record.transfer,"native_nonce":record.native_nonce,"source_epoch":record.source_epoch,"successor_epoch":record.successor_epoch,"source_generation":record.source_generation,"successor_generation":record.successor_generation,"phase":phase(record.phase),"manifest_sha256":record.manifest_sha256,"frozen_at":position(&record.frozen_at),"deadline_at":record.deadline_at,"completion":completion},"expected":expected,"witnesses":witnesses}),
            )
        }
        BackupRecorded {
            generation,
            through,
            bytes,
            sha256,
            schema_version,
            witness,
        } => (
            "backup.recorded",
            json!({"generation":generation,"through":position(through),"bytes":bytes,"sha256":sha256,"schema_version":schema_version,"witness":witness}),
        ),
        TurnErased {
            target,
            erasure,
            original_bytes,
            by,
        } => (
            "turn.erased",
            json!({"target":target,"erasure":erasure,"original_bytes":original_bytes,"by":by}),
        ),
        MessageErased {
            target,
            erasure,
            original_bytes,
            by,
        } => (
            "message.erased",
            json!({"target":target,"erasure":erasure,"original_bytes":original_bytes,"by":by}),
        ),
        ErasureRequested {
            erasure,
            targets,
            residuals,
        } => (
            "erasure.requested",
            json!({"erasure":erasure,"targets":targets.iter().map(|v|json!({"event":v.event,"expected":v.expected})).collect::<Vec<_>>(),"residuals":residuals.iter().map(|v|json!({"custodian":v.custodian,"location":v.location,"reason":v.reason})).collect::<Vec<_>>()}),
        ),
        ErasureCompleted {
            erasure,
            manifest_sha256,
            incarnation,
            witnesses,
        } => (
            "erasure.completed",
            json!({"erasure":erasure,"manifest_sha256":manifest_sha256,"incarnation":incarnation,"witnesses":witnesses}),
        ),
        RecoveryRecorded {
            recovery,
            request_key,
            source,
            source_incarnation,
            source_artifact,
            target,
            target_incarnation,
            backup,
            restored_through,
            loss,
            schema_version,
            witnesses,
            ..
        } => (
            "recovery.recorded",
            json!({"recovery":recovery,"request_key":request_key,"source":source,"source_incarnation":source_incarnation,"source_artifact":source_artifact,"target":target,"target_incarnation":target_incarnation,"backup":backup,"restored_through":position(restored_through),"loss":{"after":position(&loss.after),"prior_head":loss.prior_head.as_ref().map(position)},"schema_version":schema_version,"witnesses":witnesses}),
        ),
        _ => return Err(invalid("maintenance codec dispatch")),
    })
}
pub(super) fn body(c: &Connection, seq: i64, kind: &str) -> StoreResult<EventBody<StoredText>> {
    use EventBody::*;
    let v = facts(c, seq)?;
    Ok(match kind {
        "runtime.owner" => RuntimeOwnerEstablished {
            epoch: field(&v, "epoch")?,
            generation: field(&v, "generation")?,
            expected_owner_generation: field(&v, "expected_owner_generation")?,
            expected: field(&v, "expected")?,
            witnesses: field(&v, "witnesses")?,
            recovered: v
                .get("recovered")
                .filter(|v| !v.is_null())
                .map(read_recovered)
                .transpose()?
                .map(Box::new),
        },
        "runtime.handover" => {
            let r = v
                .get("record")
                .ok_or_else(|| invalid("handover record missing"))?;
            let completion = r
                .get("completion")
                .filter(|v| !v.is_null())
                .map(|v| -> StoreResult<_> {
                    Ok(Box::new(RuntimeHandoverCompletion {
                        activated_custody_sha256: field(v, "activated_custody_sha256")?,
                        capture_at: pos_field(v, "capture_at")?,
                        queue_cut_sha256: field(v, "queue_cut_sha256")?,
                        source_closed_sha256: field(v, "source_closed_sha256")?,
                    }))
                })
                .transpose()?;
            RuntimeHandoverRecorded {
                record: Box::new(RuntimeHandoverRecord {
                    transfer: field(r, "transfer")?,
                    native_nonce: field(r, "native_nonce")?,
                    source_epoch: field(r, "source_epoch")?,
                    successor_epoch: field(r, "successor_epoch")?,
                    source_generation: field(r, "source_generation")?,
                    successor_generation: field(r, "successor_generation")?,
                    phase: read_phase(
                        r.get("phase")
                            .ok_or_else(|| invalid("handover phase missing"))?,
                    )?,
                    manifest_sha256: field(r, "manifest_sha256")?,
                    frozen_at: pos_field(r, "frozen_at")?,
                    deadline_at: field(r, "deadline_at")?,
                    completion,
                }),
                expected: field(&v, "expected")?,
                witnesses: field(&v, "witnesses")?,
            }
        }
        "backup.recorded" => BackupRecorded {
            generation: field(&v, "generation")?,
            through: pos_field(&v, "through")?,
            bytes: field(&v, "bytes")?,
            sha256: field(&v, "sha256")?,
            schema_version: field(&v, "schema_version")?,
            witness: field(&v, "witness")?,
        },
        "turn.erased" => TurnErased {
            target: field(&v, "target")?,
            erasure: field(&v, "erasure")?,
            original_bytes: field(&v, "original_bytes")?,
            by: field(&v, "by")?,
        },
        "message.erased" => MessageErased {
            target: field(&v, "target")?,
            erasure: field(&v, "erasure")?,
            original_bytes: field(&v, "original_bytes")?,
            by: field(&v, "by")?,
        },
        "erasure.requested" => {
            let targets: Vec<Value> = field(&v, "targets")?;
            let residuals: Vec<Value> = field(&v, "residuals")?;
            if targets.len() > 60 || residuals.len() > 64 {
                return Err(invalid("stored erasure inventory exceeds bounds"));
            }
            ErasureRequested {
                erasure: field(&v, "erasure")?,
                targets: targets
                    .iter()
                    .map(|v| -> StoreResult<_> {
                        Ok(EraseTarget {
                            event: field(v, "event")?,
                            expected: field(v, "expected")?,
                        })
                    })
                    .collect::<StoreResult<_>>()?,
                residuals: residuals
                    .iter()
                    .map(|v| -> StoreResult<_> {
                        Ok(ResidualCopy {
                            custodian: field(v, "custodian")?,
                            location: field(v, "location")?,
                            reason: field(v, "reason")?,
                        })
                    })
                    .collect::<StoreResult<_>>()?,
            }
        }
        "erasure.completed" => ErasureCompleted {
            erasure: field(&v, "erasure")?,
            manifest_sha256: field(&v, "manifest_sha256")?,
            incarnation: field(&v, "incarnation")?,
            witnesses: field(&v, "witnesses")?,
        },
        "recovery.recorded" => {
            let loss = v
                .get("loss")
                .ok_or_else(|| invalid("recovery loss bounds missing"))?;
            RecoveryRecorded {
                recovery: field(&v, "recovery")?,
                request_key: field(&v, "request_key")?,
                source: field(&v, "source")?,
                source_incarnation: field(&v, "source_incarnation")?,
                source_artifact: field(&v, "source_artifact")?,
                target: field(&v, "target")?,
                target_incarnation: field(&v, "target_incarnation")?,
                backup: field(&v, "backup")?,
                restored_through: pos_field(&v, "restored_through")?,
                loss: RestoreLoss {
                    after: pos_field(loss, "after")?,
                    prior_head: loss
                        .get("prior_head")
                        .filter(|v| !v.is_null())
                        .map(read_position)
                        .transpose()?,
                },
                schema_version: field(&v, "schema_version")?,
                witnesses: field(&v, "witnesses")?,
                receipt: stored_text(c, seq, "restore-receipt")?,
            }
        }
        _ => return Err(invalid("maintenance decode dispatch")),
    })
}
