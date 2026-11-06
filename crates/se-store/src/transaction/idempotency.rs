//! Caller-key resolution is shared by ordinary and first-binding replay.
use super::*;
struct StoredRequest {
    op: Vec<u8>,
    digest: Option<Vec<u8>>,
    version: u16,
    erased: bool,
}
pub(crate) fn lookup(
    c: &Connection,
    batch: &AtomicBatch,
    info: &StoreInfo,
) -> StoreResult<Option<CommitReceipt>> {
    let scope = scope_key(c, &batch.admission.scope, false)?;
    let actor = key(
        c,
        batch.admission.actor.kind(),
        batch.admission.actor.wire(),
        if batch.admission.actor.kind() == "human" {
            &[0]
        } else {
            &scope
        },
        false,
    )?;
    if let Some(request) = &batch.request {
        let found:Option<StoredRequest>=c.query_row("SELECT operation_id,fingerprint,fingerprint_codec,erased FROM operations WHERE scope_key=? AND actor_id=?
                    AND request_key=?",crate::sql_value::sql_params![scope,actor,request.key.as_str()],|r|Ok(StoredRequest { op:crate::sql_value::value(r,0)?,digest:crate::sql_value::value(r,1)?,version:crate::sql_value::value(r,2)?,erased:crate::sql_value::value(r,3)? })).optional().map_err(sql)?;
        if let Some(StoredRequest {
            op,
            digest,
            version,
            erased,
        }) = found
        {
            if erased {
                return Err(fail(
                    StoreErrorCode::ContentErased,
                    "caller key's content-derived fingerprint was erased",
                ));
            }
            if version != 1 {
                return Err(fail(
                    StoreErrorCode::VersionUnsupported,
                    "retained intent codec is unsupported",
                ));
            }
            if digest
                != Some(
                    fingerprint(
                        &scope,
                        &actor,
                        batch.admission.actor.kind(),
                        &request.intent,
                    )?
                    .to_vec(),
                )
                || version != request.intent.codec_version
            {
                let original = receipt(c, &op, info, Some(request.key.clone()))?;
                let mut error = fail(
                    StoreErrorCode::IdempotencyKeyReused,
                    "caller key already owns a different semantic intent",
                );
                error.detail = StoreDetail::Request {
                    scope: batch.admission.scope.clone(),
                    actor: batch.admission.actor.clone(),
                    key: request.key.clone(),
                    original_event: Some(original.primary_event),
                };
                return Err(error);
            }
            let mut retained = receipt(c, &op, info, Some(request.key.clone()))?;
            retained.state = CommitState::Replayed;
            return Ok(Some(retained));
        }
    }
    Ok(None)
}
pub(super) fn fingerprint(
    scope: &[u8],
    actor: &[u8],
    actor_kind: &str,
    intent: &IntentDigest,
) -> StoreResult<[u8; 32]> {
    if intent.codec_version != 1 {
        return Err(fail(
            StoreErrorCode::VersionUnsupported,
            "unsupported intent codec",
        ));
    }
    if intent.operation.is_empty()
        || intent.operation.len() > 128
        || !intent
            .operation
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(invalid("unsupported intent codec or operation label"));
    }
    let mut hash = Sha256::new();
    hash.update(b"SEOP\0v1\0");
    for value in [
        scope,
        actor_kind.as_bytes(),
        actor,
        intent.operation.as_bytes(),
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    hash.update(intent.codec_version.to_be_bytes());
    hash.update(intent.sha256);
    Ok(hash.finalize().into())
}
