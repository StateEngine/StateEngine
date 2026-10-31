use crate::{apply, codec, connection, error::*, identity::*, *};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
pub(crate) struct Engine {
    pub db: Connection,
    pub identity: LeaseIdentity,
    pub poisoned: bool,
}
#[derive(Default, Clone, Debug)]
pub(crate) struct Phases {
    pub transaction: Duration,
    pub sync: Duration,
    pub checkpoint: Duration,
}
impl Engine {
    pub(crate) fn group(
        &mut self,
        batches: Vec<AtomicBatch>,
        maintenance: bool,
    ) -> StoreResult<(Vec<StoreResult<CommitReceipt>>, Phases)> {
        let result = self.group_inner(batches, maintenance);
        if result.is_err() {
            self.rollback();
        }
        result
    }
    fn group_inner(
        &mut self,
        batches: Vec<AtomicBatch>,
        maintenance: bool,
    ) -> StoreResult<(Vec<StoreResult<CommitReceipt>>, Phases)> {
        if self.poisoned {
            return Err(fail(
                StoreErrorCode::WriterClosed,
                "writer closed after an indeterminate transaction",
            ));
        }
        if batches.is_empty() {
            return Ok((Vec::new(), Phases::default()));
        }
        let full = batches
            .iter()
            .flat_map(|b| &b.events)
            .any(|e| security(&e.body));
        self.db
            .pragma_update(None, "synchronous", if full { "FULL" } else { "NORMAL" })
            .map_err(sql)?;
        let setting: i64 = self
            .db
            .query_row("PRAGMA synchronous", [], |r| crate::sql_value::value(r, 0))
            .map_err(sql)?;
        if setting != if full { 2 } else { 1 } {
            self.poisoned = true;
            return Err(fail(
                StoreErrorCode::PragmaRefused,
                "synchronous readback differs",
            ));
        }
        let recorded = connection::now()?;
        let started = Instant::now();
        self.db.execute_batch("BEGIN IMMEDIATE").map_err(sql)?;
        let info = match connection::info(&self.db) {
            Ok(i) => i,
            Err(e) => {
                self.rollback();
                return Err(e);
            }
        };
        if !maintenance {
            let fence: Option<(u64, Option<String>)> = self
                .db
                .query_row(
                    "SELECT owner_generation,phase FROM runtime_owner WHERE singleton=1",
                    [],
                    |r| {
                        Ok((
                            crate::sql_value::value(r, 0)?,
                            crate::sql_value::value(r, 1)?,
                        ))
                    },
                )
                .optional()
                .map_err(sql)?;
            let valid = match (self.identity.mode, fence) {
                (LeaseMode::Host, Some((g, phase))) => {
                    g == self.identity.generation
                        && !matches!(phase.as_deref(), Some("Prepared" | "Claimed"))
                }
                (LeaseMode::DirectClient, Some((_, phase))) => {
                    !matches!(phase.as_deref(), Some("Prepared" | "Claimed"))
                }
                (LeaseMode::DirectClient, None) => true,
                _ => false,
            };
            if !valid {
                self.rollback();
                return Err(fail(
                    StoreErrorCode::GenerationChanged,
                    "runtime owner generation/fence does not permit ordinary writes",
                ));
            }
        }
        let mut results = Vec::with_capacity(batches.len());
        for batch in batches {
            if let Err(e) = self.db.execute_batch("SAVEPOINT operation") {
                self.rollback();
                return Err(sql(e));
            }
            let result = self.append(batch, &info, recorded, full, maintenance);
            if result.is_err() {
                if let Err(e) = self
                    .db
                    .execute_batch("ROLLBACK TO operation; RELEASE operation")
                {
                    self.poisoned = true;
                    self.rollback();
                    return Err(sql(e));
                }
            } else if let Err(e) = self.db.execute_batch("RELEASE operation") {
                self.rollback();
                return Err(sql(e));
            }
            results.push(result);
        }
        let transaction = started.elapsed();
        let commit = Instant::now();
        if let Err(e) = self.db.execute_batch("COMMIT") {
            let mapped = sql(e);
            let unknown = !self.db.is_autocommit()
                || !matches!(mapped.code, StoreErrorCode::Busy | StoreErrorCode::DiskFull);
            self.rollback();
            self.poisoned = true;
            let code = if unknown {
                StoreErrorCode::CommitOutcomeUnknown
            } else {
                mapped.code
            };
            for r in &mut results {
                if r.is_ok() {
                    *r = Err(fail(
                        code,
                        format!("COMMIT not acknowledged: {}", mapped.cause),
                    ))
                }
            }
            return Ok((
                results,
                Phases {
                    transaction,
                    sync: commit.elapsed(),
                    checkpoint: Duration::ZERO,
                },
            ));
        }
        let sync = commit.elapsed();
        // SQLite auto-checkpoint is disabled during the COMMIT measurement so its
        // separate PASSIVE call is timed here; both routes use the 256-page policy.
        let checkpoint = Instant::now();
        let checkpoint_result = self.checkpoint_due();
        let checkpoint = checkpoint.elapsed();
        if let Err(e) = checkpoint_result {
            self.poisoned = true;
            return Err(fail(
                StoreErrorCode::CommitOutcomeUnknown,
                format!("committed; checkpoint failed: {}", e.cause),
            ));
        }
        Ok((
            results,
            Phases {
                transaction,
                sync,
                checkpoint,
            },
        ))
    }
    fn rollback(&mut self) {
        if !self.db.is_autocommit() && self.db.execute_batch("ROLLBACK").is_err() {
            self.poisoned = true
        }
    }
    fn checkpoint_due(&self) -> StoreResult<()> {
        // PRAGMA PASSIVE never waits for a reader; the live WAL is never removed.
        let (_, log, done): (i64, i64, i64) = self
            .db
            .query_row("PRAGMA wal_checkpoint(NOOP)", [], |r| {
                Ok((
                    crate::sql_value::value(r, 0)?,
                    crate::sql_value::value(r, 1)?,
                    crate::sql_value::value(r, 2)?,
                ))
            })
            .map_err(sql)?;
        if log >= 256 && log > done {
            let _: (i64, i64, i64) = self
                .db
                .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
                    Ok((
                        crate::sql_value::value(r, 0)?,
                        crate::sql_value::value(r, 1)?,
                        crate::sql_value::value(r, 2)?,
                    ))
                })
                .map_err(sql)?;
        }
        if log == -1 && done == -1 {
            return Ok(());
        }
        if log < 0 || done < 0 {
            return Err(fail(
                StoreErrorCode::Unreadable,
                "WAL checkpoint did not report its frame count",
            ));
        }
        Ok(())
    }
    fn append(
        &self,
        batch: AtomicBatch,
        info: &StoreInfo,
        recorded: i64,
        full: bool,
        maintenance: bool,
    ) -> StoreResult<CommitReceipt> {
        if batch.events.is_empty() || batch.events.len() > 64 || batch.import_checkpoint.is_some() {
            return Err(invalid(
                "wave-1 batch needs 1..64 events and no import checkpoint",
            ));
        }
        let scope = scope_key(&self.db, &batch.admission.scope, true)?;
        let actor = key(
            &self.db,
            batch.admission.actor.kind(),
            batch.admission.actor.wire(),
            if batch.admission.actor.kind() == "human" {
                &[0]
            } else {
                &scope
            },
            true,
        )?;
        for e in &batch.events {
            if e.header.scope != batch.admission.scope
                || e.header.actor != batch.admission.actor
                || e.header.session != batch.admission.session
                || e.header.origin != info.id
            {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "event scope/actor/session/origin differs from admitted batch",
                ));
            }
        }
        if let Some(request) = &batch.request {
            let found:Option<(Vec<u8>,Vec<u8>,u16)>=self.db.query_row("SELECT operation_id,fingerprint,fingerprint_codec FROM operations WHERE scope_key=? AND actor_id=? AND request_key=? AND erased=0",crate::sql_value::sql_params![scope,actor,request.key.as_str()],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?))).optional().map_err(sql)?;
            if let Some((op, digest, version)) = found {
                if digest != request.intent.sha256 || version != request.intent.codec_version {
                    let original = receipt(&self.db, &op, info, Some(request.key.clone()))?;
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
                let mut retained = receipt(&self.db, &op, info, Some(request.key.clone()))?;
                retained.state = CommitState::Replayed;
                return Ok(retained);
            }
        }
        if batch.expected_incarnation != info.incarnation
            || batch.admission.generation != self.identity.generation
        {
            return Err(fail(
                StoreErrorCode::GenerationChanged,
                "batch incarnation/generation differs",
            ));
        }
        let mut descriptors = Vec::new();
        let mut total = 0usize;
        for e in &batch.events {
            let d = descriptor(&e.body, |t| match t {
                InputText::Inline(s) => Ok(s.clone()),
                InputText::Staged(_) => later("staged payload"),
            })?;
            total = total
                .checked_add(d.len())
                .ok_or_else(|| invalid("batch bytes overflow"))?;
            if total > 2 * 1024 * 1024 {
                return Err(fail(
                    StoreErrorCode::BodyTooLarge,
                    "atomic batch exceeds 2 MiB",
                ));
            }
            descriptors.push(d);
            let runtime = matches!(
                e.body,
                EventBody::RuntimeOwnerEstablished { .. }
                    | EventBody::RuntimeHandoverRecorded { .. }
            );
            if runtime && !maintenance {
                return Err(fail(
                    StoreErrorCode::InvalidTransition,
                    "runtime facts require exclusive drained maintenance",
                ));
            }
        }
        if batch.request.is_none() {
            let prior = batch
                .events
                .iter()
                .map(|e| apply::natural(&self.db, e))
                .collect::<StoreResult<Vec<_>>>()?;
            if prior.iter().all(Option::is_some) {
                let mut seqs = Vec::new();
                for ((e, description), seq) in batch.events.iter().zip(&descriptors).zip(prior) {
                    let seq = seq.ok_or_else(|| invalid("natural membership disappeared"))?;
                    let old = crate::read::load_event(&self.db, seq, info)?;
                    let bytes = descriptor(&old.body, |t| match t {
                        StoredText::Present(s) => Ok(s.clone()),
                        StoredText::Erased { .. } => {
                            Err(fail(StoreErrorCode::ContentErased, "event content erased"))
                        }
                    })?;
                    if description != &bytes
                        || e.header.actor != old.header.actor
                        || e.header.scope != old.header.scope
                    {
                        return Err(fail(
                            StoreErrorCode::NaturalKeyConflict,
                            "natural identity differs from its retained fact",
                        ));
                    }
                    seqs.push(seq);
                }
                let mut retained = receipt_members(&self.db, &seqs, info, None)?;
                retained.state = CommitState::NaturalKeyReplay;
                return Ok(retained);
            }
        }
        let mut op_hash = Sha256::new();
        op_hash.update(&scope);
        op_hash.update(&actor);
        op_hash.update(batch.events[0].header.event.as_str());
        if let Some(k) = &batch.request {
            op_hash.update(k.key.as_str())
        }
        let op = op_hash.finalize()[..16].to_vec();
        let writer = WriterMode::from_lease(&self.identity);
        let (mode, generation) = stamp(&writer);
        self.db.execute("INSERT INTO operations(operation_id,scope_key,actor_id,request_key,fingerprint_codec,fingerprint,recorded_incarnation,writer_mode,host_generation,durability) VALUES(?,?,?,?,?,?,?,?,?,?)",crate::sql_value::sql_params![op,scope,actor,batch.request.as_ref().map(|r|r.key.as_str()),batch.request.as_ref().map(|r|r.intent.codec_version).unwrap_or(1),batch.request.as_ref().map(|r|r.intent.sha256.to_vec()),info.incarnation,mode,generation,if full{"full"}else{"normal"}]).map_err(sql)?;
        for (ordinal, (e, description)) in batch.events.into_iter().zip(descriptors).enumerate() {
            let prior = apply::natural(&self.db, &e)?;
            let seq = if let Some(seq) = prior {
                let old = crate::read::load_event(&self.db, seq, info)?;
                let old_description = descriptor(&old.body, |t| match t {
                    StoredText::Present(s) => Ok(s.clone()),
                    StoredText::Erased { .. } => {
                        Err(fail(StoreErrorCode::ContentErased, "event content erased"))
                    }
                })?;
                if description != old_description
                    || old.header.actor != e.header.actor
                    || old.header.scope != e.header.scope
                {
                    return Err(fail(
                        StoreErrorCode::NaturalKeyConflict,
                        "existing event/natural identity has different content",
                    ));
                }
                seq
            } else {
                let revision = apply::revision_for(&self.db, &e)?;
                let (kind, facts) = codec::metadata(&e.body)?;
                let event = key(&self.db, "event", e.header.event.as_str(), &scope, true)?;
                let p = match &e.header.scope {
                    Scope::Registry => None,
                    Scope::Project(_) => {
                        Some(connection::project_id(&self.db, &e.header.scope, true)?)
                    }
                };
                let session = e
                    .header
                    .session
                    .as_ref()
                    .map(|v| key(&self.db, "session", v.as_str(), &scope, true))
                    .transpose()?;
                let cause = e
                    .header
                    .cause
                    .as_ref()
                    .map(|v| key(&self.db, "event", v.as_str(), &scope, false))
                    .transpose()?;
                let supersedes = e
                    .header
                    .supersedes
                    .as_ref()
                    .map(|v| key(&self.db, "event", v.as_str(), &scope, false))
                    .transpose()?;
                self.db.execute("INSERT INTO events(event_id,project_id,actor_id,session_id,origin_id,door,kind,schema_version,recorded_incarnation,entity_revision,writer_mode,host_generation,durability,operation_id,occurred_at_us,recorded_at_us,cause_event_id,supersedes_event_id) VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?)",crate::sql_value::sql_params![event,p,actor,session,canonical(info.id.as_str()).ok_or_else(||invalid("canonical StoreId required"))?,door(e.header.door),kind,info.incarnation,revision,mode,generation,if full{"full"}else{"normal"},op,e.header.occurred_at_us,recorded,cause,supersedes]).map_err(sql)?;
                let seq = self.db.last_insert_rowid();
                apply::apply(
                    &self.db,
                    &e.header,
                    e.body,
                    seq,
                    revision,
                    facts,
                    &self.identity,
                )?;
                seq
            };
            self.db.execute("INSERT INTO operation_events(operation_id,ordinal,event_seq,newly_appended) VALUES(?,?,?,?)",crate::sql_value::sql_params![op,ordinal,seq,prior.is_none()]).map_err(sql)?;
        }
        receipt(&self.db, &op, info, batch.request.map(|r| r.key))
    }
}
pub(crate) fn stamp(writer: &WriterMode) -> (&'static str, Option<u64>) {
    match writer.kind() {
        WriterKind::Direct => ("direct", None),
        WriterKind::Host { generation } => ("host", Some(generation)),
    }
}
pub(crate) fn door(d: Door) -> &'static str {
    match d {
        Door::Cli => "cli",
        Door::Mcp => "mcp",
        Door::Hook => "hook",
        Door::Host => "host",
        Door::Import => "import",
    }
}
pub(crate) fn receipt(
    c: &Connection,
    op: &[u8],
    info: &StoreInfo,
    request_key: Option<se_types::IdempotencyKey>,
) -> StoreResult<CommitReceipt> {
    let mut q = c
        .prepare("SELECT event_seq FROM operation_events WHERE operation_id=? ORDER BY ordinal")
        .map_err(sql)?;
    let seqs = q
        .query_map([op], |r| crate::sql_value::value::<i64>(r, 0))
        .map_err(sql)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(sql)?;
    if seqs.is_empty() || seqs.len() > 64 {
        return Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "operation membership absent or exceeds bound",
        ));
    }
    receipt_members(c, &seqs, info, request_key)
}
fn receipt_members(
    c: &Connection,
    seqs: &[i64],
    info: &StoreInfo,
    request_key: Option<se_types::IdempotencyKey>,
) -> StoreResult<CommitReceipt> {
    let events = seqs
        .iter()
        .map(|s| crate::read::load_event(c, *s, info))
        .collect::<StoreResult<Vec<_>>>()?;
    let primary = &events[0];
    let mut wakes = Vec::new();
    for e in &events {
        if let (Scope::Project(p), EventBody::MessageSent { recipient, .. }) =
            (&e.header.scope, &e.body)
        {
            wakes.push(Wake {
                project: p.clone(),
                principal: recipient.clone(),
                through: e.position.clone(),
            })
        }
    }
    Ok(CommitReceipt {
        request_key,
        state: CommitState::Committed,
        primary_event: primary.header.event.clone(),
        writer: primary.writer.clone(),
        durability: primary.durability,
        wakes,
        first: events
            .iter()
            .min_by_key(|e| e.position.sequence())
            .ok_or_else(|| invalid("empty membership"))?
            .position
            .clone(),
        last: events
            .iter()
            .max_by_key(|e| e.position.sequence())
            .ok_or_else(|| invalid("empty membership"))?
            .position
            .clone(),
        events: events.into_iter().map(|e| e.header.event).collect(),
    })
}
fn security<T>(b: &EventBody<T>) -> bool {
    use EventBody::*;
    matches!(
        b,
        CredentialIssued { .. }
            | CredentialActivated { .. }
            | CredentialRevoked { .. }
            | DecisionRatified { .. }
            | DecisionRejected { .. }
            | DecisionRetracted { .. }
            | DecisionSuperseded { .. }
            | SessionActivated { .. }
            | SessionEnded { .. }
            | SessionRevoked { .. }
            | RuntimeOwnerEstablished { .. }
            | RuntimeHandoverRecorded { .. }
            | ProjectRegistered { .. }
            | ProjectRemoved { .. }
            | PrincipalRegistered { .. }
            | GrantRecorded { .. }
            | ProfileSaved { .. }
            | ErasureRequested { .. }
            | TurnErased { .. }
            | MessageErased { .. }
            | ErasureCompleted { .. }
            | RecoveryRecorded { .. }
    )
}
pub(crate) fn descriptor<T>(
    b: &EventBody<T>,
    text: impl Fn(&T) -> StoreResult<String>,
) -> StoreResult<String> {
    use EventBody::*;
    use serde_json::json;
    let (kind, facts) = codec::metadata(b)?;
    let hot = match b {
        MessageSent {
            message,
            recipient,
            kind,
            body,
            refs,
            reply_to,
        } => {
            json!({"message":message,"recipient":recipient,"kind":kind,"body":text(body)?,"refs":refs,"reply_to":reply_to})
        }
        MessageRead { message, recipient } | MessageDismissed { message, recipient } => {
            json!({"message":message,"recipient":recipient})
        }
        MessageDelivered {
            message,
            recipient,
            evidence,
        } => json!({"message":message,"recipient":recipient,"evidence":evidence}),
        WorkingStateSet {
            agent,
            text: t,
            expected,
        } => json!({"agent":agent,"text":text(t)?,"expected":expected}),
        DecisionProposed {
            decision,
            key,
            statement,
            rationale,
            prior,
            kind,
        } => {
            json!({"decision":decision,"key":key,"statement":text(statement)?,"rationale":rationale.as_ref().map(&text).transpose()?,"prior":prior,"kind":kind})
        }
        DecisionRatified {
            decision,
            expected,
            approval,
        } => json!({"decision":decision,"expected":expected,"approval":approval}),
        DecisionRejected {
            decision,
            expected,
            reason,
        }
        | DecisionRetracted {
            decision,
            expected,
            reason,
        } => json!({"decision":decision,"expected":expected,"reason":text(reason)?}),
        DecisionSuperseded {
            prior,
            replacement,
            prior_expected,
            replacement_expected,
            approval,
        } => {
            json!({"prior":prior,"replacement":replacement,"prior_expected":prior_expected,"replacement_expected":replacement_expected,"approval":approval})
        }
        _ => facts,
    };
    codec::encode(&(kind, hot))
}
pub(crate) fn batch_bytes(batch: &AtomicBatch) -> StoreResult<usize> {
    let mut bytes = 0usize;
    for e in &batch.events {
        let n = descriptor(&e.body, |t| match t {
            InputText::Inline(s) => Ok(s.clone()),
            InputText::Staged(_) => later("staged text"),
        })?
        .len()
            + 512;
        bytes = bytes
            .checked_add(n)
            .ok_or_else(|| invalid("batch byte overflow"))?;
    }
    if bytes > 2 * 1024 * 1024 || batch.events.is_empty() || batch.events.len() > 64 {
        return Err(fail(
            StoreErrorCode::BodyTooLarge,
            "batch exceeds 64 events or 2 MiB",
        ));
    }
    Ok(bytes)
}
