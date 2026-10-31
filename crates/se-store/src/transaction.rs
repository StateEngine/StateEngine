use crate::{apply, codec, connection, error::*, identity::*, *};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
mod recovery;
use recovery::Uncertain;
pub(crate) struct Engine {
    pub db: Connection,
    pub identity: LeaseIdentity,
    pub poisoned: bool,
    pub pending: Vec<Uncertain>,
    pub maintenance: Option<Box<StoreError>>,
    pub backup: Option<BackupContext>,
}
#[derive(Default, Clone, Debug)]
pub(crate) struct Phases {
    pub full: bool,
    pub transaction: Duration,
    pub sync: Option<Duration>,
    pub checkpoint: Option<Duration>,
}
impl Engine {
    pub(crate) fn group(
        &mut self,
        batches: Vec<AtomicBatch>,
        maintenance: bool,
    ) -> StoreResult<(Vec<StoreResult<CommitReceipt>>, Phases)> {
        let attempted = batches
            .iter()
            .map(Uncertain::from_batch)
            .collect::<Vec<_>>();
        let mut result = self.group_inner(batches, maintenance);
        if let Ok((results, _)) = &mut result {
            for (operation, outcome) in attempted.into_iter().zip(results) {
                match outcome {
                    Err(error) if error.code == StoreErrorCode::CommitOutcomeUnknown => {
                        operation.annotate(error);
                        if !self.pending.contains(&operation) {
                            self.pending.push(operation);
                        }
                    }
                    Ok(_) => self.pending.retain(|old| old != &operation),
                    _ => {}
                }
            }
        }
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
            let result = if self.pending.len() >= 1024
                && !self.pending.contains(&Uncertain::from_batch(&batch))
            {
                Err(fail(
                    StoreErrorCode::Backpressure,
                    "resolve outstanding indeterminate operations before admitting more writes",
                ))
            } else {
                self.append(batch, &info, recorded, full, maintenance)
            };
            if result
                .as_ref()
                .is_err_and(|e| e.code == StoreErrorCode::DiskFull)
            {
                self.rollback_confirmed()?;
                return Err(fail(
                    StoreErrorCode::DiskFull,
                    "disk full before COMMIT; the entire group was rolled back",
                ));
            }
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
            let unknown = mapped.code != StoreErrorCode::Busy;
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
                    full,
                    transaction,
                    sync: None,
                    checkpoint: None,
                },
            ));
        }
        let sync = commit.elapsed();
        let checkpoint = self.checkpoint_due();
        for receipt in results.iter_mut().filter_map(|r| r.as_mut().ok()) {
            receipt.maintenance_pending = self.maintenance.is_some();
        }
        Ok((
            results,
            Phases {
                full,
                transaction,
                sync: Some(sync),
                checkpoint,
            },
        ))
    }
    fn rollback(&mut self) {
        if !self.db.is_autocommit() && self.db.execute_batch("ROLLBACK").is_err() {
            self.poisoned = true
        }
    }
    fn checkpoint_due(&mut self) -> Option<Duration> {
        let observed = self.db.query_row("PRAGMA wal_checkpoint(NOOP)", [], |r| {
            Ok((
                crate::sql_value::value::<i64>(r, 0)?,
                crate::sql_value::value::<i64>(r, 1)?,
                crate::sql_value::value::<i64>(r, 2)?,
            ))
        });
        let (_, log, done) = match observed {
            Ok(value) => value,
            Err(error) => {
                self.maintenance = Some(sql(error));
                return None;
            }
        };
        if self
            .backup
            .as_ref()
            .is_some_and(|c| c.suppress_checkpoint(log))
        {
            return None;
        }
        if log >= 256 && log > done {
            let start = Instant::now();
            let result = self
                .db
                .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |r| {
                    Ok((
                        crate::sql_value::value::<i64>(r, 0)?,
                        crate::sql_value::value::<i64>(r, 1)?,
                        crate::sql_value::value::<i64>(r, 2)?,
                    ))
                });
            let elapsed = start.elapsed();
            self.maintenance = match result {
                Ok((0, log, done)) if log == done => None,
                Ok(_) => Some(fail(
                    StoreErrorCode::Busy,
                    "committed checkpoint has pending frames",
                )),
                Err(error) => Some(sql(error)),
            };
            Some(elapsed)
        } else {
            if (log == -1 && done == -1) || (log >= 0 && done >= 0 && log <= done) {
                self.maintenance = None;
            } else if log < 0 || done < 0 {
                self.maintenance = Some(fail(
                    StoreErrorCode::Unreadable,
                    "WAL accounting returned invalid frame counts",
                ));
            }
            None
        }
    }
    fn compare_natural(
        &self,
        event: &NewEvent,
        description: &str,
        seq: i64,
        info: &StoreInfo,
    ) -> StoreResult<()> {
        let old = crate::read::load_event(&self.db, seq, info)?;
        let retained = descriptor(&old.body, |text| match text {
            StoredText::Present(value) => Ok(value.clone()),
            StoredText::Erased { .. } => {
                Err(fail(StoreErrorCode::ContentErased, "event content erased"))
            }
        })?;
        if description != retained
            || event.header.actor != old.header.actor
            || event.header.scope != old.header.scope
        {
            return Err(fail(
                StoreErrorCode::NaturalKeyConflict,
                "natural identity differs from its retained fact",
            ));
        }
        Ok(())
    }
    fn append(
        &self,
        mut batch: AtomicBatch,
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
            let found:Option<(Vec<u8>,Vec<u8>,u16)>=self.db.query_row("SELECT operation_id,fingerprint,fingerprint_codec FROM operations WHERE scope_key=? AND actor_id=?
                    AND request_key=? AND erased=0",crate::sql_value::sql_params![scope,actor,request.key.as_str()],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?))).optional().map_err(sql)?;
            if let Some((op, digest, version)) = found {
                if digest
                    != fingerprint(
                        &scope,
                        &actor,
                        batch.admission.actor.kind(),
                        &request.intent,
                    )?
                    || version != request.intent.codec_version
                {
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
        apply::capture::canonicalize(&self.db, &mut batch)?;
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
                    self.compare_natural(e, description, seq, info)?;
                    seqs.push(seq);
                }
                let mut retained = receipt_members(&self.db, &seqs, info, None)?;
                retained.state = CommitState::NaturalKeyReplay;
                return Ok(retained);
            }
        }
        apply::capture::validate_batch(&self.db, &batch)?;
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
        let intent_fingerprint = batch
            .request
            .as_ref()
            .map(|request| {
                fingerprint(
                    &scope,
                    &actor,
                    batch.admission.actor.kind(),
                    &request.intent,
                )
                .map(|value| value.to_vec())
            })
            .transpose()?;
        self.db.execute(
            "INSERT INTO operations(operation_id,scope_key,actor_id,request_key,
             fingerprint_codec,fingerprint,recorded_incarnation,writer_mode,host_generation,durability)
             VALUES(?,?,?,?,?,?,?,?,?,?)",
            crate::sql_value::sql_params![
                op, scope, actor, batch.request.as_ref().map(|r| r.key.as_str()),
                batch.request.as_ref().map(|r| r.intent.codec_version).unwrap_or(1),
                intent_fingerprint, info.incarnation, mode, generation,
                if full { "full" } else { "normal" }
            ],
        ).map_err(sql)?;
        for (ordinal, (e, description)) in batch.events.into_iter().zip(descriptors).enumerate() {
            let prior = apply::natural(&self.db, &e)?;
            let seq = if let Some(seq) = prior {
                self.compare_natural(&e, &description, seq, info)?;
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
                self.db.execute(
                    "INSERT INTO events(event_id,project_id,actor_id,session_id,origin_id,door,kind,
                     schema_version,recorded_incarnation,entity_revision,writer_mode,host_generation,
                     durability,operation_id,occurred_at_us,recorded_at_us,cause_event_id,supersedes_event_id)
                     VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?)",
                    crate::sql_value::sql_params![
                        event, p, actor, session,
                        canonical(info.id.as_str()).ok_or_else(|| invalid("canonical StoreId required"))?,
                        door(e.header.door), kind, info.incarnation, revision, mode, generation,
                        if full { "full" } else { "normal" }, op,
                        e.header.occurred_at_us, recorded, cause, supersedes
                    ],
                ).map_err(sql)?;
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
        write_timings: None,
        maintenance_pending: false,
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
pub(crate) use crate::codec::semantic::descriptor;
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

fn fingerprint(
    scope: &[u8],
    actor: &[u8],
    actor_kind: &str,
    intent: &IntentDigest,
) -> StoreResult<[u8; 32]> {
    if intent.codec_version != 1
        || intent.operation.is_empty()
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
