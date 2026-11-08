use crate::{apply, codec, connection, error::*, identity::*, *};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
mod first_binding;
pub(crate) mod idempotency;
mod input;
use idempotency::fingerprint;
mod receipt;
mod recovery;
pub(crate) use input::{batch_sizes, natural_kind};
pub(crate) use receipt::receipt;
use receipt::{door, receipt_members, stamp};
use recovery::Uncertain;
pub(crate) struct Engine {
    pub db: Connection,
    pub path: PathBuf,
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
        self.commit(batches, maintenance, false)
    }
    fn commit(
        &mut self,
        batches: Vec<AtomicBatch>,
        maintenance: bool,
        coupled: bool,
    ) -> StoreResult<(Vec<StoreResult<CommitReceipt>>, Phases)> {
        let attempted = batches
            .iter()
            .map(Uncertain::from_batch)
            .collect::<Vec<_>>();
        let info = connection::info(&self.db)?;
        let batches = batches
            .into_iter()
            .map(|batch| {
                batch_sizes(&batch)?;
                crate::staging::prepare(batch, &info, &self.identity)
            })
            .collect();
        let mut result = self.group_inner(batches, maintenance, coupled);
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
        batches: Vec<StoreResult<AtomicBatch>>,
        maintenance: bool,
        coupled: bool,
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
            .filter_map(|b| b.as_ref().ok())
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
        if coupled {
            first_binding::check_pair(&self.db, &batches, &info)?;
        }
        for batch in batches {
            let batch = match batch {
                Ok(batch) => batch,
                Err(error) if coupled => {
                    self.rollback_confirmed()?;
                    return Err(error);
                }
                Err(error) => {
                    results.push(Err(error));
                    continue;
                }
            };
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
                return Err(context(
                    fail(
                        StoreErrorCode::DiskFull,
                        "disk full before COMMIT; the entire group was rolled back",
                    ),
                    &self.path,
                    StoreIoStage::Commit,
                ));
            }
            if result.is_err() {
                if coupled {
                    self.rollback_confirmed()?;
                    return Err(result
                        .err()
                        .ok_or_else(|| invalid("missing first binding error"))?);
                }
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
            StoredText::Present(value) => Ok(text_fingerprint(value)),
            StoredText::Erased { .. } => {
                Err(fail(StoreErrorCode::ContentErased, "event content erased"))
            }
        })?;
        if (description != retained && !codec::capture::native::resumed(event, &old))
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
        if batch.events.is_empty() || batch.events.len() > 64 {
            return Err(invalid("atomic batch needs 1..64 events"));
        }
        let importing = crate::import::validate_batch(&batch)?;
        if batch.request.is_none()
            && !maintenance
            && !importing
            && !batch
                .events
                .iter()
                .all(|event| input::natural_kind(&event.body))
        {
            return Err(invalid(
                "keyless writes are restricted to natural capture and recipient marks",
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
                || !importing && e.header.actor != batch.admission.actor
                || !importing && e.header.session != batch.admission.session
                || e.header.origin != info.id
            {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "event scope/actor/session/origin differs from admitted batch",
                ));
            }
        }
        crate::remote::validate_batch(&self.db, &batch, info, recorded)?;
        if let Some(retained) = idempotency::lookup(&self.db, &batch, info)? {
            return Ok(retained);
        }
        crate::remote::validate_new_batch(&self.db, &batch)?;
        if batch.expected_incarnation != info.incarnation
            || batch.admission.generation != self.identity.generation
        {
            return Err(fail(
                StoreErrorCode::GenerationChanged,
                "batch incarnation/generation differs",
            ));
        }
        crate::mail::validate_offer_batch(&batch)?;
        crate::import::validate_checkpoint(&batch)?;
        apply::capture::canonicalize(&self.db, &mut batch)?;
        let mut descriptors = Vec::new();
        for e in &batch.events {
            let d = descriptor(&e.body, |t| match t {
                InputText::Inline(s) => Ok(text_fingerprint(s)),
                InputText::Staged(_) => {
                    Err(invalid("staged payload was not prepared before BEGIN"))
                }
            })?;
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
                let event_actor = key(
                    &self.db,
                    e.header.actor.kind(),
                    e.header.actor.wire(),
                    if e.header.actor.kind() == "human" {
                        &[0]
                    } else {
                        &scope
                    },
                    true,
                )?;
                self.db.execute(
                    "INSERT INTO events(event_id,project_id,actor_id,session_id,origin_id,door,kind,
                     schema_version,recorded_incarnation,entity_revision,writer_mode,host_generation,
                     durability,operation_id,occurred_at_us,recorded_at_us,cause_event_id,supersedes_event_id)
                     VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?,?)",
                    crate::sql_value::sql_params![
                        event, p, event_actor, session,
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
fn security<T>(b: &EventBody<T>) -> bool {
    use EventBody::*;
    matches!(
        b,
        ChannelRecorded { .. }
            | RemoteSecurity { .. }
            | CredentialIssued { .. }
            | CredentialActivated { .. }
            | CredentialRevoked { .. }
            | DecisionRatified { .. }
            | DecisionRejected { .. }
            | DecisionRetracted { .. }
            | DecisionSuperseded { .. }
            | SessionActivated { .. }
            | SessionEnded { .. }
            | SessionRevoked { .. }
            | ProcessTransition {
                from: ProcessState::Lost,
                ..
            }
            | RuntimeOwnerEstablished { .. }
            | RuntimeHandoverRecorded { .. }
            | ProjectRegistered { .. }
            | ProjectUpdated { .. }
            | ProjectMoved { .. }
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
fn text_fingerprint(text: &str) -> serde_json::Value {
    serde_json::json!({"bytes":text.len(),"sha256":se_types::hex_lower(&Sha256::digest(text.as_bytes()))})
}
