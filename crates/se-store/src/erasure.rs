//! Forgetting: a read-only plan, then erasure on the host writer. Erasure
//! removes the bodies and their content digests, rewrites the database and
//! its write-ahead log, and replaces every backup generation taken before it.
//! Copies outside the store's custody are named, never treated as erased.
pub(crate) mod apply;
pub(crate) mod permit;
mod residuals;
use crate::{connection, error::*, open::SqliteHost, *};
use residuals::{inventory, recipient_transcripts, residual, same_inventory};
use rusqlite::{Connection, OptionalExtension};
use se_types::{EventId, HumanId};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const MAX_TARGETS: usize = 60;
/// The most copies one erasure manifest names; the plan refuses past it.
pub(crate) const MAX_RESIDUALS: usize = 64;
/// A forgettable body, as the plan observed it.
struct Body {
    target: EraseTarget,
    bytes: u64,
    turn: bool,
}
struct Observed {
    scope: Scope,
    bodies: Vec<Body>,
    residuals: Vec<ResidualCopy>,
}
fn event_key(c: &Connection, event: &EventId) -> StoreResult<Vec<u8>> {
    if let Some(bytes) = crate::identity::canonical(event.as_str()) {
        return Ok(bytes);
    }
    let keys: Vec<Vec<u8>> = c
        .prepare("SELECT storage_key FROM identities WHERE kind='event' AND wire_id=? LIMIT 2")
        .map_err(sql)?
        .query_map([event.as_str()], |r| crate::sql_value::value(r, 0))
        .map_err(sql)?
        .collect::<Result<_, _>>()
        .map_err(sql)?;
    match keys.as_slice() {
        [key] => Ok(key.clone()),
        [] => Err(fail(
            StoreErrorCode::ReferenceMissing,
            format!("event {} is absent", event.as_str()),
        )),
        _ => Err(fail(
            StoreErrorCode::ScopeMismatch,
            format!("event {} is ambiguous across projects", event.as_str()),
        )),
    }
}
fn observe_one(
    c: &Connection,
    target: &EraseTarget,
    home: &std::path::Path,
) -> StoreResult<(Vec<u8>, Body, Vec<ResidualCopy>)> {
    let row: Option<(i64, String, u64, Option<Vec<u8>>)> = c
        .query_row(
            "SELECT seq,kind,entity_revision,project_id FROM events WHERE event_id=?",
            [event_key(c, &target.event)?],
            |r| {
                Ok((
                    crate::sql_value::value(r, 0)?,
                    crate::sql_value::value(r, 1)?,
                    crate::sql_value::value(r, 2)?,
                    crate::sql_value::value(r, 3)?,
                ))
            },
        )
        .optional()
        .map_err(sql)?;
    let Some((seq, kind, revision, project)) = row else {
        return Err(fail(
            StoreErrorCode::ReferenceMissing,
            format!("event {} is absent", target.event.as_str()),
        ));
    };
    let project = project.ok_or_else(|| {
        fail(
            StoreErrorCode::InvalidTransition,
            "only project messages and captured turns can be forgotten",
        )
    })?;
    if revision != target.expected.value.get() {
        return Err(fail(
            StoreErrorCode::RevisionConflict,
            format!(
                "event {} is at revision {revision}, not the planned one",
                target.event.as_str()
            ),
        ));
    }
    let erased: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM erased_fields WHERE event_seq=?)",
            [seq],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    if erased {
        let mut error = fail(
            StoreErrorCode::ContentErased,
            format!("event {} was already forgotten", target.event.as_str()),
        );
        error.remedy.text =
            "Nothing is left to erase for this event; leave it out of the request.".into();
        return Err(error);
    }
    let (turn, sql_text) = match kind.as_str() {
        "session.turn" => (
            true,
            "SELECT length(p.content),s.value FROM turn_data d JOIN payloads p ON p.payload_id=d.text_payload LEFT JOIN symbols s ON s.id=d.source_path WHERE d.event_seq=?",
        ),
        "message.sent" => (
            false,
            "SELECT length(p.content),NULL FROM message_data d JOIN payloads p ON p.payload_id=d.body_payload WHERE d.event_seq=?",
        ),
        // Shared work mail keeps one body payload per event and no message_data row.
        "message.work_sent" => (
            false,
            "SELECT length(p.content),NULL FROM payloads p WHERE p.event_seq=? AND p.field='body'",
        ),
        _ => {
            return Err(fail(
                StoreErrorCode::InvalidTransition,
                format!(
                    "event {} is a {kind}; only message bodies and captured turns can be forgotten",
                    target.event.as_str()
                ),
            ));
        }
    };
    let (bytes, source): (u64, Option<Vec<u8>>) = c
        .query_row(sql_text, [seq], |r| {
            Ok((crate::sql_value::value(r, 0)?, r.get(1)?))
        })
        .optional()
        .map_err(sql)?
        .ok_or_else(|| {
            fail(
                StoreErrorCode::ContentErased,
                format!("event {} has no stored body", target.event.as_str()),
            )
        })?;
    let body = Body {
        target: target.clone(),
        bytes,
        turn,
    };
    let mut residuals: Vec<ResidualCopy> = residual(source, turn, home)?.into_iter().collect();
    if !turn {
        residuals.extend(recipient_transcripts(c, seq, &kind)?);
    }
    Ok((project, body, residuals))
}
fn observe(
    c: &Connection,
    targets: &[EraseTarget],
    home: &std::path::Path,
) -> StoreResult<Observed> {
    if targets.is_empty() || targets.len() > MAX_TARGETS {
        return Err(invalid("forget needs 1..60 events"));
    }
    let mut project = None;
    let mut bodies = Vec::new();
    let mut residuals: Vec<ResidualCopy> = Vec::new();
    for target in targets {
        if bodies.iter().any(|b: &Body| b.target.event == target.event) {
            return Err(invalid(format!(
                "event {} is named twice",
                target.event.as_str()
            )));
        }
        let (p, body, found) = observe_one(c, target, home)?;
        if project.as_ref().is_some_and(|known| known != &p) {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "one forget request covers one project's events",
            ));
        }
        project = Some(p);
        bodies.push(body);
        for r in found {
            if !residuals
                .iter()
                .any(|known| known.location == r.location && known.custodian == r.custodian)
            {
                residuals.push(r);
            }
        }
    }
    let project = project.ok_or_else(|| invalid("forget needs at least one event"))?;
    let id = crate::identity::wire(c, "project", &project, &[0])?;
    Ok(Observed {
        scope: Scope::Project(id.parse().map_err(invalid)?),
        bodies,
        residuals,
    })
}
fn deadline(timeout: Duration) -> StoreResult<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| invalid("erasure deadline overflow"))
}
pub(crate) fn plan(
    options: &StoreOptions,
    targets: Vec<EraseTarget>,
    lease: &dyn RuntimeLease,
) -> StoreResult<ErasurePlan> {
    let mut reader = crate::open::SqliteReader::with_slots(
        options,
        crate::read_slots::ReadSlots::new(
            std::num::NonZeroU32::new(2).ok_or_else(|| invalid("reader capacity"))?,
        )?,
    )?;
    reader.bind_identity()?;
    let c = reader.connect()?;
    let info = connection::info_at(&c, &reader.path)?;
    crate::open::validate_lease(&info, lease, LeaseMode::Host)?;
    let owned_generations = crate::backup::generation_ids(
        lease.files(),
        &options.state_directory,
        &info.id,
        deadline(options.busy_timeout)?,
    )?;
    let se_types::Read::Present { value: database } =
        lease.files().inspect_metadata(&reader.path)?
    else {
        return Err(fail(
            StoreErrorCode::Unreadable,
            "state database size is not readable",
        ));
    };
    // Rebuilding the database and each replaced backup each needs a full copy,
    // for a resumed erasure as much as a fresh one.
    let required_bytes = database
        .len()
        .saturating_mul(1 + owned_generations.len() as u64);
    if let Some(resumed) = unfinished(&c, &targets)? {
        return Ok(ErasurePlan {
            owned_generations,
            required_bytes,
            ..resumed
        });
    }
    let observed = observe(&c, &targets, &options.state_directory)?;
    let mut random = [0u8; 10];
    random.copy_from_slice(&se_proc::random_secret().map_err(invalid)?.expose()[..10]);
    let now = u64::try_from(connection::now()? / 1000).map_err(invalid)?;
    Ok(ErasurePlan {
        id: RecordId::from_parts(now, random).map_err(invalid)?,
        targets: observed.bodies.into_iter().map(|b| b.target).collect(),
        required_bytes,
        owned_generations,
        residuals: inventory(lease.files(), &options.state_directory, observed.residuals)?,
    })
}
/// An interrupted erasure is planned again from its own committed manifest, so
/// a retry resumes its cleanup instead of failing on bodies it already removed.
fn unfinished(c: &Connection, targets: &[EraseTarget]) -> StoreResult<Option<ErasurePlan>> {
    let mut erasure: Option<Vec<u8>> = None;
    for target in targets {
        let id: Option<Vec<u8>> = c
            .query_row(
                "SELECT f.erasure_id FROM events e JOIN erased_fields f ON f.event_seq=e.seq WHERE e.event_id=? AND f.field='body'",
                [event_key(c, &target.event)?],
                |r| crate::sql_value::value(r, 0),
            )
            .optional()
            .map_err(sql)?;
        match (id, &erasure) {
            (None, _) => return Ok(None),
            (Some(id), Some(known)) if &id != known => return Ok(None),
            (Some(id), _) => erasure = Some(id),
        }
    }
    let Some(erasure) = erasure else {
        return Ok(None);
    };
    let manifest: Option<Vec<u8>> = c
        .query_row(
            "SELECT p.content FROM erasures x JOIN payloads p ON p.payload_id=x.manifest_payload WHERE x.erasure_id=? AND x.completed_seq IS NULL",
            [&erasure],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    let Some(manifest) = manifest else {
        return Ok(None);
    };
    let value: serde_json::Value = serde_json::from_slice(&manifest).map_err(invalid)?;
    let field = |v: &serde_json::Value, name: &str| {
        v.get(name)
            .cloned()
            .ok_or_else(|| invalid(format!("erasure manifest lacks {name}")))
    };
    let mut planned = Vec::new();
    for t in field(&value, "targets")?
        .as_array()
        .ok_or_else(|| invalid("erasure manifest targets"))?
    {
        planned.push(EraseTarget {
            event: serde_json::from_value(field(t, "event")?).map_err(invalid)?,
            expected: Revision {
                value: serde_json::from_value(field(t, "expected")?).map_err(invalid)?,
            },
        });
    }
    if planned.len() != targets.len()
        || targets
            .iter()
            .any(|t| !planned.iter().any(|p| p.event == t.event))
    {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "these events belong to an unfinished erasure with a different event list; retry it with exactly its events",
        ));
    }
    let mut residuals = Vec::new();
    for r in field(&value, "residuals")?
        .as_array()
        .ok_or_else(|| invalid("erasure manifest residuals"))?
    {
        residuals.push(ResidualCopy {
            custodian: serde_json::from_value(field(r, "custodian")?).map_err(invalid)?,
            location: serde_json::from_value(field(r, "location")?).map_err(invalid)?,
            reason: serde_json::from_value(field(r, "reason")?).map_err(invalid)?,
        });
    }
    Ok(Some(ErasurePlan {
        id: RecordId::from_bytes(
            erasure
                .try_into()
                .map_err(|_| invalid("erasure ID length"))?,
        )?,
        targets: planned,
        owned_generations: Vec::new(),
        residuals,
        required_bytes: 0,
    }))
}
/// Names the committed revision of each event, for a caller that holds only IDs.
pub(crate) fn plan_events(
    options: &StoreOptions,
    events: Vec<EventId>,
    lease: &dyn RuntimeLease,
) -> StoreResult<ErasurePlan> {
    let mut reader = crate::open::SqliteReader::with_slots(
        options,
        crate::read_slots::ReadSlots::new(
            std::num::NonZeroU32::new(2).ok_or_else(|| invalid("reader capacity"))?,
        )?,
    )?;
    reader.bind_identity()?;
    let c = reader.connect()?;
    let mut targets = Vec::with_capacity(events.len());
    for event in events {
        let revision: Option<u64> = c
            .query_row(
                "SELECT entity_revision FROM events WHERE event_id=?",
                [event_key(&c, &event)?],
                |r| crate::sql_value::value(r, 0),
            )
            .optional()
            .map_err(sql)?;
        let revision = revision.ok_or_else(|| {
            fail(
                StoreErrorCode::ReferenceMissing,
                format!("event {} is absent", event.as_str()),
            )
        })?;
        targets.push(EraseTarget {
            event,
            expected: Revision {
                value: std::num::NonZeroU64::new(revision)
                    .ok_or_else(|| invalid("event revision is zero"))?,
            },
        });
    }
    drop(c);
    plan(options, targets, lease)
}
fn derived_event(erasure: &RecordId, part: &str, at_us: i64) -> StoreResult<EventId> {
    let digest = Sha256::new()
        .chain_update(erasure.as_bytes())
        .chain_update([0])
        .chain_update(part)
        .finalize();
    let mut random = [0u8; 10];
    random.copy_from_slice(&digest[..10]);
    EventId::from_parts(u64::try_from(at_us / 1000).map_err(invalid)?, random).map_err(invalid)
}
fn batch(
    host: &SqliteHost,
    info: &StoreInfo,
    scope: &Scope,
    owner: &HumanId,
    bodies: Vec<(EventId, EventBody<InputText>)>,
) -> StoreResult<AtomicBatch> {
    let at = connection::now()?;
    let actor = Actor::Human(owner.clone());
    Ok(AtomicBatch {
        expected_incarnation: info.incarnation,
        admission: Admission {
            scope: scope.clone(),
            actor: actor.clone(),
            session: None,
            generation: host.engine.identity.generation,
        },
        request: None,
        events: bodies
            .into_iter()
            .map(|(event, body)| NewEvent {
                header: EventHeader {
                    event,
                    scope: scope.clone(),
                    actor: actor.clone(),
                    session: None,
                    origin: info.id.clone(),
                    door: Door::Cli,
                    occurred_at_us: at,
                    cause: None,
                    supersedes: None,
                },
                body,
            })
            .collect(),
        import_checkpoint: None,
    })
}
fn commit(host: &mut SqliteHost, batch: AtomicBatch) -> StoreResult<CommitReceipt> {
    let (mut results, _) = host.engine.group(vec![batch], true)?;
    results
        .pop()
        .ok_or_else(|| invalid("erasure commit returned no receipt"))?
}
fn requested(host: &SqliteHost, erasure: &RecordId) -> StoreResult<Option<bool>> {
    let key = erasure.as_bytes();
    host.engine
        .db
        .query_row(
            "SELECT completed_seq IS NOT NULL FROM erasures WHERE erasure_id=?",
            [key.to_vec()],
            |r| crate::sql_value::value(r, 0),
        )
        .optional()
        .map_err(sql)
}
/// Rewrites the database without free pages, then empties the write-ahead log.
fn rewrite(host: &mut SqliteHost, lease: &dyn RuntimeLease) -> StoreResult<bool> {
    host.engine.db.execute_batch("VACUUM").map_err(|error| {
        let mut error = sql(error);
        error.code = StoreErrorCode::ErasurePhysicalGuaranteeUnavailable;
        error
    })?;
    let until = Instant::now() + host.engine.timeout;
    loop {
        let report = host.checkpoint(CheckpointMode::Truncate, lease)?;
        if !report.busy && report.checkpointed_frames >= report.wal_frames {
            return Ok(true);
        }
        if Instant::now() >= until {
            return Ok(false);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
pub(crate) fn options(host: &SqliteHost) -> StoreResult<StoreOptions> {
    Ok(StoreOptions {
        state_directory: host
            .reader
            .path
            .parent()
            .ok_or_else(|| invalid("state path parent"))?
            .to_path_buf(),
        busy_timeout: host.reader.timeout,
    })
}
/// Commits the request and every body removal as one transaction, with freed
/// pages zeroed as they are released.
fn request(
    host: &mut SqliteHost,
    info: &StoreInfo,
    plan: &ErasurePlan,
    owner: &HumanId,
    observed: Observed,
) -> StoreResult<()> {
    let mut events = vec![(
        derived_event(&plan.id, "requested", connection::now()?)?,
        EventBody::ErasureRequested {
            erasure: plan.id,
            targets: plan.targets.clone(),
            residuals: plan.residuals.clone(),
        },
    )];
    for body in observed.bodies {
        let (target, erasure, original_bytes, by) =
            (body.target.event, plan.id, body.bytes, owner.clone());
        let event = derived_event(&plan.id, target.as_str(), connection::now()?)?;
        let erased = if body.turn {
            EventBody::TurnErased {
                target,
                erasure,
                original_bytes,
                by,
            }
        } else {
            EventBody::MessageErased {
                target,
                erasure,
                original_bytes,
                by,
            }
        };
        events.push((event, erased));
    }
    let batch = batch(host, info, &observed.scope, owner, events)?;
    host.engine
        .db
        .execute_batch("PRAGMA secure_delete=ON")
        .map_err(sql)?;
    let committed = commit(host, batch);
    let restored = host
        .engine
        .db
        .execute_batch("PRAGMA secure_delete=OFF")
        .map_err(sql);
    // The commit's own failure is the one to report; restoring the pragma comes second.
    committed?;
    restored
}
/// How long erasure waits for one backup copy to finish.
const BACKUP_WAIT: Duration = Duration::from_secs(60);
/// Each new backup retires the oldest of at most two, so two fresh copies
/// replace every generation taken before the erasure. Returns how many of
/// `owned` are witnessed gone: removed by these backups, or absent on disk.
fn replace_backups(
    host: &SqliteHost,
    lease: &dyn RuntimeLease,
    options: &StoreOptions,
    owned: &[RecordId],
) -> StoreResult<usize> {
    let gone = |removed: &[RecordId]| -> StoreResult<usize> {
        let mut count = 0;
        for id in owned {
            if removed.contains(id)
                || crate::backup::generation_absent(lease.files(), &options.state_directory, *id)?
            {
                count += 1;
            }
        }
        Ok(count)
    };
    let mut removed = Vec::new();
    let mut retired = gone(&removed)?;
    for _ in 0..2 {
        if retired == owned.len() {
            break;
        }
        let timeout = options.busy_timeout.max(BACKUP_WAIT);
        let report = crate::backup::run(options, lease, host.context.clone(), timeout)?;
        removed.extend(report.removed);
        retired = gone(&removed)?;
    }
    Ok(retired)
}
pub(crate) fn erase(
    host: &mut SqliteHost,
    plan: ErasurePlan,
    approval: ErasureApproval,
    lease: &dyn RuntimeLease,
) -> StoreResult<ErasureReport> {
    host.engine
        .reopen(&host.reader.path, host.reader.timeout, lease)?;
    let info = connection::info(&host.engine.db)?;
    crate::open::validate_lease(&info, lease, LeaseMode::Host)?;
    if approval.erasure != plan.id || approval.expected_incarnation != info.incarnation {
        return Err(fail(
            StoreErrorCode::GenerationChanged,
            "the approval names another erasure or store incarnation",
        ));
    }
    if !plan.residuals.is_empty() && !approval.accept_named_residuals {
        return Err(fail(
            StoreErrorCode::ErasureExternalCopies,
            "copies outside StateEngine's custody remain; review them and confirm to forget anyway",
        ));
    }
    let options = options(host)?;
    if requested(host, &plan.id)? == Some(true) {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "this erasure already completed",
        ));
    }
    // No backup copies or publishes while this is held: one already running finishes
    // first, and none starts until the bodies are gone. The final residual check and
    // the list of generations to replace are both read under it.
    let fence = host
        .context
        .fence(deadline(options.busy_timeout.max(BACKUP_WAIT))?)?;
    // An interrupted erasure resumes its physical cleanup; nothing is re-planned.
    if requested(host, &plan.id)?.is_none() {
        let observed = observe(&host.engine.db, &plan.targets, &options.state_directory)?;
        let residuals = inventory(
            lease.files(),
            &options.state_directory,
            observed.residuals.clone(),
        )?;
        if !same_inventory(&residuals, &plan.residuals) {
            return Err(fail(
                StoreErrorCode::ErasurePlanChanged,
                "copies outside StateEngine's custody changed after planning; nothing was erased",
            ));
        }
        request(host, &info, &plan, &approval.owner, observed)?;
    }
    let owned = crate::backup::generation_ids(
        lease.files(),
        &options.state_directory,
        &info.id,
        deadline(options.busy_timeout)?,
    )?;
    drop(fence);
    let mut report = ErasureReport {
        erasure: plan.id,
        completed_event: None,
        cleanup_complete: false,
        incarnation: info.incarnation,
        erased_fields: plan.targets.clone(),
        residuals: plan.residuals.clone(),
        backups_replaced: 0,
        cleanup_failure: None,
    };
    // The bodies are gone from here on: a later failure leaves cleanup incomplete and
    // says why, rather than reading as if nothing happened.
    let job = Cleanup {
        lease,
        options: &options,
        info: &info,
        plan: &plan,
        approval: &approval,
        owned: &owned,
    };
    if let Err(error) = job.run(host, &mut report) {
        report.cleanup_complete = false;
        report.completed_event = None;
        report.cleanup_failure = Some(error.cause);
    }
    Ok(report)
}
/// Physical cleanup after the request committed: rewrite, replace the pinned backups,
/// then record completion.
struct Cleanup<'a> {
    lease: &'a dyn RuntimeLease,
    options: &'a StoreOptions,
    info: &'a StoreInfo,
    plan: &'a ErasurePlan,
    approval: &'a ErasureApproval,
    owned: &'a [RecordId],
}
impl Cleanup<'_> {
    fn run(&self, host: &mut SqliteHost, report: &mut ErasureReport) -> StoreResult<()> {
        let Self {
            lease,
            options,
            info,
            plan,
            approval,
            owned,
        } = *self;
        if !rewrite(host, lease)? {
            return Ok(());
        }
        report.backups_replaced = replace_backups(host, lease, options, owned)?;
        if report.backups_replaced != owned.len() {
            return Ok(());
        }
        let manifest = apply::manifest(&plan.id, &plan.targets, &plan.residuals);
        let scope = event_scope(host, plan)?;
        let event = derived_event(&plan.id, "completed", connection::now()?)?;
        let body = EventBody::ErasureCompleted {
            erasure: plan.id,
            manifest_sha256: Sha256::digest(manifest.as_bytes()).into(),
            incarnation: info.incarnation,
            witnesses: approval.buffer_witnesses.clone(),
        };
        commit(
            host,
            batch(
                host,
                info,
                &scope,
                &approval.owner,
                vec![(event.clone(), body)],
            )?,
        )?;
        report.cleanup_complete = true;
        report.completed_event = Some(event);
        Ok(())
    }
}
/// The completion is recorded in the project scope its request used.
fn event_scope(host: &SqliteHost, plan: &ErasurePlan) -> StoreResult<Scope> {
    let target = plan
        .targets
        .first()
        .ok_or_else(|| invalid("erasure has no targets"))?;
    let project: Vec<u8> = host
        .engine
        .db
        .query_row(
            "SELECT project_id FROM events WHERE event_id=?",
            [event_key(&host.engine.db, &target.event)?],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    let id = crate::identity::wire(&host.engine.db, "project", &project, &[0])?;
    Ok(Scope::Project(id.parse().map_err(invalid)?))
}
