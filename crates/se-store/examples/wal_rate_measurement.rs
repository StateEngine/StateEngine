//! Diagnostic consumer for WAL maintenance at a declared arrival cadence.
use rusqlite::{Connection, OpenFlags};
use se_store::*;
use serde_json::json;
use std::time::{Duration, Instant};
#[path = "../tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../tests/support/host_fixture.rs"]
mod native_host;
use native_host::{host, options, wait};

fn payload(
    f: &Fixture,
    key: &str,
    body_bytes: usize,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let bodies = (0..8)
        .map(|n| {
            let pattern = format!("{key}-{n}-");
            let mut body = pattern.repeat(body_bytes.div_ceil(pattern.len()));
            body.truncate(body_bytes);
            Ok(EventBody::MessageSent {
                quiet: false,
                message: message()?,
                recipient: Actor::Agent(f.b.clone()),
                kind: "finding".into(),
                body: InputText::Inline(body),
                refs: vec![],
                reply_to: None,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    f.batch(
        f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
        Some(request(key)?),
        bodies,
    )
}

fn wal(db: &Connection) -> Result<(i64, i64, u64), Box<dyn std::error::Error>> {
    let (log, done): (i64, i64) = db.query_row("PRAGMA wal_checkpoint(NOOP)", [], |r| {
        Ok((r.get(1)?, r.get(2)?))
    })?;
    if log < 0 || done < 0 || done > log {
        return Err("invalid outside WAL frame counts".into());
    }
    let page: i64 = db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok((
        log,
        done,
        32 + u64::try_from(log)? * (u64::try_from(page)? + 24),
    ))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("usage: wal_rate_measurement RATE_BYTES_PER_SECOND SECONDS BURST_REQUESTS BODY_BYTES EVIDENCE_DIRECTORY".into());
    }
    let rate: u64 = args[0].parse()?;
    let seconds: u64 = args[1].parse()?;
    let burst: usize = args[2].parse()?;
    let body_bytes: usize = args[3].parse()?;
    if rate == 0
        || seconds == 0
        || seconds > 1800
        || !(1..=4).contains(&burst)
        || !(1..=24500).contains(&body_bytes)
    {
        return Err("measurement arguments exceed the declared bounds".into());
    }
    let output = std::path::PathBuf::from(&args[4]);
    std::fs::create_dir(&output)?;
    let output = std::fs::canonicalize(output)?;
    se_proc::initialize_file_creation_owner()?;
    let home = output.join("fixture");
    drop(se_proc::NativeStateFiles::create(&home)?);
    let state = home.join("state");
    drop(se_proc::NativeStateFiles::create(&state)?);
    let f = Fixture::at(home, state)?;
    let (h, lease) = host(&f)?;
    let mut writer = h.start_writer(options(256)?, lease.clone())?;
    let client = writer.client();
    let path = f.options.state_directory.join("state.db");
    let outside = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    outside.busy_timeout(Duration::from_millis(10))?;
    let mut samples = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output.join("receipts.jsonl"))?;
    use std::io::Write;
    let started = Instant::now();
    let mut submitted = 0_u64;
    let mut events = Vec::new();
    let mut foreground = 0;
    let mut maintenance_failed = 0;
    let mut high_water = 0;
    let mut resets = 0;
    let mut previous_log = wal(&outside)?.0;
    let mut max_completion_ms = 0_f64;
    let mut max_checkpoint_ms = 0_f64;
    let mut max_queue_ms = 0_f64;
    let mut late_bursts = 0;
    let mut errors = Vec::new();
    let mut observation_errors = Vec::new();
    let mut bursts = 0_u64;
    let payload_per_request = u64::try_from(body_bytes)? * 8;
    let period =
        Duration::from_secs_f64((payload_per_request * u64::try_from(burst)?) as f64 / rate as f64);
    while started.elapsed() < Duration::from_secs(seconds) {
        let due = started + period.mul_f64(bursts as f64);
        if Instant::now() < due {
            std::thread::sleep(due.saturating_duration_since(Instant::now()));
        }
        if started.elapsed() >= Duration::from_secs(seconds) {
            break;
        }
        if Instant::now().saturating_duration_since(due) > Duration::from_millis(5) {
            late_bursts += 1;
        }
        let mut pending = Vec::new();
        for _ in 0..burst {
            let key = format!("rate-{submitted}");
            let batch = payload(&f, &key, body_bytes)?;
            submitted += 1;
            pending.push((Instant::now(), client.submit(batch)?));
        }
        for (queued, completion) in pending {
            match wait(completion)? {
                Ok(receipt) => {
                    if receipt.state != CommitState::Committed {
                        return Err("receipt is not a known commit".into());
                    }
                    let elapsed = queued.elapsed().as_secs_f64() * 1000.0;
                    max_completion_ms = max_completion_ms.max(elapsed);
                    let timing = receipt
                        .write_timings
                        .as_ref()
                        .ok_or("host receipt timings absent")?;
                    max_queue_ms = max_queue_ms.max(timing.queue.as_secs_f64() * 1000.0);
                    if let Some(checkpoint) = timing.checkpoint {
                        foreground += 1;
                        max_checkpoint_ms =
                            max_checkpoint_ms.max(checkpoint.as_secs_f64() * 1000.0);
                    }
                    maintenance_failed += usize::from(receipt.maintenance_failed);
                    let observation = match wal(&outside) {
                        Ok((log, done, bytes)) => {
                            resets += usize::from(log < previous_log);
                            previous_log = log;
                            high_water = high_water.max(bytes);
                            json!({"state":"read","frames":log,"backfilled_frames":done,"bytes":bytes})
                        }
                        Err(error) => {
                            observation_errors.push(error.to_string());
                            json!({"state":"unreadable","error":error.to_string()})
                        }
                    };
                    events.extend(receipt.events);
                    writeln!(
                        samples,
                        "{}",
                        json!({"elapsed":started.elapsed().as_secs_f64(),"completion_ms":elapsed,"queue_ms":timing.queue.as_secs_f64()*1000.0,"transaction_ms":timing.transaction.as_secs_f64()*1000.0,"commit_sync_ms":timing.commit_sync.as_secs_f64()*1000.0,"checkpoint_ms":timing.checkpoint.map(|v|v.as_secs_f64()*1000.0),"maintenance_failed":receipt.maintenance_failed,"wal":observation})
                    )?;
                }
                Err(error) => {
                    errors.push(format!("{:?}: {}", error.code, error.cause));
                }
            }
        }
        bursts += 1;
        if foreground > 0 || !errors.is_empty() {
            break;
        }
    }
    let traffic_seconds = started.elapsed().as_secs_f64();
    let mut readback = 0;
    for event in &events {
        let id = uuid::Uuid::parse_str(
            event
                .as_str()
                .strip_prefix("ev_")
                .ok_or("event prefix absent")?,
        )?;
        let count: i64 = outside.query_row(
            "SELECT count(*) FROM events WHERE event_id=?1",
            [id.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        if count != 1 {
            return Err("returned event is absent or ambiguous outside the writer".into());
        }
        readback += 1;
    }
    let flush = wait(writer.flush(Duration::from_secs(10))?)??;
    let flush_debug = format!("{flush:?}");
    drop(flush);
    let drain = wait(writer.drain(Duration::from_secs(10)))??;
    let drain_debug = format!("{:?}", drain.report);
    drop(drain);
    let record = json!({"state":"measured","requested_payload_bytes_per_second":rate,"requested_seconds":seconds,
        "body_bytes":body_bytes,"messages_per_request":8,"burst_requests":burst,"burst_period_ms":period.as_secs_f64()*1000.0,
        "traffic_seconds":traffic_seconds,"submitted_requests":submitted,"returned_events":events.len(),"outside_readback_events":readback,
        "completed_payload_bytes_per_second":(readback as f64*body_bytes as f64)/traffic_seconds,
        "foreground_checkpoint_receipts":foreground,"maximum_checkpoint_ms":max_checkpoint_ms,"maximum_completion_ms":max_completion_ms,
        "maximum_queue_ms":max_queue_ms,"maintenance_failure_receipts":maintenance_failed,"sampled_wal_high_water_bytes":high_water,
        "observed_wal_resets":resets,"late_bursts":late_bursts,"errors":errors,"observation_errors":observation_errors,"flush":flush_debug,"drain":drain_debug,
        "scope":"Finite optimized public host-writer observation at this message size and cadence; sampled WAL high water, not every intermediate byte. Foreground checkpoint stops this arm; absence over a finite run does not prove indefinite capacity."});
    std::fs::write(
        output.join("result.json"),
        serde_json::to_vec_pretty(&record)?,
    )?;
    println!("{record}");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("measurement failed: {error}");
        std::process::exit(1);
    }
}
