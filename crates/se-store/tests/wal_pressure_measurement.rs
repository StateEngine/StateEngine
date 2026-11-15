//! Development observer: continuous queued writes across the hard WAL cutoff.
#![cfg(any(target_os = "linux", windows))]
use rusqlite::{Connection, OpenFlags};
use se_store::*;
use serde_json::json;
use std::{
    collections::VecDeque,
    num::NonZeroU16,
    path::Path,
    time::{Duration, Instant},
};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::{host, options, wait};
const GROUPS: usize = 256;
const PIPELINE: usize = 4;
const HARD: u64 = 64 * 1024 * 1024;

fn batch(f: &Fixture, index: usize) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let key = format!("pressure-group-{index}");
    let bodies = (0..40)
        .map(|n| {
            let pattern = format!("{key}-{n}-");
            let mut body = pattern.repeat(24500usize.div_ceil(pattern.len()));
            body.truncate(24500);
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
        Some(request(&key)?),
        bodies,
    )
}
fn wal(db: &Connection) -> Result<(i64, i64, u64), Box<dyn std::error::Error>> {
    let (log, done): (i64, i64) = db.query_row("PRAGMA wal_checkpoint(NOOP)", [], |r| {
        Ok((r.get(1)?, r.get(2)?))
    })?;
    if log < 0 || done < 0 || done > log {
        return Err("invalid external WAL accounting".into());
    }
    let page: u32 = db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok((log, done, u64::try_from(log)? * (u64::from(page) + 24) + 32))
}
fn verify(db: &Connection, index: usize, receipt: &CommitReceipt) -> Check {
    let key = format!("pressure-group-{index}");
    let actual = db.prepare("SELECT e.event_id FROM operations o JOIN operation_events m USING(operation_id) JOIN events e ON e.seq=m.event_seq WHERE o.request_key=? ORDER BY m.ordinal")?
        .query_map([key], |r| r.get::<_,Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let expected = receipt
        .events
        .iter()
        .map(|id| {
            Ok(
                uuid::Uuid::parse_str(id.as_str().strip_prefix("ev_").ok_or("event prefix")?)?
                    .as_bytes()
                    .to_vec(),
            )
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    if actual != expected || actual.len() != 40 {
        return Err("outside operation membership differs from receipt".into());
    }
    Ok(())
}

#[test]
fn measure_continuous_wal_pressure() -> Check {
    let f = Fixture::new()?;
    let (h, lease) = host(&f)?;
    let mut configuration = options(8)?;
    configuration.maximum_requests = NonZeroU16::new(1).ok_or("zero group limit")?;
    configuration.resident_bytes =
        std::num::NonZeroU32::new(8 * 1024 * 1024).ok_or("zero resident limit")?;
    let writer = h.start_writer(configuration, lease)?;
    let client = writer.client();
    let database = f.options.state_directory.join("state.db");
    let outside = Connection::open_with_flags(
        &database,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    outside.busy_timeout(Duration::from_secs(1))?;
    let clock = Instant::now();
    let mut pending = VecDeque::new();
    let mut rows = Vec::new();
    let mut largest = 0;
    let mut previous_finish_lower = None;
    let mut maximum_gap_upper_us = 0;
    for index in 0..GROUPS + PIPELINE - 1 {
        if index < GROUPS {
            let prepared = batch(&f, index)?;
            let submitted_us = clock.elapsed().as_micros();
            let completion = client.submit(prepared)?;
            let submitted_by_us = clock.elapsed().as_micros();
            pending.push_back((index, submitted_us, submitted_by_us, completion));
        }
        if index < PIPELINE - 1 {
            continue;
        }
        let (index, submitted_us, submitted_by_us, completion) =
            pending.pop_front().ok_or("pipeline ended early")?;
        let receipt = wait(completion)??;
        let returned_us = clock.elapsed().as_micros();
        if receipt.state != CommitState::Committed {
            return Err("pressure write was not committed".into());
        }
        let timing = receipt
            .write_timings
            .as_ref()
            .ok_or("pressure receipt omitted timing")?;
        if timing.group_requests != 1 {
            return Err("pressure groups were combined despite their configured limit".into());
        }
        let writer_start = submitted_us + timing.queue.as_micros();
        let writer_start_upper = submitted_by_us + timing.queue.as_micros();
        if let Some(previous) = previous_finish_lower {
            maximum_gap_upper_us =
                maximum_gap_upper_us.max(writer_start_upper.saturating_sub(previous));
        }
        let checkpoint_us = timing.checkpoint.map(|d| d.as_micros());
        previous_finish_lower = Some(
            writer_start
                + timing.transaction.as_micros()
                + timing.commit_sync.as_micros()
                + checkpoint_us.unwrap_or(0),
        );
        verify(&outside, index, &receipt)?;
        let (log, done, bytes) = wal(&outside)?;
        largest = largest.max(bytes);
        let physical_bytes = match std::fs::metadata(database.with_extension("db-wal")) {
            Ok(meta) => Some(meta.len()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        rows.push(json!({"index":index,"submitted_us":submitted_us,"submitted_by_us":submitted_by_us,"returned_us":returned_us,
            "queue_us":timing.queue.as_micros(),"transaction_us":timing.transaction.as_micros(),
            "commit_us":timing.commit_sync.as_micros(),"checkpoint_us":checkpoint_us,
            "wal_log":log,"wal_done":done,"sampled_wal_bytes":bytes,
            "sampled_physical_wal_bytes":physical_bytes,"verified_events":receipt.events.len(),
            "maintenance_pending":receipt.maintenance_pending,"maintenance_failed":receipt.maintenance_failed}));
    }
    if !pending.is_empty() || rows.len() != GROUPS {
        return Err("pressure samples are incomplete".into());
    }
    std::thread::sleep(Duration::from_millis(750));
    let settled = wal(&outside)?;
    let drained = wait(writer.drain(Duration::from_secs(4)))??;
    drop(drained);
    let hard_pauses: Vec<_> = rows
        .iter()
        .filter_map(|r| r["checkpoint_us"].as_u64())
        .collect();
    let maximum_pause_us = hard_pauses.iter().max().copied();
    let report = json!({"scope":"Public host writer under continuous one-MiB groups; not MCP request latency",
        "groups":GROUPS,"pipeline":PIPELINE,"verified_events":GROUPS*40,
        "hard_cutoff_bytes":HARD,"sampled_logical_high_water_bytes":largest,
        "maximum_writer_gap_upper_us":maximum_gap_upper_us,
        "continuous_under_250ms":maximum_gap_upper_us<250_000,
        "hard_checkpoint_count":hard_pauses.len(),"maximum_checkpoint_pause_us":maximum_pause_us,
        "maintenance_failure_receipts":rows.iter().filter(|r|r["maintenance_failed"]==true).count(),
        "checkpoint_pause_within_20ms":maximum_pause_us.map(|v|v<=20_000),
        "settled_wal":{"log":settled.0,"done":settled.1,"bytes":settled.2},"rows":rows});
    let output = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/judge-diagnostics");
    std::fs::create_dir_all(&output)?;
    std::fs::write(
        output.join("wal-pressure.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    println!(
        "pressure observer: {GROUPS} groups, {} verified events, {} hard checkpoints, max pause {:?} us, sampled WAL {largest} bytes, maximum writer gap upper {maximum_gap_upper_us} us",
        GROUPS * 40,
        hard_pauses.len(),
        maximum_pause_us
    );
    // Measurements retain misses. Independent review owns the budget verdict.
    Ok(())
}
