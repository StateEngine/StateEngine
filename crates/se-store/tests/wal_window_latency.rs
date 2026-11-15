//! Temporary paired observer of the public host-writer API, not an MCP journey.
use rusqlite::{Connection, OpenFlags};
use se_store::*;
use serde_json::{Value, json};
use std::{
    num::NonZeroU16,
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::{host, options, wait};
const CLIENTS: usize = 8;
const GROUPS: usize = 2560;
const EVENTS: usize = 4;

fn batch(f: &Fixture, index: usize) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let key = format!("window-group-{index}");
    let mut bodies = Vec::new();
    for n in 0..EVENTS {
        let pattern = format!("{key}-{n}-");
        let mut body = pattern.repeat(24500usize.div_ceil(pattern.len()));
        body.truncate(24500);
        bodies.push(EventBody::MessageSent {
            quiet: false,
            message: message()?,
            recipient: Actor::Agent(f.b.clone()),
            kind: "finding".into(),
            body: InputText::Inline(body),
            refs: vec![],
            reply_to: None,
        });
    }
    f.batch(
        f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
        Some(request(&key)?),
        bodies,
    )
}
fn quantile(rows: &[Value], field: &str) -> Option<u64> {
    let mut values: Vec<_> = rows.iter().filter_map(|r| r[field].as_u64()).collect();
    values.sort_unstable();
    values
        .get((values.len() * 95).div_ceil(100).saturating_sub(1))
        .copied()
}
fn verify(db: &Connection, index: usize, receipt: &CommitReceipt) -> Check {
    let key = format!("window-group-{index}");
    let actual = db.prepare("SELECT e.event_id FROM operations o JOIN operation_events m USING(operation_id) JOIN events e ON e.seq=m.event_seq WHERE o.request_key=? ORDER BY m.ordinal")?
        .query_map([key], |r|r.get::<_,Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
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
    if actual != expected || actual.len() != EVENTS {
        return Err("outside event membership differs".into());
    }
    Ok(())
}

type Observations = (Vec<Value>, Vec<(usize, CommitReceipt)>);
fn client_run(
    client: SqliteClient,
    barrier: Arc<Barrier>,
    clock: Instant,
    load: Vec<(usize, AtomicBatch)>,
) -> Observations {
    let mut rows = Vec::new();
    let mut receipts = Vec::new();
    barrier.wait();
    for (index, batch) in load {
        let submitted = clock.elapsed().as_micros();
        let result = client
            .submit(batch)
            .map_err(|e| e.to_string())
            .and_then(|completion| wait(completion).map_err(|e| e.to_string()))
            .and_then(|result| result.map_err(|e| e.to_string()));
        let returned = clock.elapsed().as_micros();
        match result {
            Ok(receipt) => {
                let timing = receipt.write_timings.as_ref();
                rows.push(json!({"index":index,"submitted_us":submitted,"returned_us":returned,
                            "receipt_us":returned-submitted,"committed":receipt.state==CommitState::Committed,
                            "queue_us":timing.map(|t|t.queue.as_micros()),
                            "transaction_us":timing.map(|t|t.transaction.as_micros()),
                            "commit_us":timing.map(|t|t.commit_sync.as_micros()),
                            "checkpoint_us":timing.and_then(|t|t.checkpoint.map(|d|d.as_micros())),
                            "group_requests":timing.map(|t|t.group_requests),
                            "maintenance_failed":receipt.maintenance_failed,
                            "events":receipt.events.iter().map(|e|e.as_str()).collect::<Vec<_>>()}));
                receipts.push((index, receipt));
            }
            Err(error) => rows.push(json!({"index":index,"submitted_us":submitted,
                        "returned_us":returned,"receipt_us":returned-submitted,"error":error})),
        }
    }
    (rows, receipts)
}

#[test]
fn eight_clients_cross_wal_pressure_without_hidden_receipts() -> Check {
    let f = Fixture::new()?;
    let mut loads: Vec<Vec<_>> = (0..CLIENTS).map(|_| Vec::new()).collect();
    for index in 0..GROUPS {
        loads[index % CLIENTS].push((index, batch(&f, index)?));
    }
    let (h, lease) = host(&f)?;
    let mut config = options(16)?;
    config.maximum_requests = NonZeroU16::new(1).ok_or("group limit")?;
    let writer = h.start_writer(config, lease)?;
    let clock = Instant::now();
    let barrier = Arc::new(Barrier::new(CLIENTS + 1));
    let mut workers = Vec::new();
    for load in loads {
        let client = writer.client();
        let barrier = barrier.clone();
        workers.push(std::thread::spawn(move || {
            client_run(client, barrier, clock, load)
        }));
    }
    barrier.wait();
    let mut rows = Vec::new();
    let mut receipts = Vec::new();
    let mut errors = Vec::new();
    for worker in workers {
        match worker.join() {
            Ok((r, c)) => {
                rows.extend(r);
                receipts.extend(c);
            }
            Err(_) => errors.push("client thread panicked".to_string()),
        }
    }
    let completed_us = clock.elapsed().as_micros();
    let drain = wait(writer.drain(Duration::from_secs(4)));
    match drain {
        Ok(Ok(host)) => {
            if host.report.maintenance_failed || !host.report.indeterminate.is_empty() {
                errors.push(format!("drain: {:?}", host.report));
            }
            drop(host);
        }
        Ok(Err(error)) => errors.push(error.to_string()),
        Err(error) => errors.push(error.to_string()),
    }
    let db = Connection::open_with_flags(
        f.options.state_directory.join("state.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut verified = 0;
    for (index, receipt) in &receipts {
        match verify(&db, *index, receipt) {
            Ok(()) => verified += receipt.events.len(),
            Err(error) => errors.push(error.to_string()),
        }
    }
    let exact_operations: i64 = db.query_row(
        "SELECT count(*) FROM operations WHERE request_key LIKE 'window-group-%'",
        [],
        |r| r.get(0),
    )?;
    rows.sort_by_key(|r| r["index"].as_u64());
    let mut returned: Vec<_> = rows
        .iter()
        .filter_map(|r| r["returned_us"].as_u64())
        .collect();
    returned.sort_unstable();
    let maximum_receipt_gap = returned.windows(2).map(|v| v[1] - v[0]).max();
    let failed_rows = rows
        .iter()
        .filter(|r| {
            r.get("error").is_some()
                || r["committed"] != true
                || r["group_requests"] != 1
                || r["maintenance_failed"] == true
        })
        .count();
    let report = json!({"scope":"Eight real client threads through the public host-writer API; no MCP/provider claim",
        "os":std::env::consts::OS,"clients":CLIENTS,"requested_groups":GROUPS,
        "requested_events":GROUPS*EVENTS,"completed_groups":receipts.len(),"exact_operations":exact_operations,
        "verified_events":verified,"failed_rows":failed_rows,"errors":errors,
        "completed_us":completed_us,"groups_per_second":receipts.len() as f64*1_000_000.0/completed_us as f64,
        "queue_p95_us":quantile(&rows,"queue_us"),"receipt_p95_us":quantile(&rows,"receipt_us"),
        "maximum_receipt_gap_us":maximum_receipt_gap,"rows":rows});
    let output = std::env::var_os("SE_WAL_LATENCY_OUTPUT").ok_or("observer output required")?;
    std::fs::write(output, serde_json::to_vec_pretty(&report)?)?;
    if report["errors"].as_array().is_none_or(|e| !e.is_empty())
        || failed_rows != 0
        || receipts.len() != GROUPS
        || exact_operations != i64::try_from(GROUPS)?
        || verified != GROUPS * EVENTS
    {
        return Err("paired pressure observation incomplete; retain report and trace".into());
    }
    Ok(())
}
