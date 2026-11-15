//! Independent public writer/reader control for quiet scheduling and durability.
#![cfg(any(target_os = "linux", windows))]
use rusqlite::{Connection, OpenFlags};
use se_store::*;
use std::time::{Duration, Instant};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::{host, options, wait};

fn batch(f: &Fixture, key: &str, count: usize) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let bodies = (0..count)
        .map(|index| {
            Ok(EventBody::MessageSent {
                quiet: false,
                message: message()?,
                recipient: Actor::Agent(f.b.clone()),
                kind: "finding".into(),
                body: InputText::Inline(format!("{key}-{index}-").repeat(2000)),
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

fn wal(db: &Connection) -> Result<(i64, i64), Box<dyn std::error::Error>> {
    let value = db.query_row("PRAGMA wal_checkpoint(NOOP)", [], |row| {
        Ok((row.get(1)?, row.get(2)?))
    })?;
    let (log, done): (i64, i64) = value;
    assert!(log >= done && done >= 0);
    Ok(value)
}

#[test]
fn short_public_write_gaps_keep_debt_then_quiet_settles_and_drain_preserves_events() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let writer = host.start_writer(options(256)?, lease.clone())?;
    let client = writer.client();
    let path = f.options.state_directory.join("state.db");
    let open = || {
        Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
    };
    let pinned = open()?;
    pinned.execute_batch("BEGIN")?;
    let _: i64 = pinned.query_row("SELECT count(*) FROM events", [], |row| row.get(0))?;
    let outside = open()?;
    let mut receipts = vec![(
        "quiet-seed".to_owned(),
        wait(client.submit(batch(&f, "quiet-seed", 12)?)?)??,
    )];
    assert_eq!(receipts[0].1.state, CommitState::Committed);
    std::thread::sleep(Duration::from_millis(620));
    let initial = wal(&outside)?;
    assert!(
        initial.0 > initial.1,
        "pinned control did not retain checkpoint debt"
    );
    pinned.execute_batch("ROLLBACK")?;
    let mut observations = Vec::new();
    for index in 0..6 {
        let key = format!("quiet-edge-{index}");
        let receipt = wait(client.submit(batch(&f, &key, 1)?)?)??;
        let completed = Instant::now();
        std::thread::sleep(Duration::from_millis(15));
        observations.push((completed.elapsed(), wal(&outside)?));
        receipts.push((key, receipt));
        std::thread::sleep(Duration::from_millis(40));
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while wal(&outside)? != (0, 0) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    let settled = wal(&outside)?;
    let drained = wait(writer.drain(Duration::from_secs(5)))??;
    assert!(!drained.report.maintenance_failed);
    for (key, receipt) in &receipts {
        assert_eq!(receipt.state, CommitState::Committed);
        let expected = receipt
            .events
            .iter()
            .map(|id| {
                let raw = id.as_str().strip_prefix("ev_").ok_or("event prefix")?;
                Ok(uuid::Uuid::parse_str(raw)?.as_bytes().to_vec())
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        let observed = outside.prepare("SELECT e.event_id FROM operations o JOIN operation_events m USING(operation_id) JOIN events e ON e.seq=m.event_seq WHERE o.request_key=? ORDER BY m.ordinal")?
            .query_map([key], |row| row.get::<_, Vec<u8>>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(observed, expected, "outside event membership differs");
    }
    let integrity: String = outside.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    assert_eq!(integrity, "ok");
    assert_eq!(settled, (0, 0), "debt did not settle after traffic stopped");
    eprintln!(
        "public quiet samples: {observations:?}; externally verified {} events",
        receipts.iter().map(|(_, r)| r.events.len()).sum::<usize>()
    );
    assert!(
        observations
            .iter()
            .all(|(age, _)| *age < Duration::from_millis(200)),
        "observer lost the short-gap window"
    );
    assert!(
        observations.iter().all(|(_, (log, done))| log > done),
        "maintenance entered a short public write gap"
    );
    drop(drained);
    Ok(())
}
