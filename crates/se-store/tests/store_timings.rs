#![cfg(any(target_os = "linux", windows))]
use se_store::*;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::*;
use std::time::Duration;
fn timed(receipt: &CommitReceipt) -> Result<&WriteTimings, Box<dyn std::error::Error>> {
    receipt
        .write_timings
        .as_ref()
        .ok_or_else(|| "host completion omitted its own timing".into())
}
fn mail(f: &Fixture, key: &str, keyless: bool) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let mut batch = f.send(
        Actor::Agent(f.a.clone()),
        Actor::Agent(f.b.clone()),
        message()?,
        key,
        key,
    )?;
    if keyless {
        batch.request = None;
    }
    Ok(batch)
}

/// Protects: E3 timing — concurrent keyless completions carry their own worker measurements even when awaited in reverse order.
#[test]
fn concurrent_keyless_receipts_match_their_own_store_measurements() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease)?;
    let client = owner.client();
    let a = mail(&f, "keyless-a", true)?;
    let aid = a.events[0].header.event.clone();
    let b = mail(&f, "keyless-b", true)?;
    let bid = b.events[0].header.event.clone();
    let aw = client.submit(a)?;
    let bw = client.submit(b)?;
    let br = wait(bw)??;
    let ar = wait(aw)??;
    assert_eq!(ar.primary_event, aid);
    assert_eq!(br.primary_event, bid);
    assert!(timed(&ar)?.group_requests >= 1);
    assert!(timed(&br)?.group_requests >= 1);
    assert_eq!(timed(&ar)?.request_key, None);
    assert_eq!(timed(&br)?.request_key, None);
    assert!(
        timed(&ar)?.checkpoint.is_none(),
        "unrun checkpoint manufactured a zero timing"
    );
    assert!(
        timed(&br)?.checkpoint.is_none(),
        "unrun checkpoint manufactured a zero timing"
    );
    assert_eq!(timed(&ar)?.durability, CommitDurability::Normal);
    assert_eq!(timed(&br)?.durability, CommitDurability::Normal);
    drop(wait(owner.drain(Duration::from_secs(2)))??);
    Ok(())
}

/// Protects: E3 timing — promotion measures the current FULL group while a replay retains its original NORMAL receipt.
#[test]
fn group_promotion_and_replay_attempt_timings_keep_distinct_durability() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let mut owner = host.start_writer(options(256)?, lease)?;
    let client = owner.client();
    let sid = se_types::SessionId::from_parts(1_700_000_000_000 + serial(), [29; 10])?;
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request("prepared-for-timing")?),
        vec![EventBody::SessionPrepared {
            session: sid.clone(),
            agent: f.a.clone(),
            provider: Provider::Claude,
            surface: None,
            native_ref: "timing-session".into(),
            consent: Consent::Capture,
            generation: 1,
            expected: Expected::Absent,
        }],
    )?)?)??;
    let original_message = message()?;
    let original = wait(client.submit(f.send(
        Actor::Agent(f.a.clone()),
        Actor::Agent(f.b.clone()),
        original_message.clone(),
        "original normal",
        "retained-normal",
    )?)?)??;
    assert_eq!(original.durability, CommitDurability::Normal);
    let blocker = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    blocker.execute_batch("BEGIN IMMEDIATE")?;
    let gate = client.submit(mail(&f, "gate", false)?)?;
    let flush = owner.flush(Duration::from_secs(2))?;
    let normal = client.submit(mail(&f, "promoted-normal", true)?)?;
    let full = client.submit(f.batch(
        f.owner_project(),
        Some(request("activate-full")?),
        vec![EventBody::SessionActivated {
            session: sid,
            expected: revision(1)?,
            incumbent: None,
            process: None,
            containment: ContainmentFact::NotLaunched,
            witnesses: vec![],
        }],
    )?)?;
    let replay = client.submit(f.send(
        Actor::Agent(f.a.clone()),
        Actor::Agent(f.b.clone()),
        original_message,
        "original normal",
        "retained-normal",
    )?)?;
    blocker.execute_batch("ROLLBACK")?;
    wait(gate)??;
    wait(flush)??;
    let normal = wait(normal)??;
    let full = wait(full)??;
    let replay = wait(replay)??;
    for receipt in [&normal, &full, &replay] {
        assert_eq!(timed(receipt)?.group_requests, 3);
        assert_eq!(timed(receipt)?.durability, CommitDurability::Full);
    }
    assert_eq!(normal.durability, CommitDurability::Full);
    assert_eq!(full.durability, CommitDurability::Full);
    assert_eq!(replay.state, CommitState::Replayed);
    assert_eq!(replay.durability, CommitDurability::Normal);
    same_receipt(&original, &replay);
    for receipt in [&normal, &full, &replay] {
        assert_eq!(timed(receipt)?.request_key, receipt.request_key);
        assert_eq!(timed(receipt)?.transaction, timed(&normal)?.transaction);
        assert_eq!(timed(receipt)?.commit_sync, timed(&normal)?.commit_sync);
        assert_eq!(timed(receipt)?.checkpoint, timed(&normal)?.checkpoint);
    }
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snap = reader.snapshot(f.self_scope(&f.a))?;
    let retained = present(
        snap.operation_receipt(Actor::Agent(f.a.clone()), request("retained-normal")?.key)?,
    )?;
    assert!(retained.write_timings.is_none());
    same_receipt(&original, &retained);
    drop(snap);
    drop(wait(owner.drain(Duration::from_secs(2)))??);
    Ok(())
}

/// Protects: E3 timing — every completion owns its measurements beyond the retired sample's old capacity.
#[test]
fn every_receipt_keeps_timings_past_the_former_sample_capacity() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease)?;
    let client = owner.client();
    for n in 0..1026 {
        let receipt = wait(client.submit(mail(&f, &format!("timed-{n}"), true)?)?)??;
        assert_eq!(timed(&receipt)?.request_key, receipt.request_key);
        assert!(timed(&receipt)?.group_requests >= 1);
        assert_eq!(timed(&receipt)?.durability, CommitDurability::Normal);
    }
    drop(wait(owner.drain(Duration::from_secs(2)))??);
    Ok(())
}

/// Protects: E3 timing — direct writes never manufacture host worker measurements.
#[test]
fn direct_receipts_do_not_have_host_write_timings() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let receipt = direct.append(mail(&f, "direct", false)?, &*lease)?;
    assert!(receipt.write_timings.is_none());
    Ok(())
}
