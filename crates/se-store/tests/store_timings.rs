#![cfg(any(target_os = "linux", windows))]
use se_store::*;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::*;
use std::time::{Duration, Instant};
fn timed(receipt: &CommitReceipt) -> Result<&WriteTimings, Box<dyn std::error::Error>> {
    receipt
        .write_timings
        .as_ref()
        .ok_or_else(|| "host completion omitted its own timing".into())
}
fn mail(f: &Fixture, key: &str) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    f.send(
        Actor::Agent(f.a.clone()),
        Actor::Agent(f.b.clone()),
        message()?,
        key,
        key,
    )
}

// Seed keyed mail before measuring the legal, naturally idempotent recipient mark.
fn recipient_mark(
    f: &Fixture,
    client: &SqliteClient,
    key: &str,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let id = message()?;
    wait(client.submit(f.send(
        Actor::Agent(f.a.clone()),
        Actor::Agent(f.b.clone()),
        id.clone(),
        key,
        key,
    )?)?)??;
    f.batch(
        f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.b.clone())),
        None,
        vec![EventBody::MessageRead {
            message: id,
            recipient: Actor::Agent(f.b.clone()),
        }],
    )
}

/// Protects: E3 timing — concurrent keyless completions carry their own worker measurements even when awaited in reverse order.
#[test]
fn concurrent_keyless_receipts_match_their_own_store_measurements() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease)?;
    let client = owner.client();
    let a = recipient_mark(&f, &client, "keyless-a")?;
    let aid = a.events[0].header.event.clone();
    let b = recipient_mark(&f, &client, "keyless-b")?;
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
    drop(wait_drained(owner.drain(DRAIN_DEADLINE))??);
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
    let normal = recipient_mark(&f, &client, "promoted-normal")?;
    let blocker = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    blocker.execute_batch("BEGIN IMMEDIATE")?;
    let gate = client.submit(mail(&f, "gate")?)?;
    let flush = owner.flush(Duration::from_secs(2))?;
    let normal = client.submit(normal)?;
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
    drop(wait_drained(owner.drain(DRAIN_DEADLINE))??);
    Ok(())
}

/// Protects: E3 timing — every completion owns its measurements beyond the retired sample's old capacity.
#[test]
fn every_receipt_keeps_timings_past_the_former_sample_capacity() -> Check {
    const RECEIPTS: usize = 1026;
    const LOAD_BUDGET: Duration = Duration::from_secs(75);
    const DRAIN_DEADLINE: Duration = Duration::from_secs(10);
    const DRAIN_BUDGET: Duration = Duration::from_secs(20);
    let f = Fixture::new_case()?;
    let admission = f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone()));
    let messages = (0..RECEIPTS)
        .map(|_| message())
        .collect::<Result<Vec<_>, _>>()?;
    // Seed self-notes in batches before opening the writer. Each recipient
    // mark still commits separately and gets its own completion.
    {
        let (mut direct, lease) = f.direct()?;
        for (index, chunk) in messages.chunks(64).enumerate() {
            let notes = chunk
                .iter()
                .cloned()
                .map(|message| EventBody::MessageSent {
                    quiet: false,
                    message,
                    recipient: Actor::Agent(f.a.clone()),
                    kind: "finding".into(),
                    body: InputText::Inline("timing seed".into()),
                    refs: vec![],
                    reply_to: None,
                })
                .collect();
            direct.append(
                f.batch(
                    admission.clone(),
                    Some(request(&format!("timing-seed-{index}"))?),
                    notes,
                )?,
                &*lease,
            )?;
        }
        direct.close()?;
    }
    let (host, lease) = host_from_existing(&f)?;
    let owner = host.start_writer(options(256)?, lease)?;
    let client = owner.client();
    // Check all receipts under one workload deadline, leaving time for setup
    // and drain inside nextest's 120-second termination window.
    let started = Instant::now();
    let deadline = started + LOAD_BUDGET;
    let observed = (|| -> Check {
        let mut slowest = Duration::ZERO;
        for (index, message) in messages.into_iter().enumerate() {
            let batch = f.batch(
                admission.clone(),
                None,
                vec![EventBody::MessageRead {
                    message,
                    recipient: Actor::Agent(f.a.clone()),
                }],
            )?;
            let event = batch.events[0].header.event.clone();
            let submitted = Instant::now();
            let receipt = wait_until(client.submit(batch)?, deadline).map_err(|error| {
                format!(
                    "receipt {}/{RECEIPTS} after {:?}: {error}",
                    index + 1,
                    started.elapsed()
                )
            })??;
            slowest = slowest.max(submitted.elapsed());
            let timing = timed(&receipt)?;
            if receipt.primary_event != event
                || receipt.state != CommitState::Committed
                || timing.request_key != receipt.request_key
                || timing.group_requests == 0
                || timing.durability != CommitDurability::Normal
            {
                return Err(format!(
                    "receipt {}/{RECEIPTS} did not carry its own committed Normal timing",
                    index + 1
                )
                .into());
            }
        }
        eprintln!(
            "{RECEIPTS} receipts in {:?}; slowest {:?}",
            started.elapsed(),
            slowest
        );
        Ok(())
    })();
    // Sealing by Drop does not join the writer. Always wait for drain before
    // allowing fixture cleanup, and retain the directory on any failure.
    let drained = wait_until(owner.drain(DRAIN_DEADLINE), Instant::now() + DRAIN_BUDGET)
        .and_then(|report| report.map(drop).map_err(Into::into));
    if let Err(error) = &drained {
        eprintln!("timing fixture writer drain failed: {error}");
    }
    f._root
        .as_ref()
        .ok_or("missing timing fixture owner")?
        .finish(observed.and(drained))
}

/// Protects: E3 timing — direct writes never manufacture host worker measurements.
#[test]
fn direct_receipts_do_not_have_host_write_timings() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let receipt = direct.append(mail(&f, "direct")?, &*lease)?;
    assert!(receipt.write_timings.is_none());
    Ok(())
}
