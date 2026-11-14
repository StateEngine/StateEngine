//! Real writer debt reaches the shared CLI/MCP envelope without false warnings.
#![cfg(any(target_os = "linux", windows))]
use se_core::{
    admission::HumanTerminal,
    commit::{AbsentRevision, Cx, ExpectedRevision, OpStep, WorkingStateSet},
    dispatch::{CallFacts, Kernel},
    ops::{AnyOp, AnyOutput},
};
use se_store::*;
use std::time::{Duration, Instant};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native_host;
use native_host::{host, options, wait};
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "Only session preparation is shared with this consumer."
)]
mod session;

fn seed(f: &Fixture) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    f.batch(
        f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
        Some(request("visibility-seed")?),
        (0..40)
            .map(|_| {
                Ok(EventBody::MessageSent {
                    quiet: false,
                    message: message()?,
                    recipient: Actor::Agent(f.b.clone()),
                    kind: "finding".into(),
                    body: InputText::Inline("x".repeat(24500)),
                    refs: vec![],
                    reply_to: None,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?,
    )
}
struct Continuation {
    kernel: Kernel,
    then: se_core::ports::Then,
    admission: Admission,
}
fn plan(
    f: &Fixture,
    reader: &SqliteReader,
    door: Door,
    session: Option<&se_types::SessionId>,
    number: u64,
) -> Result<(AtomicBatch, Continuation), Box<dyn std::error::Error>> {
    let kernel = Kernel::new(CallFacts {
        event: event()?,
        message: message()?,
        agent: agent()?,
        profile_event: event()?,
        occurred_at_us: 1_700_000_000_000_000,
        door,
    })?;
    let admission = match session {
        Some(session) => Admission {
            scope: Scope::Project(f.project.clone()),
            actor: Actor::Agent(f.a.clone()),
            session: Some(session.clone()),
            generation: 1,
        },
        None => f.owner_project(),
    };
    let scope = ReadScope {
        admission: admission.clone(),
        visibility: if session.is_some() {
            Visibility::SelfOnly(f.a.clone())
        } else {
            Visibility::Owner
        },
    };
    let mut snapshot = reader.snapshot(scope.clone())?;
    let plan = kernel.plan(
        AnyOp::WorkingStateSet(WorkingStateSet {
            text: format!("visibility-{number}"),
            expect: if number == 0 {
                ExpectedRevision::Absent(AbsentRevision::Absent)
            } else {
                ExpectedRevision::Revision(number)
            },
            idempotency_key: request(&format!("visibility-{number}"))?.key,
            owner_agent: session.is_none().then(|| f.a.clone()),
        }),
        &mut Cx {
            read: &mut snapshot,
            admission: &admission,
        },
        &HumanTerminal::Refused {
            reason: "ordinary owner work".into(),
        },
    )?;
    snapshot.close()?;
    let OpStep::Commit { batch, then } = plan else {
        return Err("working state did not plan a commit".into());
    };
    Ok((
        batch,
        Continuation {
            kernel,
            then,
            admission,
        },
    ))
}
fn finish(
    reader: &SqliteReader,
    continuation: Continuation,
    receipt: &CommitReceipt,
) -> Result<AnyOutput, Box<dyn std::error::Error>> {
    let Continuation {
        kernel,
        then,
        admission,
    } = continuation;
    let visibility = match &admission.actor {
        Actor::Agent(agent) => Visibility::SelfOnly(agent.clone()),
        _ => Visibility::Owner,
    };
    let mut snapshot = reader.snapshot(ReadScope {
        admission: admission.clone(),
        visibility,
    })?;
    let output = kernel.committed(
        then,
        receipt.clone(),
        &mut Cx {
            read: &mut snapshot,
            admission: &admission,
        },
    )?;
    snapshot.close()?;
    Ok(output)
}
fn write(
    f: &Fixture,
    reader: &SqliteReader,
    client: &se_store::SqliteClient,
    door: Door,
    session: Option<&se_types::SessionId>,
    number: u64,
) -> Result<(CommitReceipt, AnyOutput), Box<dyn std::error::Error>> {
    let (batch, continuation) = plan(f, reader, door, session, number)?;
    let receipt = wait(client.submit(batch)?)??;
    let output = finish(reader, continuation, &receipt)?;
    Ok((receipt, output))
}

fn visible(receipt: &CommitReceipt, output: &AnyOutput, failed: bool) -> Check {
    assert_eq!(receipt.state, CommitState::Committed);
    assert_eq!(receipt.maintenance_failed, failed);
    // The CLI warning condition reads this exact production predicate. MCP
    // serializes this same output through its structured-content encoder.
    assert_eq!(
        output.maintenance_pending(),
        failed,
        "public maintenance visibility must reflect an actual failure"
    );
    if failed {
        assert!(receipt.maintenance_pending);
    }
    let json = serde_json::to_value(output)?;
    assert_eq!(
        json.get("maintenance_pending"),
        if failed {
            Some(&serde_json::Value::Bool(true))
        } else {
            None
        }
    );
    assert_eq!(
        json["event_id"].as_str(),
        Some(receipt.primary_event.as_str())
    );
    Ok(())
}
// A flush reports the current facts; it does not join the background task.
// Observe recovery within one deadline, including the task clearing its own
// retained failure. Every flush error remains a failure of this fixture.
fn recovered(writer: &mut se_store::SqliteWriter) -> Check {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("checkpoint recovery did not become visible before its deadline")?;
        let report = wait(writer.flush(remaining)?)??;
        if !report.maintenance_pending && !report.maintenance_failed {
            return Ok(());
        }
        // Let the independent task run while the writer is idle. The interval
        // is only an observation cadence, never evidence of completion.
        std::thread::park_timeout(
            Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}

/// Protects: scheduled, actually failed and recovered checkpoints remain
/// distinct through real native SQLite, typed receipts and public envelopes.
#[test]
fn scheduled_work_is_quiet_and_failures_reach_cli_and_session_envelopes() -> Check {
    for door in [Door::Cli, Door::Mcp] {
        let mut f = Fixture::new()?;
        f.options.busy_timeout = Duration::from_secs(5);
        let (host, lease) = host(&f)?;
        let mut writer = host.start_writer(options(256)?, lease.clone())?;
        let client = writer.client();
        let session = if matches!(door, Door::Mcp) {
            let session = session::session()?;
            wait(client.submit(f.batch(
                f.owner_project(),
                Some(request("visibility-session")?),
                vec![
                    session::prepared(&f, &session, &f.a),
                    session::activated(&session)?,
                ],
            )?)?)??;
            Some(session)
        } else {
            None
        };
        let reader = present(SqliteFactory::open_reader(&f.options)?)?;
        let pin = rusqlite::Connection::open_with_flags(
            f.options.state_directory.join("state.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        pin.execute_batch("BEGIN")?;
        let _: i64 = pin.query_row("SELECT count(*) FROM events", [], |r| r.get(0))?;
        let seed_batch = seed(&f)?;
        let (batch, continuation) = plan(&f, &reader, door, session.as_ref(), 0)?;
        let gate = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
        gate.execute_batch("BEGIN IMMEDIATE")?;
        // Both requests are already queued before the writer can commit. Thus
        // no elapsed-time guess can let an idle checkpoint race the quiet case.
        let seed_wait = client.submit(seed_batch)?;
        let first_wait = client.submit(batch)?;
        gate.execute_batch("ROLLBACK")?;
        let seeded = wait(seed_wait)??;
        assert!(seeded.maintenance_pending);
        assert!(!seeded.maintenance_failed);
        let receipt = wait(first_wait)??;
        let output = finish(&reader, continuation, &receipt)?;
        assert!(receipt.maintenance_pending);
        visible(&receipt, &output, false)?;
        // The old reader prevents a real PASSIVE checkpoint from completing.
        // No fake receipt, failure flag or production pause hook is supplied.
        let failed = wait(writer.flush(Duration::from_secs(4))?)??;
        assert!(failed.maintenance_pending && failed.maintenance_failed);
        let (receipt, output) = write(&f, &reader, &client, door, session.as_ref(), 1)?;
        visible(&receipt, &output, true)?;
        pin.execute_batch("ROLLBACK")?;
        recovered(&mut writer)?;
        let (receipt, output) = write(&f, &reader, &client, door, session.as_ref(), 2)?;
        visible(&receipt, &output, false)?;
        drop(wait(writer.drain(Duration::from_secs(4)))??);
    }
    Ok(())
}
