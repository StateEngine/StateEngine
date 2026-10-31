use crate::*;

/// Protects: owned async completion — actual SQLite contention refuses without effects, and cancellation after independently observed durable commit retains the original key for one-effect replay.
pub async fn uncertain_write(
    f: &Fixture,
    session: &SessionId,
    runtime: &se_host::HostedRuntime,
) -> Check {
    let router = runtime.router()?;
    let call = || -> Result<se_host::RoutedCall, Box<dyn std::error::Error>> {
        Ok(se_host::RoutedCall {
            admitted: se_host::HostedCall {
                input: se_host::HostedInput::Operation(se_core::ops::AnyOp::WorkingStateSet(
                    se_core::ops::WorkingStateSet {
                        text: "accepted before cancellation".into(),
                        expect: se_core::commit::ExpectedRevision::Absent(
                            se_core::commit::AbsentRevision::Absent,
                        ),
                        idempotency_key: key("uncertain-working")?,
                        owner_agent: None,
                    },
                )),
                kernel: se_core::dispatch::Kernel::new(se_core::dispatch::CallFacts {
                    event: fixture::event()?,
                    message: fixture::message()?,
                    occurred_at_us: i64::try_from(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)?
                            .as_micros(),
                    )?,
                    door: Door::Cli,
                })?,
                admission: Admission {
                    scope: Scope::Project(f.project.clone()),
                    actor: Actor::Agent(f.a.clone()),
                    session: Some(session.clone()),
                    generation: runtime.generation().get(),
                },
                terminal: se_core::admission::HumanTerminal::Refused {
                    reason: "agent operation does not require a human terminal".into(),
                },
                selections: None,
            },
            hook: None,
        })
    };
    // This independent connection is an actual competing SQLite writer, not a
    // writer/VFS/runtime double or a production pause hook.
    let competing = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    competing.execute_batch("BEGIN IMMEDIATE")?;
    let mut bounded = options();
    bounded.timeout = Duration::from_secs(1);
    let deadline = se_host::client::lease::Deadline::from_options(&bounded)?;
    let outcome = router.execute_call(call()?, &deadline).await;
    competing.execute_batch("ROLLBACK")?;
    drop(competing);
    let error = outcome
        .err()
        .ok_or("competing SQLite writer was silently ignored")?;
    assert!(
        matches!(error.body.detail(), se_types::Detail::StoreBusy(_)),
        "wrong contention result: {error}"
    );
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut cancelled_options = options();
    cancelled_options.timeout = Duration::from_secs(10);
    let cancel = cancelled_options.cancelled.clone();
    let completion_deadline = se_host::client::lease::Deadline::from_options(&cancelled_options)?;
    let submitted = call()?;
    let mut completion = std::pin::pin!(router.execute_call(submitted, &completion_deadline));
    // A caller may be descheduled at any await. Poll the production future,
    // observing the real receipt between polls; no clock or native fact is
    // substituted. Cancel before resuming delivery of the durable completion.
    loop {
        let polled = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(std::future::Future::poll(completion.as_mut(), cx))
        })
        .await;
        if let std::task::Poll::Ready(result) = polled {
            return Err(format!(
                "completion was delivered before controlled cancellation: {:?}",
                result.err()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
        let mut snapshot = reader.snapshot(f.self_scope(&f.a))?;
        let receipt =
            snapshot.operation_receipt(Actor::Agent(f.a.clone()), key("uncertain-working")?)?;
        snapshot.close()?;
        if matches!(receipt, Read::Present { .. }) {
            cancel.store(true, std::sync::atomic::Ordering::Release);
            break;
        }
        completion_deadline.remaining()?;
    }
    let error = completion
        .await
        .err()
        .ok_or("cancelled completion reported acknowledged success")?;
    assert!(
        matches!(error.body.detail(),se_types::Detail::CommitOutcomeUnknown(value) if value.operation=="working_state.set" && value.key.as_deref()==Some("uncertain-working")),
        "accepted write lost its identity: {error}"
    );
    let replay = router.execute_call(call()?, &bound()?).await?;
    let value = serde_json::to_value(replay.output)?;
    assert_eq!(value["state"], "replayed");
    assert_eq!(value["revision"], 1);
    assert_eq!(value["current_revision"], 1);
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut read = reader.snapshot(f.self_scope(&f.a))?;
    let state = present(read.working_state(f.a.clone())?)?;
    assert_eq!(state.revision.value.get(), 1);
    assert!(
        matches!(state.current.body,EventBody::WorkingStateSet {text:StoredText::Present(ref text),..} if text=="accepted before cancellation")
    );
    read.close()?;
    println!(
        "PASS uncertain_write: cancelled durable SQLite write retained its original key and replay resolved one effect with a fresh continuation snapshot"
    );
    Ok(())
}
