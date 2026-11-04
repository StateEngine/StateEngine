use crate::*;

/// Protects: abandoning accepted receipt waits cannot permanently exhaust write admission; outside SQLite receipts prove every abandoned request completed before the next request.
pub async fn check(f: &Fixture, session: &SessionId, runtime: &se_host::HostedRuntime) -> Check {
    let router = runtime.router()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let call = |request: &str| -> Result<se_host::RoutedCall, Box<dyn std::error::Error>> {
        Ok(se_host::RoutedCall {
            admitted: se_host::HostedCall {
                input: se_host::HostedInput::Operation(se_core::ops::AnyOp::MessageSend(
                    se_core::ops::MessageSend {
                        to: f.b.as_str().into(),
                        body: format!("actual abandoned wait {request}"),
                        kind: Default::default(),
                        refs: vec![],
                        reply_to: None,
                        work: None,
                        idempotency_key: key(request)?,
                    },
                )),
                kernel: se_core::dispatch::Kernel::new(se_core::dispatch::CallFacts {
                    event: fixture::event()?,
                    message: fixture::message()?,
                    agent: fixture::agent()?,
                    profile_event: fixture::event()?,
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
                    reason: "agent message does not require a human terminal".into(),
                },
                selections: None,
            },
            hook: None,
        })
    };
    let slots = runtime.blocking_pool().foreground_admission();
    let idle_capacity = slots.available_permits();
    assert!(idle_capacity > 0, "capture an idle foreground pool");
    let mut completed = 0;
    let mut refusals = Vec::new();
    'requests: for index in 0..17 {
        let request = format!("abandoned-message-{index}");
        // A real independent writer prevents the receipt from existing during
        // controlled polling. No completion can be consumed before abandonment.
        let competing = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
        competing.execute_batch("BEGIN IMMEDIATE")?;
        let deadline = bound()?;
        let mut completion = Box::pin(router.execute_call(call(&request)?, &deadline));
        let mut idle_polls = 0;
        loop {
            let polled = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(std::future::Future::poll(completion.as_mut(), cx))
            })
            .await;
            if let std::task::Poll::Ready(result) = polled {
                let error = result
                    .err()
                    .ok_or("write bypassed the actual competing SQLite writer")?;
                refusals.push(format!("request {index}: {error}"));
                drop(completion);
                competing.execute_batch("ROLLBACK")?;
                continue 'requests;
            }
            if slots.available_permits() == idle_capacity {
                idle_polls += 1;
            } else {
                idle_polls = 0;
            }
            if idle_polls == 8 {
                break;
            }
            deadline.remaining()?;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // Drop the actual boxed execution future, rather than just a Pin<&mut>.
        drop(completion);
        competing.execute_batch("ROLLBACK")?;
        drop(competing);
        loop {
            let mut snapshot = reader.snapshot(f.self_scope(&f.a))?;
            let receipt = snapshot.operation_receipt(Actor::Agent(f.a.clone()), key(&request)?)?;
            snapshot.close()?;
            if let Read::Present { value } = receipt {
                assert_eq!(
                    value.events.len(),
                    1,
                    "abandoned write duplicated its effect"
                );
                completed += 1;
                break;
            }
            deadline.remaining().map_err(|error| {
                format!("abandoned request {index} never committed independently: {error}")
            })?;
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    match router
        .execute_call(call("after-abandoned-waits")?, &bound()?)
        .await
    {
        Ok(output) => {
            let output = serde_json::to_value(output.output)?;
            assert_eq!(output["state"], "committed");
            let mut snapshot = reader.snapshot(f.self_scope(&f.a))?;
            let receipt = present(
                snapshot
                    .operation_receipt(Actor::Agent(f.a.clone()), key("after-abandoned-waits")?)?,
            )?;
            snapshot.close()?;
            assert_eq!(receipt.events.len(), 1);
        }
        Err(error) => assert!(
            matches!(error.body.detail(), se_types::Detail::StoreBusy(_)),
            "{completed} independently completed abandoned writes poisoned later admission: {error}; prior refusals: {refusals:?}"
        ),
    }
    assert_eq!(
        completed, 17,
        "could not complete 17 actual abandoned waits: {refusals:?}"
    );
    println!(
        "PASS abandoned_waits: 17 dropped accepted waits independently committed; the next write succeeded or returned typed StoreBusy"
    );
    Ok(())
}
