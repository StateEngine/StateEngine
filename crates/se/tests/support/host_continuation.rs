use crate::*;

/// Protects: cancellation after the durable receipt reaches the executor but before continuation admission reports the confirmed commit with exact retained events and key; retry resolves exactly one effect.
pub async fn check(
    f: &Fixture,
    runtime: &se_host::HostedRuntime,
    mut call: impl FnMut() -> Result<se_host::RoutedCall, Box<dyn std::error::Error>>,
) -> Check {
    let router = runtime.router()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let slots = runtime.blocking_pool().foreground_admission();
    let idle_capacity = u32::try_from(slots.available_permits())?;
    assert!(idle_capacity > 0, "capture an idle foreground pool");
    let mut controls = options();
    controls.timeout = Duration::from_secs(10);
    let cancel = controls.cancelled.clone();
    let deadline = se_host::client::lease::Deadline::from_options(&controls)?;
    let mut completion = std::pin::pin!(router.execute_call(call()?, &deadline));
    let committed_events = loop {
        if let std::task::Poll::Ready(result) = poll(completion.as_mut()).await {
            return Err(format!(
                "continuation write acknowledged before controlled descheduling: {:?}",
                result.err()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
        let mut snapshot = reader.snapshot(f.self_scope(&f.a))?;
        let committed =
            snapshot.operation_receipt(Actor::Agent(f.a.clone()), key("continuation-working")?)?;
        snapshot.close()?;
        if let Read::Present { value } = committed {
            break value.events;
        }
        deadline.remaining()?;
    };
    // This is the actual public admission resource shared with listener native
    // checks, not a mocked executor or a production test pause hook. Once the
    // accepted submission releases it, hold it while the real continuation
    // queues for foreground admission.
    let held = tokio::time::timeout(
        Duration::from_secs(2),
        slots.clone().acquire_many_owned(idle_capacity),
    )
    .await??;
    let held_count = Arc::strong_count(&slots);
    loop {
        if let std::task::Poll::Ready(result) = poll(completion.as_mut()).await {
            return Err(format!(
                "continuation bypassed held foreground admission: {:?}",
                result.err()
            )
            .into());
        }
        if Arc::strong_count(&slots) > held_count {
            break;
        }
        deadline.remaining()?;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    // The receipt has now been consumed: the future owns a queued acquisition
    // of this same semaphore, observed through its public Arc. Cancellation
    // therefore targets the continuation, rather than racing the receipt wait.
    cancel.store(true, std::sync::atomic::Ordering::Release);
    let result = completion.await;
    drop(held);
    let error = result
        .err()
        .ok_or("cancelled blocked continuation reported success")?;
    assert_eq!(
        error.code().as_str(),
        "committed-response-unavailable",
        "a receipt already consumed by the executor must report a confirmed commit: {error}"
    );
    assert_eq!(error.class(), se_types::Class::Incomplete);
    let wire = serde_json::to_value(error.body.detail())?;
    let detail = &wire["detail"];
    assert_eq!(detail["operation"], "working_state.set");
    assert_eq!(detail["key"], "continuation-working");
    assert_eq!(detail["natural_events"], serde_json::json!([]));
    assert_eq!(
        detail["committed_events"],
        serde_json::to_value(&committed_events)?
    );
    assert!(
        detail["reason"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    let replay = router.execute_call(call()?, &bound()?).await?;
    let value = serde_json::to_value(replay.output)?;
    assert_eq!(value["state"], "replayed");
    assert_eq!(value["revision"], 2);
    assert_eq!(value["current_revision"], 2);
    let mut snapshot = reader.snapshot(f.self_scope(&f.a))?;
    let state = present(snapshot.working_state(f.a.clone())?)?;
    assert_eq!(state.revision.value.get(), 2);
    assert!(
        matches!(state.current.body,EventBody::WorkingStateSet{text:StoredText::Present(ref text),..} if text=="accepted before continuation cancellation")
    );
    snapshot.close()?;
    println!(
        "PASS post_commit_continuation: actual foreground admission holds delivery after receipt, cancellation confirms exact committed events and key, and replay resolves one effect"
    );
    Ok(())
}
async fn poll<F: std::future::Future>(
    mut future: std::pin::Pin<&mut F>,
) -> std::task::Poll<F::Output> {
    std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx))).await
}
