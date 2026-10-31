use crate::*;

/// Protects: cancellation after the durable receipt reaches the executor but before continuation admission must retain the accepted key, and retry must resolve exactly one effect.
pub async fn check(
    f: &Fixture,
    runtime: &se_host::HostedRuntime,
    mut call: impl FnMut() -> Result<se_host::RoutedCall, Box<dyn std::error::Error>>,
) -> Check {
    let router = runtime.router()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut controls = options();
    controls.timeout = Duration::from_secs(10);
    let cancel = controls.cancelled.clone();
    let deadline = se_host::client::lease::Deadline::from_options(&controls)?;
    let mut completion = std::pin::pin!(router.execute_call(call()?, &deadline));
    loop {
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
        if matches!(committed, Read::Present { .. }) {
            break;
        }
        deadline.remaining()?;
    }
    // This is the actual public admission resource shared with listener native
    // checks, not a mocked executor or a production test pause hook. Once the
    // accepted submission releases it, hold it while the real continuation
    // queues for foreground admission.
    let slots = runtime.blocking_pool().foreground_admission();
    let held =
        tokio::time::timeout(Duration::from_secs(2), slots.clone().acquire_owned()).await??;
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
    assert!(
        matches!(error.body.detail(),se_types::Detail::CommitOutcomeUnknown(value) if value.operation=="working_state.set" && value.key.as_deref()==Some("continuation-working")),
        "post-commit continuation lost accepted write identity: {error}"
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
        "PASS post_commit_continuation: actual foreground admission holds delivery after receipt, cancellation retains the key, and replay resolves one effect"
    );
    Ok(())
}
async fn poll<F: std::future::Future>(
    mut future: std::pin::Pin<&mut F>,
) -> std::task::Poll<F::Output> {
    std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx))).await
}
