//! Native pre-commit traffic stays bounded, inert and independently closeable.
use super::*;
use crate::client::lease::Deadline;
use std::io::Read;

async fn queue(
    listener: &mut IpcListener,
    endpoint: &EndpointRecord,
    count: usize,
) -> std::result::Result<Vec<Raw>, Box<dyn std::error::Error>> {
    let endpoint = endpoint.clone();
    let clients = tokio::task::spawn_blocking(move || {
        (0..count)
            .map(|_| raw_connect(&endpoint).map_err(|error| error.to_string()))
            .collect::<std::result::Result<Vec<_>, _>>()
    });
    let deadline = Deadline::from_options(&options(Duration::from_secs(5)))?;
    let peers = tokio::select! {
        outcome = listener.retain_startup_clients(&deadline) => {
            return Err(format!("pre-commit accept ended before parent connection: {outcome:?}").into());
        }
        peers = clients => peers?.map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
    };
    // Drive the last connected instance into the queue and leave an idle spare.
    // Timeout cancels only the evented accept, as the real commit branch does.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            listener.retain_startup_clients(&deadline),
        )
        .await
        .is_err(),
        "pre-commit accept ended instead of retaining a spare"
    );
    Ok(peers)
}

fn silent(peer: &mut Raw) -> Check {
    peer.set_bound(bound(Duration::from_millis(50)));
    let error = peer
        .read(&mut [0u8; 1])
        .err()
        .ok_or("pre-commit client received data or closure before admission")?;
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    peer.set_bound(bound(Duration::from_secs(5)));
    Ok(())
}

#[test]
fn startup_queue_accepts_the_parent_without_reading_the_early_client() -> Check {
    let home = Home::new()?;
    let (rt, mut listener, endpoint) = configured(&home, 4, 2)?;
    let mut peers = rt.block_on(queue(&mut listener, &endpoint, 2))?;
    assert_eq!(listener.startup_clients.len(), 2);
    silent(&mut peers[0])?;
    let mut early = peers.remove(0);
    let expected = endpoint.clone();
    let reader = std::thread::spawn(move || {
        challenge(&mut early, &expected)
            .map(|_| ())
            .map_err(|error| error.to_string())
    });
    let outcome = rt.block_on(async {
        let accepted = listener.accept(Arc::new(AtomicBool::new(false))).await?;
        assert!(accepted.handshake().await.is_err()); // Peer closes after its challenge.
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    let challenged = reader.join().map_err(|_| "challenge reader panicked")?;
    drop(peers);
    rt.block_on(listener.close_joined(
        &crate::runtime::BlockingPool::new(rt.handle().clone()),
        &Deadline::from_options(&options(Duration::from_secs(5)))?,
    ))?;
    outcome?;
    challenged.map_err(|error| error.into())
}

#[test]
fn startup_overflow_refuses_oldest_clients_and_keeps_exact_ingress_capacity() -> Check {
    let home = Home::new()?;
    let (rt, mut listener, endpoint) = configured(&home, 2, 1)?;
    let mut peers = rt.block_on(queue(&mut listener, &endpoint, 6))?;
    assert_eq!(listener.startup_clients.len(), 1); // exact configured pre-auth bound
    assert_eq!(listener.incoming.available_permits(), 2);
    assert_eq!(listener.preauth.available_permits(), 1);
    for peer in &mut peers[..5] {
        let error = challenge(peer, &endpoint)
            .err()
            .ok_or("overflow client received a challenge before commit")?;
        let error = error
            .downcast_ref::<se_types::SeError>()
            .ok_or("overflow did not deliver a typed refusal")?;
        assert!(busy(error), "overflow lost its capacity cause: {error}");
    }
    for peer in &mut peers[5..] {
        silent(peer)?;
    }
    assert_eq!(
        listener
            .native
            .current_instances(&bound(Duration::from_secs(2)))?,
        3, // reservation + one retained client + one spare
    );
    drop(peers);
    rt.block_on(listener.close_joined(
        &crate::runtime::BlockingPool::new(rt.handle().clone()),
        &Deadline::from_options(&options(Duration::from_secs(5)))?,
    ))
    .map_err(|error| error.into())
}

#[test]
fn failed_start_close_releases_queued_clients_spare_and_protected_reservation() -> Check {
    let home = Home::new()?;
    let (rt, mut listener, endpoint) = configured(&home, 4, 2)?;
    let mut peers = rt.block_on(queue(&mut listener, &endpoint, 2))?;
    let pool = crate::runtime::BlockingPool::new(rt.handle().clone());
    rt.block_on(listener.close_joined(
        &pool,
        &Deadline::from_options(&options(Duration::from_secs(5)))?,
    ))?;
    for peer in &mut peers {
        peer.set_bound(bound(Duration::from_secs(2)));
        assert_eq!(
            peer.read(&mut [0u8; 1])?,
            0,
            "failed-start peer stayed live"
        );
    }
    drop(peers);
    // Native first-instance creation, rather than a field count, witnesses that
    // the exact protected name is available after failed-start cleanup.
    let next = IpcListener::bind_with_limits(
        endpoint,
        rt.handle().clone(),
        Arc::new(Semaphore::new(2)),
        &limits(4, 2)?,
    )?;
    rt.block_on(next.close_joined(
        &pool,
        &Deadline::from_options(&options(Duration::from_secs(5)))?,
    ))
    .map_err(|error| error.into())
}

#[test]
fn disconnected_early_client_does_not_prevent_the_next_startup_connection() -> Check {
    let home = Home::new()?;
    let (rt, mut listener, endpoint) = configured(&home, 4, 2)?;
    // The client closes before the host reactor has polled ConnectNamedPipe.
    drop(raw_connect(&endpoint)?);
    let outcome = rt.block_on(queue(&mut listener, &endpoint, 1));
    let pool = crate::runtime::BlockingPool::new(rt.handle().clone());
    let closed = rt.block_on(listener.close_joined(
        &pool,
        &Deadline::from_options(&options(Duration::from_secs(5)))?,
    ));
    drop(outcome?);
    closed.map_err(|error| error.into())
}
