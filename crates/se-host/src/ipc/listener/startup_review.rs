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
    let selected = endpoint.clone();
    let clients = rt.spawn_blocking(move || {
        let mut readers = Vec::new();
        let mut retained = None;
        let mut failure = None;
        for index in 0..6 {
            match raw_connect(&selected) {
                Ok(mut peer) if index < 5 => {
                    let expected = selected.clone();
                    readers.push(std::thread::spawn(move || {
                        match challenge(&mut peer, &expected) {
                            Err(error)
                                if error.downcast_ref::<se_types::SeError>().is_some_and(busy) =>
                            {
                                Ok(())
                            }
                            Err(error) => Err(format!("overflow lost its capacity cause: {error}")),
                            Ok(_) => {
                                Err("overflow client received a challenge before commit".into())
                            }
                        }
                    }));
                }
                Ok(peer) => retained = Some(peer),
                Err(error) => {
                    failure = Some(error.to_string());
                    break;
                }
            }
        }
        // Every reader is joined even when an earlier connection/read failed.
        for reader in readers {
            let outcome = reader
                .join()
                .unwrap_or_else(|_| Err("refusal reader panicked".into()));
            if let Err(error) = outcome {
                failure.get_or_insert(error);
            }
        }
        match failure {
            Some(error) => Err(error),
            None => retained.ok_or_else(|| "last startup client was absent".to_owned()),
        }
    });
    let mut peer = rt.block_on(async {
        let deadline = Deadline::from_options(&options(Duration::from_secs(5)))?;
        let peer = tokio::select! {
            outcome = listener.retain_startup_clients(&deadline) => {
                Err(format!("pre-commit pump ended before responsive peers joined: {outcome:?}").into())
            }
            result = clients => result?.map_err(|error| -> Box<dyn std::error::Error> { error.into() }),
        }?;
        listener.join_startup_refusals(&deadline).await?;
        Ok::<_, Box<dyn std::error::Error>>(peer)
    })?;
    assert_eq!(listener.startup_clients.len(), 1); // exact configured pre-auth bound
    assert_eq!(listener.incoming.available_permits(), 1); // the queued stream owns one slot
    assert_eq!(listener.preauth.available_permits(), 1);
    silent(&mut peer)?;
    assert_eq!(
        listener
            .native
            .current_instances(&bound(Duration::from_secs(2)))?,
        3, // reservation + one retained client + one spare
    );
    drop(peer);
    rt.block_on(listener.close_joined(
        &crate::runtime::BlockingPool::new(rt.handle().clone()),
        &Deadline::from_options(&options(Duration::from_secs(5)))?,
    ))
    .map_err(|error| error.into())
}

#[test]
fn silent_overflow_closes_within_the_original_bound_and_keeps_a_spare() -> Check {
    let home = Home::new()?;
    let (rt, mut listener, endpoint) = configured(&home, 2, 1)?;
    let selected = endpoint.clone();
    let clients = rt.spawn_blocking(move || {
        (0..2)
            .map(|_| raw_connect(&selected).map_err(|error| error.to_string()))
            .collect::<std::result::Result<Vec<_>, _>>()
    });
    let started = std::time::Instant::now();
    let mut peers = rt.block_on(async {
        let deadline = Deadline::from_options(&options(Duration::from_millis(200)))?;
        let peers = {
            let pumping = listener.retain_startup_clients(&deadline);
            tokio::pin!(pumping);
            let peers = tokio::select! {
                outcome = &mut pumping => {
                    return Err(format!("silent fixture ended before both clients connected: {outcome:?}").into());
                }
                result = clients => result?.map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
            };
            // The real startup owner also retains its original absolute clock.
            // Let that clock cancel an idle accept or a still-pending refusal.
            let _ = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline.at()),
                &mut pumping,
            )
            .await;
            peers
        };
        // Task clocks remain original; this separate clock bounds observation.
        listener
            .join_startup_refusals(&Deadline::from_options(&options(Duration::from_secs(2)))?)
            .await?;
        Ok::<_, Box<dyn std::error::Error>>(peers)
    })?;
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(listener.startup_clients.len(), 1);
    assert_eq!(listener.incoming.available_permits(), 1); // the queued stream owns one slot
    assert_eq!(listener.preauth.available_permits(), 1);
    peers[0].set_bound(bound(Duration::from_secs(1)));
    let mut closed = Vec::new();
    Read::take(&mut peers[0], 4097).read_to_end(&mut closed)?;
    assert!(
        closed.len() <= 4096,
        "silent-peer close exceeded its frame bound"
    );
    silent(&mut peers[1])?;
    assert_eq!(
        listener
            .native
            .current_instances(&bound(Duration::from_secs(2)))?,
        3,
    );
    drop(peers);
    rt.block_on(listener.close_joined(
        &crate::runtime::BlockingPool::new(rt.handle().clone()),
        &Deadline::from_options(&options(Duration::from_secs(5)))?,
    ))
    .map_err(|error| error.into())
}

struct ClockStep(&'static str, std::time::Instant);
impl ClockStep {
    fn new(name: &'static str) -> Self {
        eprintln!("REFUSAL_CLOCK {name} begin");
        Self(name, std::time::Instant::now())
    }
    fn finish<T, E: std::fmt::Display>(
        self,
        result: std::result::Result<T, E>,
    ) -> std::result::Result<T, Box<dyn std::error::Error>> {
        let elapsed = self.1.elapsed().as_millis();
        eprintln!(
            "REFUSAL_CLOCK {} elapsed_ms={elapsed} ok={}",
            self.0,
            result.is_ok()
        );
        result.map_err(|error| format!("{} after {elapsed} ms: {error}", self.0).into())
    }
}

// A write larger than the native 64-KiB output quota holds the real write
// pending while its client stays silent. This is synthetic transport pressure,
// not a replacement for the separate typed-refusal protocol controls.
async fn backpressure(
    stream: &NativeStream,
) -> std::result::Result<usize, Box<dyn std::error::Error>> {
    ClockStep::new("backpressure writable")
        .finish(tokio::time::timeout(Duration::from_secs(1), stream.writable()).await)??;
    let padding = vec![b'P'; 256 * 1024];
    let queued = stream.try_write(&padding)?;
    assert_eq!(
        queued,
        padding.len(),
        "fixture did not queue its bounded padding"
    );
    assert!(
        matches!(stream.try_write(b"P"), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "fixture did not establish native write backpressure"
    );
    Ok(queued)
}

#[test]
fn cancelled_accept_preserves_the_refusal_clock_without_delaying_admission() -> Check {
    let home = ClockStep::new("create test home").finish(Home::new())?;
    let (rt, mut listener, endpoint) =
        ClockStep::new("bind configured listener").finish(configured(&home, 2, 1))?;
    let mut peers = ClockStep::new("initial client queue").finish(rt.block_on(queue(
        &mut listener,
        &endpoint,
        1,
    )))?;
    let padding = ClockStep::new("prime native backpressure").finish(
        rt.block_on(backpressure(
            &listener
                .startup_clients
                .front()
                .ok_or("first queued stream absent")?
                .stream,
        )),
    )?;
    let clients = rt.spawn_blocking(move || {
        ClockStep::new("second native connect")
            .finish(raw_connect(&endpoint))
            .map_err(|error| error.to_string())
    });
    let original = Deadline::from_options(&options(Duration::from_secs(2)))?;
    peers.push(ClockStep::new("pump until second connection").finish(rt.block_on(async {
        let pumping = listener.retain_startup_clients(&original);
        tokio::pin!(pumping);
        let peer = tokio::select! {
            outcome = &mut pumping => {
                return Err(format!("startup pump ended: {outcome:?}").into());
            }
            result = clients => result?.map_err(|error| -> Box<dyn std::error::Error> { error.into() })?,
        };
        // Preserve this exact future through every Pending. Cancellation occurs
        // only at the simulated ownership-commit boundary, with the write held.
        let cancelled = ClockStep::new("commit cancellation boundary")
            .finish(Ok::<_, std::convert::Infallible>(
                tokio::time::timeout(Duration::from_millis(100), &mut pumping).await,
            ))?;
        assert!(cancelled.is_err());
        Ok::<_, Box<dyn std::error::Error>>(peer)
    }))?);
    assert_eq!(listener.startup_clients.len(), 1);
    assert_eq!(listener.startup_refusals.len(), 1);
    assert_eq!(listener.incoming.available_permits(), 0);
    assert_eq!(listener.preauth.available_permits(), 1);
    // Normal post-commit admission must not join or await this pending refusal.
    let admitted =
        ClockStep::new("immediate post-commit admission").finish(rt.block_on(async {
            tokio::time::timeout(
                Duration::from_millis(100),
                listener.accept(Arc::new(AtomicBool::new(false))),
            )
            .await?
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })
        }))?;
    assert!(listener.startup_clients.is_empty());
    let wait = ClockStep::new("original clock expiry");
    std::thread::sleep(
        original
            .at()
            .saturating_duration_since(std::time::Instant::now())
            + Duration::from_millis(20),
    );
    wait.finish(Ok::<_, std::convert::Infallible>(()))?;
    assert!(original.remaining().is_err());
    ClockStep::new("join refusal task").finish(rt.block_on(
        listener.join_startup_refusals(&Deadline::from_options(&options(Duration::from_secs(2)))?),
    ))?;
    assert!(listener.startup_refusals.is_empty());
    assert_eq!(listener.incoming.available_permits(), 1);
    peers[0].set_bound(bound(Duration::from_secs(2)));
    let mut closed = Vec::new();
    ClockStep::new("drain refused padding and EOF")
        .finish(Read::take(&mut peers[0], padding as u64 + 1).read_to_end(&mut closed))?;
    assert!(
        closed.len() <= padding && closed.iter().all(|byte| *byte == b'P'),
        "refusal wrote new data after its original clock"
    );
    ClockStep::new("retained client stays silent").finish(silent(&mut peers[1]))?;
    drop(admitted);
    drop(peers);
    ClockStep::new("final listener close").finish(rt.block_on(listener.close_joined(
        &crate::runtime::BlockingPool::new(rt.handle().clone()),
        &Deadline::from_options(&options(Duration::from_secs(2)))?,
    )))
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
