//! Real transport consumers. The crate-local grant below stands for completed
//! runtime admission; these tests do not qualify core authorization or Owner.
use super::*;
#[path = "../../../tests/support/ipc_fixture.rs"]
mod fixture;
use crate::client::{BlockingIpcClient, lease::ClientCredential};
use fixture::*;
use std::time::Duration;

fn limits(
    active: u32,
    preauth: u32,
) -> std::result::Result<crate::HostLimits, Box<dyn std::error::Error>> {
    Ok(crate::HostLimits {
        sessions: nonzero(1)?,
        active_connections: nonzero(active)?,
        preauth_connections: nonzero(preauth)?,
        parked_mail_waits: nonzero(1)?,
        resident_queue_bytes: nonzero(4096)?,
        session_notice_ids: nonzero(1)?,
        aggregate_notice_ids: nonzero(1)?,
        response_bytes: nonzero(4096)?,
        blocking_jobs: nonzero(2)?,
    })
}
fn configured(
    home: &Home,
    active: u32,
    preauth: u32,
) -> std::result::Result<
    (tokio::runtime::Runtime, IpcListener, EndpointRecord),
    Box<dyn std::error::Error>,
> {
    let endpoint = home.record()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let listener = IpcListener::bind_with_limits(
        endpoint.clone(),
        rt.handle().clone(),
        Arc::new(Semaphore::new(2)),
        &limits(active, preauth)?,
    )?;
    Ok((rt, listener, endpoint))
}
fn busy(error: &se_types::SeError) -> bool {
    matches!(error.body.detail(), se_types::Detail::StoreBusy(_))
}
fn client(
    endpoint: EndpointRecord,
) -> std::thread::JoinHandle<std::result::Result<(), se_types::SeError>> {
    std::thread::spawn(move || {
        BlockingIpcClient::connect_authenticated(
            &endpoint,
            ClientCredential::Session(se_types::Secret::new(vec![3; 32])?),
            std::num::NonZeroU32::new(4096)
                .ok_or_else(|| se_types::SeError::invalid("fixture cap", "nonzero"))?,
            &options(Duration::from_secs(5)),
        )
        .map(|_| ())
    })
}

#[test]
fn full_preauth_pool_sends_typed_busy_and_releases_its_slot_after_eof() -> Check {
    let home = Home::new()?;
    let (rt, mut listener, endpoint) = configured(&home, 4, 1)?;
    let first_endpoint = endpoint.clone();
    let (release, wait) = std::sync::mpsc::channel();
    let (seen, started) = std::sync::mpsc::channel();
    let stalled = std::thread::spawn(move || -> std::result::Result<(), String> {
        let work = || -> Check {
            let mut stream = raw_connect(&first_endpoint)?;
            let _ = challenge(&mut stream, &first_endpoint)?;
            seen.send(())?;
            wait.recv_timeout(Duration::from_secs(8))?;
            Ok(())
        };
        work().map_err(|e| e.to_string())
    });
    let outcome = rt.block_on(async {
        let accepted = listener.accept(Arc::new(AtomicBool::new(false))).await?;
        let first = tokio::spawn(async move { accepted.handshake().await.map(|_| ()) });
        tokio::time::timeout(Duration::from_secs(3), async {
            while started.try_recv().is_err() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let second = client(endpoint.clone());
        let accepted = tokio::time::timeout(
            Duration::from_millis(500),
            listener.accept(Arc::new(AtomicBool::new(false))),
        )
        .await??;
        let refused = accepted
            .handshake()
            .await
            .err()
            .ok_or("occupied preauth slot was admitted")?;
        let remote = second
            .join()
            .map_err(|_| "capacity client panicked")?
            .err()
            .ok_or("remote capacity client was admitted")?;
        assert!(
            busy(&refused) && busy(&remote),
            "capacity cause lost: local={refused}, remote={remote}"
        );
        assert!(!first.is_finished());
        release.send(())?;
        assert!(first.await?.is_err());
        let third = client(endpoint);
        let pending = listener
            .accept(Arc::new(AtomicBool::new(false)))
            .await?
            .handshake()
            .await?;
        let active = pending
            .finish(AuthorizedConnection { _private: () }, nonzero(4096)?)
            .await?;
        third
            .join()
            .map_err(|_| "recovered capacity client panicked")??;
        drop(active);
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    let _ = release.send(());
    let stalled = stalled
        .join()
        .map_err(|_| "stalled capacity client panicked")?;
    listener.close()?;
    outcome?;
    stalled.map_err(|e| -> Box<dyn std::error::Error> { e.into() })
}

#[test]
fn active_pool_busy_is_typed_while_fixed_stop_uses_no_operation_slot() -> Check {
    let home = Home::new()?;
    let (rt, mut listener, endpoint) = configured(&home, 1, 1)?;
    let outcome = rt.block_on(async {
        let first = client(endpoint.clone());
        let pending = listener
            .accept(Arc::new(AtomicBool::new(false)))
            .await?
            .handshake()
            .await?;
        let active = pending
            .finish(AuthorizedConnection { _private: () }, nonzero(4096)?)
            .await?;
        first
            .join()
            .map_err(|_| "active fixture client panicked")??;
        let second = client(endpoint.clone());
        let pending = listener
            .accept(Arc::new(AtomicBool::new(false)))
            .await?
            .handshake()
            .await?;
        let refused = pending
            .finish(AuthorizedConnection { _private: () }, nonzero(4096)?)
            .await
            .err()
            .ok_or("occupied active slot admitted")?;
        let remote = second
            .join()
            .map_err(|_| "active-capacity client panicked")?
            .err()
            .ok_or("remote active capacity client admitted")?;
        assert!(
            busy(&refused) && busy(&remote),
            "active-capacity cause lost: local={refused}, remote={remote}"
        );
        let stop_endpoint = endpoint.clone();
        let stop = std::thread::spawn(
            move || -> std::result::Result<codec::RuntimeStopReply, se_types::SeError> {
                BlockingIpcClient::stop(
                    &stop_endpoint,
                    &se_types::Secret::new(vec![1; 32])?,
                    se_types::IdempotencyKey::new("full-active-stop")?,
                    se_types::UnixMicros::new(1_800_000_000_000_000)?,
                    &options(Duration::from_secs(5)),
                )
            },
        );
        let mut pending = listener
            .accept(Arc::new(AtomicBool::new(false)))
            .await?
            .handshake()
            .await?;
        pending.verify_owner_mac(&secret(1)?)?;
        let HandshakeInput::Stop(request) = pending.input() else {
            return Err("fixed stop decoded as an operation".into());
        };
        let reply = codec::RuntimeStopReply {
            epoch: request.expected_epoch.clone(),
            generation: request.generation,
            key: request.key.clone(),
            outcome: codec::RuntimeStopOutcome::Refused { error: refusal()? },
        };
        pending
            .finish_stop(
                AuthorizedConnection { _private: () },
                &reply,
                &Deadline::from_options(&options(Duration::from_secs(5)))?,
            )
            .await?;
        assert!(matches!(
            stop.join()
                .map_err(|_| "stop capacity client panicked")??
                .outcome,
            codec::RuntimeStopOutcome::Refused { .. }
        ));
        drop(active);
        let recovered = client(endpoint);
        let pending = listener
            .accept(Arc::new(AtomicBool::new(false)))
            .await?
            .handshake()
            .await?;
        drop(
            pending
                .finish(AuthorizedConnection { _private: () }, nonzero(4096)?)
                .await?,
        );
        recovered
            .join()
            .map_err(|_| "released active client panicked")??;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    listener.close()?;
    outcome
}

#[test]
fn invalid_capacity_configuration_refuses_before_binding_the_endpoint() -> Check {
    let home = Home::new()?;
    let endpoint = home.record()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    for (active, preauth) in [(257, 1), (1, 2), (65, 65)] {
        assert!(
            IpcListener::bind_with_limits(
                endpoint.clone(),
                rt.handle().clone(),
                Arc::new(Semaphore::new(2)),
                &limits(active, preauth)?
            )
            .is_err()
        );
    }
    IpcListener::bind_with_limits(
        endpoint,
        rt.handle().clone(),
        Arc::new(Semaphore::new(2)),
        &limits(1, 1)?,
    )?
    .close()?;
    Ok(())
}
