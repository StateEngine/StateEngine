#![cfg(feature = "listener")]
#[path = "support/ipc_fixture.rs"]
mod fixture;
use fixture::*;
use se_host::{
    client::{auth, wire},
    *,
};
use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[test]
fn stalled_handshake_does_not_delay_a_normal_native_client() -> Check {
    let home = Home::new()?;
    let (rt, mut server, endpoint) = listener(&home)?;
    let (release, wait) = std::sync::mpsc::channel();
    let (seen, started) = std::sync::mpsc::channel();
    let first_endpoint = endpoint.clone();
    let stalled = std::thread::spawn(move || -> Result<(), String> {
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
        let accepted = tokio::time::timeout(
            Duration::from_secs(1),
            server.accept(Arc::new(AtomicBool::new(false))),
        )
        .await??;
        let first = tokio::spawn(async move { accepted.handshake().await.map(|_| ()) });
        tokio::time::timeout(Duration::from_secs(3), async {
            while started.try_recv().is_err() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let normal = std::thread::spawn(move || -> Result<(), String> {
            let work = || -> Check {
                let mut stream = raw_connect(&endpoint)?;
                let proof = challenge(&mut stream, &endpoint)?;
                let nonce = [6; 32];
                let mac = auth::create_owner_mac(
                    &secret(1)?,
                    auth::ProofDomain::Owner,
                    &proof,
                    &nonce,
                    &se_proc::native_ipc::observe_ipc_self()?.binding(),
                )?;
                let hello = auth::encode_client_hello(&ClientHello {
                    version: endpoint.api,
                    expected_generation: None,
                    maximum_reply_bytes: nonzero(4096)?,
                    authority: PresentedAuthority::OwnerProof { nonce, mac },
                })?;
                stream.write_all(hello.as_bytes())?;
                let frame = wire::read_payload(&mut stream, wire::MAX_FRAME_BYTES)?;
                assert!(!frame.as_bytes().is_empty());
                Ok(())
            };
            work().map_err(|e| e.to_string())
        });
        let begin = Instant::now();
        let admitted = tokio::time::timeout(Duration::from_millis(750), async {
            let mut second = server
                .accept(Arc::new(AtomicBool::new(false)))
                .await?
                .handshake()
                .await?;
            second.verify_owner_mac(
                &secret(1).map_err(|_| se_types::SeError::invalid("fixture key", "32 bytes"))?,
            )?;
            second
                .refuse(
                    refusal().map_err(|_| {
                        se_types::SeError::invalid("fixture refusal", "typed error")
                    })?,
                )
                .await
        })
        .await;
        assert!(
            !first.is_finished(),
            "stalled peer ended before the normal-client isolation witness"
        );
        let _ = release.send(());
        let rejected = first.await?;
        let normal = normal.join().map_err(|_| "normal client panicked")?;
        assert!(rejected.is_err(), "EOF without hello was admitted");
        admitted??;
        normal.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        assert!(begin.elapsed() < Duration::from_secs(1));
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    let _ = release.send(());
    let stalled = stalled.join().map_err(|_| "stalled client panicked")?;
    server.close()?;
    outcome?;
    stalled.map_err(|e| -> Box<dyn std::error::Error> { e.into() })
}

#[test]
fn trickled_hello_does_not_renew_the_absolute_native_deadline() -> Check {
    let home = Home::new()?;
    let (rt, mut server, endpoint) = listener(&home)?;
    let done = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&done);
    let client = std::thread::spawn(move || -> Result<(), String> {
        let work = || -> Check {
            let mut stream = raw_connect(&endpoint)?;
            let _ = challenge(&mut stream, &endpoint)?;
            stream.write_all(&1000u32.to_be_bytes())?;
            while !stop.load(Ordering::Acquire) {
                if stream.write_all(b" ").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(())
        };
        work().map_err(|e| e.to_string())
    });
    let begin = Instant::now();
    let outcome = rt.block_on(async {
        let accepted = server.accept(Arc::new(AtomicBool::new(false))).await?;
        Ok::<_, se_types::SeError>(
            tokio::time::timeout(Duration::from_secs(7), accepted.handshake()).await,
        )
    });
    done.store(true, Ordering::Release);
    let client = client.join().map_err(|_| "trickle client panicked")?;
    let elapsed = begin.elapsed();
    server.close()?;
    let refusal = outcome??;
    let error = match refusal {
        Ok(_) => return Err("partial hello was admitted".into()),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("deadline"),
        "slow hello did not refuse at its absolute deadline: {error}"
    );
    assert!(
        elapsed >= Duration::from_secs(4) && elapsed < Duration::from_millis(6500),
        "trickle renewed or bypassed hello clock: {elapsed:?}"
    );
    client.map_err(|e| -> Box<dyn std::error::Error> { e.into() })
}
