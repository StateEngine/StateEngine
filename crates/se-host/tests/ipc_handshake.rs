#![cfg(feature = "listener")]
#[path = "support/ipc_fixture.rs"]
mod fixture;
use fixture::*;
use se_host::{
    client::{BlockingIpcClient, lease::ClientCredential},
    *,
};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

fn handshake(machine: bool, wrong_key: bool) -> Check {
    let home = Home::new()?;
    let endpoint = home.record()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut listener = IpcListener::bind(
        endpoint.clone(),
        rt.handle().clone(),
        Arc::new(tokio::sync::Semaphore::new(2)),
    )?;
    let credential = if machine {
        ClientCredential::Machine(secret(if wrong_key { 2 } else { 1 })?)
    } else {
        ClientCredential::Session(secret(3)?)
    };
    let budget = nonzero(4096)?;
    let client = std::thread::spawn(move || {
        BlockingIpcClient::connect_authenticated(
            &endpoint,
            credential,
            budget,
            &options(Duration::from_secs(5)),
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    });
    let accepted = rt.block_on(async {
        let mut pending = tokio::time::timeout(
            Duration::from_secs(10),
            listener.accept(Arc::new(AtomicBool::new(false))),
        )
        .await??
        .handshake()
        .await?;
        assert_eq!(pending.peer().native().pid(), std::process::id());
        match pending.input() {
            HandshakeInput::Call(hello) => {
                assert_eq!(
                    matches!(hello.authority, PresentedAuthority::OwnerProof { .. }),
                    machine
                );
            }
            _ => return Err("operation hello decoded as a stop request".into()),
        }
        let first = pending.verify_owner_mac(&secret(1)?);
        assert_eq!(first.is_ok(), machine && !wrong_key);
        assert!(
            pending.verify_owner_mac(&secret(1)?).is_err(),
            "a consumed or absent owner challenge was reused"
        );
        pending.refuse(refusal()?).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    let outcome = client.join().map_err(|_| "blocking client panicked")?;
    listener.close()?;
    accepted?;
    assert!(
        outcome.is_err(),
        "a pending handshake bypassed runtime authorization"
    );
    let text = outcome.err().ok_or("missing refusal")?;
    assert!(
        !text.contains("[1, 1, 1"),
        "credential bytes appeared in a refusal"
    );
    Ok(())
}

/// Protects: 40 §7 — a genuine native connection proves its machine MAC once and still requires runtime authorization.
#[test]
fn machine_handshake_verifies_native_bound_proof_and_transmits_typed_refusal() -> Check {
    handshake(true, false)
}

/// Protects: 40 §7 — a failed machine MAC consumes its challenge and cannot become an authorized connection.
#[test]
fn wrong_machine_key_cannot_reuse_a_challenge() -> Check {
    handshake(true, true)
}

/// Protects: 40 §7 — a supplied session credential has no fallback to machine authority.
#[test]
fn session_handshake_has_no_machine_authority_fallback() -> Check {
    handshake(false, false)
}
