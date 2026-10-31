#![cfg(feature = "listener")]
#[path = "support/ipc_fixture.rs"]
mod fixture;
use fixture::*;
use se_host::{
    client::{auth, endpoint, wire},
    *,
};
use std::{
    io::Write,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

#[cfg(unix)]
type Raw = std::os::unix::net::UnixStream;
#[cfg(windows)]
type Raw = se_proc::native_ipc::NativePipeStream;
fn raw_connect(endpoint: &EndpointRecord) -> Result<Raw, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        let IpcEndpoint::UnixSocket(path) = &endpoint.address else {
            return Err("Unix endpoint required".into());
        };
        let stream = Raw::connect(path.to_local()?)?;
        stream.set_read_timeout(Some(Duration::from_secs(8)))?;
        stream.set_write_timeout(Some(Duration::from_secs(8)))?;
        Ok(stream)
    }
    #[cfg(windows)]
    {
        let IpcEndpoint::WindowsPipe(name) = &endpoint.address else {
            return Err("Windows endpoint required".into());
        };
        Ok(Raw::connect(
            std::ffi::OsStr::new(name),
            bound(Duration::from_secs(8)),
        )?)
    }
}
fn listener(
    home: &Home,
) -> Result<(tokio::runtime::Runtime, IpcListener, EndpointRecord), Box<dyn std::error::Error>> {
    let endpoint = home.record()?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let listener = IpcListener::bind(
        endpoint.clone(),
        rt.handle().clone(),
        Arc::new(tokio::sync::Semaphore::new(2)),
    )?;
    Ok((rt, listener, endpoint))
}
fn challenge(
    stream: &mut Raw,
    endpoint: &EndpointRecord,
) -> Result<ServerChallenge, Box<dyn std::error::Error>> {
    let frame = wire::read_payload(stream, wire::MAX_ENDPOINT_BYTES)?;
    Ok(auth::decode_challenge(frame.as_bytes(), endpoint)?)
}

/// Every proof crosses the actual Tokio listener and native protected endpoint.
#[test]
fn wire_mac_binding_domains_and_cross_connection_replay_are_enforced() -> Check {
    for mode in [
        "valid",
        "wrong-key",
        "wrong-peer",
        "call-signed-stop",
        "stop-signed-owner",
        "valid-stop",
        "replay",
    ] {
        let home = Home::new()?;
        let (rt, mut server, endpoint) = listener(&home)?;
        let rounds = if mode == "replay" { 2 } else { 1 };
        let client = std::thread::spawn(move || -> Result<(), String> {
            let work = || -> Check {
                let mut replay = None;
                for round in 0..rounds {
                    let mut stream = raw_connect(&endpoint)?;
                    let challenge = challenge(&mut stream, &endpoint)?;
                    let bytes = if round == 1 {
                        replay.take().ok_or("first proof was not retained")?
                    } else {
                        let mut peer = se_proc::native_ipc::observe_ipc_self()?.binding();
                        if mode == "wrong-peer" {
                            peer.push(0);
                        }
                        let key = secret(if mode == "wrong-key" { 9 } else { 1 })?;
                        let nonce = [7; 32];
                        let stop = matches!(mode, "stop-signed-owner" | "valid-stop");
                        let domain = if matches!(mode, "call-signed-stop" | "valid-stop") {
                            auth::ProofDomain::RuntimeStop
                        } else {
                            auth::ProofDomain::Owner
                        };
                        let mac = auth::create_owner_mac(&key, domain, &challenge, &nonce, &peer)?;
                        let frame = if stop {
                            endpoint::encode_stop(&endpoint::RuntimeStopRequest {
                                expected_epoch: endpoint.epoch.clone(),
                                generation: endpoint.generation,
                                key: se_types::IdempotencyKey::new("native-stop-fixture")?,
                                deadline_at: se_types::UnixMicros::new(1_800_000_000_000_000)?,
                                nonce,
                                mac,
                            })?
                        } else {
                            auth::encode_client_hello(&ClientHello {
                                version: endpoint.api,
                                expected_generation: None,
                                maximum_reply_bytes: nonzero(4096)?,
                                authority: PresentedAuthority::OwnerProof { nonce, mac },
                            })?
                        };
                        frame.as_bytes().to_vec()
                    };
                    if mode == "replay" && round == 0 {
                        replay = Some(bytes.clone());
                    }
                    stream.write_all(&bytes)?;
                    let refusal = wire::read_payload(&mut stream, wire::MAX_FRAME_BYTES)?;
                    assert!(!refusal.as_bytes().is_empty());
                }
                Ok(())
            };
            work().map_err(|e| e.to_string())
        });
        let accepted = rt.block_on(async {
            for round in 0..rounds {
                let mut pending = server.accept(Arc::new(AtomicBool::new(false))).await?;
                let expected =
                    matches!(mode, "valid" | "valid-stop") || (mode == "replay" && round == 0);
                assert_eq!(
                    pending.verify_owner_mac(&secret(1)?).is_ok(),
                    expected,
                    "wire MAC admission: {mode}, round {round}"
                );
                assert!(
                    pending.verify_owner_mac(&secret(1)?).is_err(),
                    "consumed native challenge reused"
                );
                pending.refuse(refusal()?).await?;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        });
        let outcome = client.join().map_err(|_| "raw client panicked")?;
        server.close()?;
        accepted?;
        outcome.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    }
    Ok(())
}

#[test]
fn product_listener_refuses_closed_and_pre_auth_bounded_frames() -> Check {
    let mut failures = Vec::new();
    for mode in [
        "zero",
        "oversize",
        "pre-auth-oversize",
        "unknown",
        "duplicate",
        "deep",
        "utf8",
        "partial",
    ] {
        let home = Home::new()?;
        let (rt, mut server, endpoint) = listener(&home)?;
        let (release, wait) = std::sync::mpsc::channel();
        let client = std::thread::spawn(move || -> Result<(), String> {
            let work = || -> Check {
                let mut stream = raw_connect(&endpoint)?;
                let _challenge = challenge(&mut stream, &endpoint)?;
                let hello = auth::encode_client_hello(&ClientHello {
                    version: endpoint.api,
                    expected_generation: None,
                    maximum_reply_bytes: nonzero(4096)?,
                    authority: PresentedAuthority::Session(secret(3)?),
                })?;
                let text = String::from_utf8(payload(&hello)?)?;
                let body = match mode {
                    "unknown" => text.replacen('{', "{\"unknown\":true,", 1).into_bytes(),
                    "duplicate" => text
                        .replacen(
                            "\"maximum_reply_bytes\":4096",
                            "\"maximum_reply_bytes\":4096,\"maximum_reply_bytes\":4096",
                            1,
                        )
                        .into_bytes(),
                    "deep" => format!("{{\"padding\":{}null{}}}", "[".repeat(65), "]".repeat(65))
                        .into_bytes(),
                    "utf8" => vec![0xff],
                    _ => Vec::new(),
                };
                let length = match mode {
                    "zero" => 0,
                    "oversize" => wire::MAX_FRAME_BYTES + 1,
                    "pre-auth-oversize" => 16 * 1024 + 1,
                    "partial" => 100,
                    _ => body.len(),
                };
                stream.write_all(&(length as u32).to_be_bytes())?;
                stream.write_all(&body)?;
                if mode == "partial" {
                    drop(stream);
                } else {
                    let _ = wait.recv_timeout(Duration::from_secs(3));
                }
                Ok(())
            };
            work().map_err(|e| e.to_string())
        });
        let outcome = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_millis(500),
                server.accept(Arc::new(AtomicBool::new(false))),
            )
            .await
        });
        let _ = release.send(());
        let client_result = client.join().map_err(|_| "malformed client panicked")?;
        let refused = matches!(outcome.as_ref(), Ok(Err(_)));
        drop(outcome);
        server.close()?;
        client_result.map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        if !refused {
            failures.push(mode);
        }
    }
    assert!(
        failures.is_empty(),
        "malformed pre-auth frames accepted or oversized bodies awaited: {failures:?}"
    );
    Ok(())
}

#[test]
fn silent_peer_cannot_retain_the_listener_accept_slot() -> Check {
    let home = Home::new()?;
    let (rt, mut server, endpoint) = listener(&home)?;
    let (release, wait) = std::sync::mpsc::channel();
    let client = std::thread::spawn(move || -> Result<(), String> {
        let _stream = raw_connect(&endpoint).map_err(|e| e.to_string())?;
        let _ = wait.recv_timeout(Duration::from_secs(3));
        Ok(())
    });
    let outcome = rt.block_on(async {
        tokio::time::timeout(
            Duration::from_millis(500),
            server.accept(Arc::new(AtomicBool::new(false))),
        )
        .await
    });
    let _ = release.send(());
    client
        .join()
        .map_err(|_| "silent client panicked")?
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let accepted = matches!(outcome.as_ref(), Ok(Ok(_)));
    drop(outcome);
    server.close()?;
    assert!(
        accepted,
        "OS accept retained the listener slot while waiting for an unauthenticated peer"
    );
    Ok(())
}
