#![cfg(feature = "listener")]
#[path = "support/ipc_fixture.rs"]
mod fixture;
use fixture::*;
use se_host::{
    client::{BlockingIpcClient, endpoint, lease::ClientCredential},
    *,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    process::{Child, Command, Stdio},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

#[test]
#[ignore = "copied-image native client, invoked by boundary/cache consumers"]
fn ipc_native_boundary_client() -> Check {
    let root = std::env::var_os("SE_IPC_NATIVE_JUDGE_ROOT").ok_or("fixture root absent")?;
    let root = std::path::Path::new(&root);
    let endpoint = endpoint::decode_endpoint(&fs::read(root.join("endpoint"))?)?;
    if std::env::var_os("SE_IPC_NATIVE_OVERSIZED").is_some() {
        let mut stream = raw_connect(&endpoint)?;
        assert_eq!(
            stream.read(&mut [0])?,
            0,
            "oversized peer received a challenge"
        );
        return Ok(());
    }
    fs::write(
        root.join("client-binding"),
        se_proc::native_ipc::observe_ipc_self()?.binding(),
    )?;
    let outcome = BlockingIpcClient::connect_authenticated(
        &endpoint,
        ClientCredential::Machine(secret(1)?),
        nonzero(4096)?,
        &options(Duration::from_secs(5)),
    );
    let error = outcome
        .err()
        .ok_or("pending boundary client bypassed runtime admission")?;
    assert!(
        error.to_string().contains("review admission"),
        "client failed before the typed runtime refusal: {error}"
    );
    Ok(())
}
fn child(
    image: &std::path::Path,
    root: &std::path::Path,
    oversized: bool,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(image);
    command
        .args([
            "--exact",
            "ipc_native_boundary_client",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SE_IPC_NATIVE_JUDGE_ROOT", root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if oversized {
        command.env("SE_IPC_NATIVE_OVERSIZED", "1");
    }
    Ok(command.spawn_executable()?)
}
fn joined(child: Child) -> Check {
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "native boundary child: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
fn publish(home: &Home, endpoint: &EndpointRecord) -> Check {
    fs::write(
        home.0.join("endpoint"),
        endpoint::encode_endpoint(endpoint)?.as_bytes(),
    )?;
    Ok(())
}
fn admitted_peer(
    rt: &tokio::runtime::Runtime,
    listener: &mut IpcListener,
    child: Child,
    home: &Home,
    expected: se_types::Sha256,
) -> Check {
    let outcome = rt.block_on(async {
        let mut pending = tokio::time::timeout(
            Duration::from_secs(7),
            listener.accept(Arc::new(AtomicBool::new(false))),
        )
        .await??
        .handshake()
        .await?;
        assert_eq!(
            pending.peer().native().pid(),
            child.id(),
            "actual other-process native PID was replaced by observer identity"
        );
        assert_eq!(
            pending.peer().native().image_sha256(),
            expected,
            "native image cache returned stale content"
        );
        assert_eq!(
            pending.peer().native().binding(),
            fs::read(home.0.join("client-binding"))?,
            "client/server native binding disagreed"
        );
        pending.verify_owner_mac(&secret(1)?)?;
        pending.refuse(refusal()?).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    let joined = joined(child);
    outcome?;
    joined
}
fn digest(path: &std::path::Path) -> Result<se_types::Sha256, Box<dyn std::error::Error>> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut block = [0; 65536];
    loop {
        let n = file.read(&mut block)?;
        if n == 0 {
            break;
        }
        hash.update(&block[..n]);
    }
    Ok(se_types::Sha256::from_bytes(hash.finalize().into()))
}

#[test]
fn actual_cross_process_credentials_and_image_binding_reach_the_product_listener() -> Check {
    let home = Home::new()?;
    let (rt, mut server, endpoint) = listener(&home)?;
    publish(&home, &endpoint)?;
    let child = child(&std::env::current_exe()?, &home.0, false)?;
    let outcome = admitted_peer(&rt, &mut server, child, &home, endpoint.image_sha256);
    server.close()?;
    outcome
}

#[cfg(target_os = "linux")]
#[test]
fn oversized_real_peer_is_refused_before_challenge_or_content_hashing() -> Check {
    let home = Home::new()?;
    let (rt, mut server, endpoint) = listener(&home)?;
    publish(&home, &endpoint)?;
    let image = home.0.join("oversized-peer");
    fs::copy(std::env::current_exe()?, &image)?;
    fs::OpenOptions::new()
        .write(true)
        .open(&image)?
        .set_len(512 * 1024 * 1024 + 1)?;
    let child = child(&image, &home.0, true)?;
    let outcome = rt.block_on(async {
        let accepted = server.accept(Arc::new(AtomicBool::new(false))).await?;
        tokio::time::timeout(Duration::from_secs(2), accepted.handshake())
            .await?
            .err()
            .ok_or_else(|| -> Box<dyn std::error::Error> { "oversized peer admitted".into() })
    });
    let joined = joined(child);
    server.close()?;
    let error = outcome?;
    assert!(
        error.to_string().contains("512 MiB"),
        "oversized refusal lost its cause: {error}"
    );
    joined
}

#[test]
fn image_cache_invalidates_same_inode_changes_and_same_metadata_replacements() -> Check {
    let home = Home::new()?;
    let (rt, mut server, endpoint) = listener(&home)?;
    publish(&home, &endpoint)?;
    let source = std::env::current_exe()?;
    let image = home.0.join(if cfg!(windows) {
        "cached-peer.exe"
    } else {
        "cached-peer"
    });
    fs::copy(&source, &image)?;
    fs::OpenOptions::new()
        .append(true)
        .open(&image)?
        .write_all(b"A")?;
    let first_time = fs::metadata(&image)?.modified()?;
    let size = fs::metadata(&image)?.len();
    let first = digest(&image)?;
    admitted_peer(
        &rt,
        &mut server,
        child(&image, &home.0, false)?,
        &home,
        first,
    )?;
    // Change content in the same file object, preserving size. Its mtime must
    // invalidate the retained entry even though the pathname and inode agree.
    {
        use std::io::{Seek, SeekFrom};
        let mut file = fs::OpenOptions::new().write(true).open(&image)?;
        file.seek(SeekFrom::End(-1))?;
        file.write_all(b"B")?;
        file.sync_all()?;
        file.set_times(fs::FileTimes::new().set_modified(first_time + Duration::from_secs(2)))?;
    }
    let second_time = fs::metadata(&image)?.modified()?;
    assert_ne!(first_time, second_time);
    assert_eq!(fs::metadata(&image)?.len(), size);
    let second = digest(&image)?;
    assert_ne!(first, second);
    admitted_peer(
        &rt,
        &mut server,
        child(&image, &home.0, false)?,
        &home,
        second,
    )?;
    // Retain the old object under another name, so the new object cannot reuse
    // its identity. Match mtime and size to make native file identity essential.
    fs::rename(&image, image.with_extension("previous"))?;
    fs::copy(&source, &image)?;
    fs::OpenOptions::new()
        .append(true)
        .open(&image)?
        .write_all(b"C")?;
    fs::OpenOptions::new()
        .write(true)
        .open(&image)?
        .set_times(fs::FileTimes::new().set_modified(second_time))?;
    assert_eq!(fs::metadata(&image)?.modified()?, second_time);
    assert_eq!(fs::metadata(&image)?.len(), size);
    let third = digest(&image)?;
    assert_ne!(second, third);
    let outcome = admitted_peer(
        &rt,
        &mut server,
        child(&image, &home.0, false)?,
        &home,
        third,
    );
    server.close()?;
    outcome
}

#[test]
fn native_client_timeout_cancellation_and_reuse_survive_idle_tokio_accept() -> Check {
    use se_proc::native_ipc::*;
    let home = Home::new()?;
    let (rt, mut server, endpoint) = listener(&home)?;
    rt.block_on(async {
        assert!(
            tokio::time::timeout(
                Duration::from_millis(30),
                server.accept(Arc::new(AtomicBool::new(false)))
            )
            .await
            .is_err()
        );
    });
    let client = std::thread::spawn(move || -> Result<(), String> {
        let work = || -> Check {
            #[cfg(unix)]
            let mut stream = match &endpoint.address {
                IpcEndpoint::UnixSocket(path) => {
                    NativeUnixStream::connect(&path.to_local()?, bound(Duration::from_secs(5)))?
                }
                _ => return Err("Unix endpoint absent".into()),
            };
            #[cfg(windows)]
            let mut stream = match &endpoint.address {
                IpcEndpoint::WindowsPipe(name) => NativePipeStream::connect(
                    std::ffi::OsStr::new(name),
                    bound(Duration::from_secs(5)),
                )?,
                _ => return Err("Windows endpoint absent".into()),
            };
            let _ = se_host::client::wire::read_payload(
                &mut stream,
                se_host::client::wire::MAX_ENDPOINT_BYTES,
            )?;
            stream.set_bound(bound(Duration::from_millis(30)));
            assert_eq!(
                stream
                    .read(&mut [0])
                    .err()
                    .ok_or("idle native read succeeded")?
                    .kind(),
                std::io::ErrorKind::TimedOut
            );
            let cancelled = bound(Duration::from_secs(5));
            cancelled
                .cancelled
                .store(true, std::sync::atomic::Ordering::Release);
            stream.set_bound(cancelled);
            assert_eq!(
                stream
                    .read(&mut [0])
                    .err()
                    .ok_or("cancelled native read succeeded")?
                    .kind(),
                std::io::ErrorKind::Interrupted
            );
            stream.set_bound(bound(Duration::from_secs(5)));
            let hello = se_host::client::auth::encode_client_hello(&ClientHello {
                version: endpoint.api,
                expected_generation: None,
                maximum_reply_bytes: nonzero(4096)?,
                authority: PresentedAuthority::Session(secret(3)?),
            })?;
            stream.write_all(hello.as_bytes())?;
            let refusal = se_host::client::wire::read_payload(
                &mut stream,
                se_host::client::wire::MAX_ENDPOINT_BYTES,
            )?;
            assert!(!refusal.as_bytes().is_empty());
            Ok(())
        };
        work().map_err(|e| e.to_string())
    });
    let outcome = rt.block_on(async {
        let pending = server
            .accept(Arc::new(AtomicBool::new(false)))
            .await?
            .handshake()
            .await?;
        pending.refuse(refusal()?).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    let client = client
        .join()
        .map_err(|_| "bounded native client panicked")?;
    server.close()?;
    outcome?;
    client.map_err(|e| -> Box<dyn std::error::Error> { e.into() })
}

#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
