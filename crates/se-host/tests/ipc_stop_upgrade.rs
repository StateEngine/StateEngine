#![cfg(feature = "listener")]
#[path = "support/ipc_fixture.rs"]
mod fixture;
use fixture::*;
use se_host::{
    client::{BlockingIpcClient, endpoint, lease::ClientCredential},
    *,
};
use std::{
    fs,
    process::{Command, Stdio},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

#[test]
#[ignore = "owned copied-image server, run only by the upgrade consumer"]
fn ipc_upgrade_server_fixture() -> Check {
    let root = std::env::var_os("SE_IPC_UPGRADE_JUDGE_HOME").ok_or("fixture admission absent")?;
    let home = Home::new()?;
    let (rt, mut server, record) = listener(&home)?;
    let record_path = std::path::Path::new(&root).join("endpoint");
    fs::write(
        record_path.with_extension("pending"),
        endpoint::encode_endpoint(&record)?.as_bytes(),
    )?;
    fs::rename(record_path.with_extension("pending"), &record_path)?;
    let outcome = rt.block_on(async {
        // Operation verification must fail before sending its hello after the
        // running image was moved and replaced; it cannot gain stop's exemption.
        let first = tokio::time::timeout(
            Duration::from_secs(10),
            server.accept(Arc::new(AtomicBool::new(false))),
        )
        .await??;
        assert!(
            first.handshake().await.is_err(),
            "upgraded operation image was admitted"
        );
        let mut stop = tokio::time::timeout(
            Duration::from_secs(10),
            server.accept(Arc::new(AtomicBool::new(false))),
        )
        .await??
        .handshake()
        .await?;
        assert!(matches!(stop.input(), HandshakeInput::Stop(_)));
        stop.verify_owner_mac(&secret(1)?)?;
        stop.refuse(refusal()?).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    server.close()?;
    outcome
}

#[test]
fn stop_keeps_exact_process_proof_across_real_executable_replacement() -> Check {
    let home = Home::new()?;
    let image = home.0.join(if cfg!(windows) {
        "installed-host.exe"
    } else {
        "installed-host"
    });
    fs::copy(std::env::current_exe()?, &image)?;
    let child = Command::new(&image)
        .args([
            "--exact",
            "ipc_upgrade_server_fixture",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SE_IPC_UPGRADE_JUDGE_HOME", &home.0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn_executable()?;
    let mut child = child;
    let deadline = Instant::now() + Duration::from_secs(10);
    let path = home.0.join("endpoint");
    while !path.try_exists()? {
        if child.try_wait()?.is_some() || Instant::now() >= deadline {
            let output = child.wait_with_output()?;
            return Err(format!(
                "copied server failed before endpoint: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let record = endpoint::decode_endpoint(&fs::read(&path)?)?;
    assert_eq!(record.epoch.owner.fields().pid.get(), child.id());
    fs::rename(&image, image.with_extension("previous"))?;
    fs::write(
        &image,
        b"a replacement image cannot inherit the old host's operation proof\n",
    )?;
    let operation = BlockingIpcClient::connect_authenticated(
        &record,
        ClientCredential::Machine(secret(1)?),
        nonzero(4096)?,
        &options(Duration::from_secs(5)),
    );
    let operation_refused = operation.is_err();
    let stop = BlockingIpcClient::stop(
        &record,
        &secret(1)?,
        se_types::IdempotencyKey::new("upgrade-stop-fixture")?,
        se_types::UnixMicros::new(1_800_000_000_000_000)?,
        &options(Duration::from_secs(5)),
    );
    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "copied-image server failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        operation_refused,
        "operation proof lost its image binding during upgrade"
    );
    assert!(
        matches!(stop?.outcome, endpoint::RuntimeStopOutcome::Refused { .. }),
        "authenticated stop did not reach the typed runtime refusal"
    );
    assert_eq!(
        fs::read(&image)?,
        b"a replacement image cannot inherit the old host's operation proof\n"
    );
    Ok(())
}

#[path = "../../test-support/executable.rs"]
mod executable;
use executable::ExecutableCommand;
