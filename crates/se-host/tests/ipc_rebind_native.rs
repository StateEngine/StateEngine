//! Native listener preserves the seat selector and observes the actual process.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
#[path = "support/ipc_fixture.rs"]
mod fixture;
use fixture::*;
use se_host::{
    client::{BlockingIpcClient, endpoint},
    *,
};
use std::{
    fs,
    process::{Command, Stdio},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

#[test]
#[ignore = "spawned by the native rebind listener test"]
fn rebind_client() -> Check {
    let root = std::env::var_os("SE_REBIND_TEST_ROOT").ok_or("fixture root absent")?;
    let endpoint =
        endpoint::decode_endpoint(&fs::read(std::path::Path::new(&root).join("endpoint"))?)?;
    let project = se_types::ProjectId::from_parts(1_700_000_000_001, [1; 10])?;
    let agent = se_types::AgentId::from_parts(1_700_000_000_002, [2; 10])?;
    let result = BlockingIpcClient::rebind(
        &endpoint,
        &options(Duration::from_secs(20)),
        project,
        agent,
        "http://127.0.0.1:43123/".into(),
    );
    let error = result.err().ok_or("listener granted an unadmitted peer")?;
    assert!(error.to_string().contains("review admission"));
    Ok(())
}

#[test]
fn native_rebind_request_uses_the_connected_process_and_exact_seat() -> Check {
    let home = Home::new()?;
    let (rt, mut server, endpoint) = listener(&home)?;
    fs::write(
        home.0.join("endpoint"),
        endpoint::encode_endpoint(&endpoint)?.as_bytes(),
    )?;
    let child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "rebind_client",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SE_REBIND_TEST_ROOT", &*home.0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let expected_pid = child.id();
    let outcome = rt.block_on(async {
        let pending = tokio::time::timeout(
            Duration::from_secs(20),
            server.accept(Arc::new(AtomicBool::new(false))),
        )
        .await??
        .handshake()
        .await?;
        assert_eq!(pending.peer().native().pid(), expected_pid);
        assert_eq!(
            pending.peer().native().image_sha256(),
            endpoint.image_sha256
        );
        match pending.input() {
            HandshakeInput::Rebind(request) => {
                assert_eq!(
                    request.project_id,
                    se_types::ProjectId::from_parts(1_700_000_000_001, [1; 10])?
                );
                assert_eq!(
                    request.agent_id,
                    se_types::AgentId::from_parts(1_700_000_000_002, [2; 10])?
                );
                assert_eq!(request.control_endpoint, "http://127.0.0.1:43123/");
            }
            _ => return Err("rebind was decoded as another handshake family".into()),
        }
        pending.refuse(refusal()?).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    });
    let output = child.wait_with_output()?;
    server.close()?;
    outcome?;
    assert!(
        output.status.success(),
        "native client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
