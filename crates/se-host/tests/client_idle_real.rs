//! Real native-runtime lease expiry, deliberately longer than the production idle timeout.
use se_host::{
    IpcEnvelope, IpcRequest, RawOperation,
    client::{
        BlockingConnection, BlockingIpcClient, ClientOptions, endpoint::decode_endpoint,
        lease::ClientCredential,
    },
};
use std::{
    fs,
    io::Write,
    num::NonZeroU32,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

type Check = Result<(), Box<dyn std::error::Error>>;
#[path = "support/idle_session.rs"]
mod idle_session;

fn status(
    connection: &mut BlockingConnection,
    options: &ClientOptions,
    id: u64,
    token: Option<&se_types::Secret>,
) -> Check {
    let output = connection.exchange(
        IpcEnvelope {
            version: connection.negotiated().version,
            request_id: id,
            generation: connection.negotiated().generation,
            authority: token
                .map(|token| {
                    se_types::Secret::new(token.expose().to_vec())
                        .map(se_host::PresentedAuthority::Session)
                })
                .transpose()?,
            presence: None,
            cli_selections: None,
            request: IpcRequest::Operation(RawOperation {
                name: "project.status".into(),
                arguments: serde_json::json!({}),
                key: None,
            }),
        },
        options,
    )?;
    assert_eq!(output.schema, "se.status/v1");
    Ok(())
}

#[test]
#[ignore = "waits beyond the real 300s server idle timeout; requires SE_IDLE_HOME with an owned running runtime"]
fn authenticated_client_renews_after_real_server_idle_expiry() -> Check {
    let home = PathBuf::from(std::env::var_os("SE_IDLE_HOME").ok_or("SE_IDLE_HOME absent")?);
    let endpoint = decode_endpoint(&fs::read(home.join("endpoint.json"))?)?;
    let options = ClientOptions {
        expected_generation: Some(endpoint.generation),
        timeout: Duration::from_secs(30),
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let mut connection = BlockingIpcClient::connect_authenticated(
        &endpoint,
        ClientCredential::Machine(se_types::Secret::new(fs::read(home.join("credential"))?)?),
        NonZeroU32::new(1_048_576).ok_or("zero reply budget")?,
        &options,
    )?;
    status(&mut connection, &options, 1, None)?;
    let started = Instant::now();
    println!("authenticated before real idle; waiting 305 seconds");
    std::io::stdout().flush()?;
    std::thread::sleep(Duration::from_secs(305));
    println!("real idle elapsed_ms={}", started.elapsed().as_millis());
    status(&mut connection, &options, 2, None)?;
    status(&mut connection, &options, 3, None)?;
    Ok(())
}

#[test]
#[ignore = "creates a protected session fixture in an explicitly owned stopped SE_IDLE_HOME"]
fn prepare_idle_session() -> Check {
    let home = PathBuf::from(std::env::var_os("SE_IDLE_HOME").ok_or("SE_IDLE_HOME absent")?);
    let init = PathBuf::from(std::env::var_os("SE_IDLE_INIT").ok_or("SE_IDLE_INIT absent")?);
    idle_session::prepare(&home, &init)
}

#[test]
#[ignore = "waits beyond the real 300s server idle timeout; requires the owned prepared session fixture"]
fn session_client_renews_reads_and_writes_after_real_idle_expiry() -> Check {
    let home = PathBuf::from(std::env::var_os("SE_IDLE_HOME").ok_or("SE_IDLE_HOME absent")?);
    let endpoint = decode_endpoint(&fs::read(home.join("endpoint.json"))?)?;
    let token = se_types::Secret::new(fs::read(home.join("idle-session-credential"))?)?;
    let options = ClientOptions {
        expected_generation: Some(endpoint.generation),
        timeout: Duration::from_secs(30),
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let connect = || {
        BlockingIpcClient::connect_authenticated(
            &endpoint,
            ClientCredential::Session(se_types::Secret::new(token.expose().to_vec())?),
            NonZeroU32::new(1_048_576)
                .ok_or_else(|| se_types::SeError::invalid("reply budget", "positive"))?,
            &options,
        )
    };
    let mut reader = connect()?;
    let mut writer = connect()?;
    status(&mut reader, &options, 1, Some(&token))?;
    status(&mut writer, &options, 1, Some(&token))?;
    let started = Instant::now();
    println!("two session clients authenticated; waiting 305 seconds");
    std::io::stdout().flush()?;
    std::thread::sleep(Duration::from_secs(305));
    println!(
        "real session idle elapsed_ms={}",
        started.elapsed().as_millis()
    );
    status(&mut reader, &options, 2, Some(&token))?;
    for id in [2, 3] {
        let op = se_core::ops::AnyOp::WorkingStateSet(se_core::commit::WorkingStateSet {
            text: "session write after real idle".into(),
            expect: se_core::commit::ExpectedRevision::Absent(
                se_core::commit::AbsentRevision::Absent,
            ),
            idempotency_key: se_types::IdempotencyKey::new("real-idle-session-write")?,
            owner_agent: None,
        });
        let expected = op.meta().family.schema();
        let key = op.idempotency_key().cloned();
        let name = op.meta().name.to_owned();
        let mut value = serde_json::to_value(op)?;
        let output = writer.exchange(
            IpcEnvelope {
                version: writer.negotiated().version,
                request_id: id,
                generation: writer.negotiated().generation,
                authority: Some(se_host::PresentedAuthority::Session(se_types::Secret::new(
                    token.expose().to_vec(),
                )?)),
                presence: None,
                cli_selections: None,
                request: IpcRequest::Operation(RawOperation {
                    name,
                    arguments: value.get_mut("input").ok_or("input absent")?.take(),
                    key,
                }),
            },
            &options,
        )?;
        assert_eq!(output.schema, expected);
        println!("session write {id}: {}", output.value);
    }
    Ok(())
}
