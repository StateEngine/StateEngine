#![allow(
    dead_code,
    reason = "Shared public host fixtures exercise different admission and shutdown consumers."
)]
use se_host::{
    client::{ClientOptions, lease::Deadline},
    *,
};
use se_store::*;
use se_types::{
    AgentId, HostEpoch, HostGeneration, LifecycleId, MachineId, ProcessFields, ProcessInstance,
};
use std::{
    io::Write,
    num::{NonZeroU16, NonZeroU32},
    sync::Arc,
    time::Duration,
};
#[path = "../../../se-store/tests/support/store_fixture.rs"]
pub mod fixture;
pub use fixture::*;
#[path = "../../../se-store/tests/support/wave2_control_fixture.rs"]
pub mod process;
#[path = "../../../se-store/tests/support/capture_fixture.rs"]
pub mod session;
pub fn positive(n: u32) -> Result<NonZeroU32, Box<dyn std::error::Error>> {
    NonZeroU32::new(n).ok_or_else(|| "zero limit".into())
}
pub fn options() -> ClientOptions {
    ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(20),
        cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    }
}
pub fn bound() -> Result<Deadline, Box<dyn std::error::Error>> {
    Ok(Deadline::from_options(&options())?)
}
pub fn now() -> Result<i64, Box<dyn std::error::Error>> {
    Ok(i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?)
}
pub fn seed(f: &Fixture) -> Check {
    let (direct, lease) = f.direct()?;
    direct.close()?;
    drop(lease);
    let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
    let mut staged = files.create_staging(&f.options.state_directory)?;
    staged.file.write_all(&[23; 32])?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, &f.options.state_directory.join("credential"))?;
    Ok(())
}
pub fn direct(f: &Fixture) -> Result<(SqliteDirect, Arc<Lease>), Box<dyn std::error::Error>> {
    let lease = Lease::acquire(
        &f.options.state_directory,
        LeaseMode::DirectClient,
        Some(f.store.clone()),
    )?;
    Ok((
        present(SqliteFactory::open_direct(&f.options, &*lease)?)?,
        lease,
    ))
}
pub fn credential(
    session: &se_types::SessionId,
    purpose: &str,
    secret: &str,
    expires: i64,
    activates: i64,
) -> Result<EventBody<InputText>, Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    Ok(EventBody::CredentialIssued {
        credential: session::record()?,
        session: session.clone(),
        purpose: purpose.into(),
        secret_sha256: Sha256::digest(secret.as_bytes()).into(),
        expires_at_us: expires,
        activation_deadline_us: activates,
        expected: Expected::Absent,
    })
}
pub fn start(f: &Fixture) -> Result<HostStart, Box<dyn std::error::Error>> {
    let machine = MachineId::new("read-phase-native-consumer")?;
    let native = se_proc::current_runtime_identity(machine.clone())
        .map_err(|e| format!("native runtime identity: {e:?}"))?;
    let peer = se_proc::native_ipc::observe_ipc_self()?;
    Ok(HostStart {
        state_directory: f.options.state_directory.clone(),
        epoch: HostEpoch {
            owner: ProcessInstance::from_observation(ProcessFields {
                machine,
                boot: native.boot_id,
                pid: positive(peer.pid())?,
                started: peer.started().clone(),
                executable: peer.image().clone(),
                argv_sha256: se_types::Sha256::from_bytes([0; 32]),
            })?,
            generation: HostGeneration::new(1)?,
        },
        kind: se_host::HostKind::Standalone,
        writer: WriterOptions {
            maximum_requests: NonZeroU16::new(4).ok_or("maximum requests")?,
            queue_requests: NonZeroU16::new(16).ok_or("queue requests")?,
            resident_bytes: positive(1024 * 1024)?,
            group_bytes: positive(1024 * 1024)?,
        },
        limits: se_host::HostLimits {
            sessions: positive(2)?,
            active_connections: positive(2)?,
            preauth_connections: positive(2)?,
            parked_mail_waits: positive(2)?,
            resident_queue_bytes: positive(1024 * 1024)?,
            session_notice_ids: positive(16)?,
            aggregate_notice_ids: positive(32)?,
            response_bytes: positive(1024 * 1024)?,
            blocking_jobs: positive(2)?,
        },
    })
}
/// Real TCP to the published listener; no private HTTP dispatcher is called.
pub async fn rpc(
    port: u16,
    bearer: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body =
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let raw = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
    stream.write_all(raw.as_bytes()).await?;
    let mut bytes = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(25),
        stream.take(1_048_577).read_to_end(&mut bytes),
    )
    .await??;
    if bytes.len() > 1_048_576 {
        return Err("HTTP response exceeded bound".into());
    }
    let split = bytes
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or("HTTP framing absent")?;
    let head = std::str::from_utf8(&bytes[..split])?;
    let mut body = &bytes[split + 4..];
    let mut decoded = Vec::new();
    if head
        .lines()
        .any(|line| line.eq_ignore_ascii_case("transfer-encoding: chunked"))
    {
        loop {
            let end = body
                .windows(2)
                .position(|b| b == b"\r\n")
                .ok_or("chunk size absent")?;
            let count = usize::from_str_radix(
                std::str::from_utf8(&body[..end])?
                    .split(';')
                    .next()
                    .ok_or("size")?,
                16,
            )?;
            body = &body[end + 2..];
            if count == 0 {
                break;
            }
            if body.len() < count + 2 || &body[count..count + 2] != b"\r\n" {
                return Err("truncated chunk".into());
            }
            decoded.extend_from_slice(&body[..count]);
            body = &body[count + 2..];
        }
        body = &decoded;
    }
    Ok(serde_json::from_slice(body)?)
}
pub fn require(ok: bool, reason: impl Into<String>) -> Check {
    if ok {
        Ok(())
    } else {
        Err(reason.into().into())
    }
}

/// Poll both public consumers on the caller's supplied runtime; no Tokio macro
/// feature or replacement executor is needed by the independent test.
pub async fn join<A: std::future::Future, B: std::future::Future>(
    a: A,
    b: B,
) -> (A::Output, B::Output) {
    use std::{future::poll_fn, task::Poll};
    let mut a = Box::pin(a);
    let mut b = Box::pin(b);
    let mut left = None;
    let mut right = None;
    poll_fn(move |cx| {
        if left.is_none()
            && let Poll::Ready(value) = a.as_mut().poll(cx)
        {
            left = Some(value);
        }
        if right.is_none()
            && let Poll::Ready(value) = b.as_mut().poll(cx)
        {
            right = Some(value);
        }
        match (left.take(), right.take()) {
            (Some(a), Some(b)) => Poll::Ready((a, b)),
            (a, b) => {
                left = a;
                right = b;
                Poll::Pending
            }
        }
    })
    .await
}

/// A store-only unresolved old session, with no claim of a real native child.
pub async fn old_stop_unproved(f: &Fixture, writer: &SqliteClient) -> Check {
    let old = session::session()?;
    let mut identity = process::identity(&f.a)?;
    identity.session = Some(old.clone());
    let receipt = writer
        .submit(f.batch(
            f.owner_project(),
            Some(super::fixture::request(&format!(
                "fixture-wave2_host_fixture-235-{}",
                serial()
            ))?),
            vec![
                session::prepared(f, &old, &f.a),
                process::registration(&identity, ProcessState::Starting),
            ],
        )?)?
        .await?;
    writer
        .submit(f.batch(
            f.owner_project(),
            Some(super::fixture::request(&format!(
                "fixture-wave2_host_fixture-245-{}",
                serial()
            ))?),
            vec![
                process::transition(
                    &identity,
                    1,
                    ProcessState::Starting,
                    ProcessState::StopRequested,
                    receipt.primary_event.clone(),
                )?,
                process::transition(
                    &identity,
                    2,
                    ProcessState::StopRequested,
                    ProcessState::StopUnproved,
                    receipt.primary_event,
                )?,
            ],
        )?)?
        .await?;
    Ok(())
}

/// Focused capture consumers use an explicit port without taking the legacy default.
pub fn configure_private_listener(host: &mut HostedRuntime) -> Check {
    for port in 20000..=29999 {
        if port != 20800
            && let Ok(probe) = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        {
            let mut configuration = se_core::config_policy::ConfigFile::default();
            configuration.runtime.listen_port = Some(probe.local_addr()?.port());
            host.configure(configuration)?;
            return Ok(());
        }
    }
    Err("no available explicit test listener port".into())
}
