#![allow(
    dead_code,
    reason = "Shared fixtures serve codecs and native transport test binaries."
)]
use se_host::*;
#[cfg(unix)]
use se_types::NativePath;
use se_types::{
    API_VERSION, BootId, ErrorEnvelope, Generation, HostEpoch, HostGeneration, IdempotencyKey,
    MachineId, ProcessFields, ProcessInstance, RenderCx, SeError, Secret, Sha256,
};
use std::{
    error::Error,
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64},
    },
    time::{Duration, Instant},
};
#[path = "../../../test-support/directory.rs"]
#[allow(
    clippy::duplicate_mod,
    reason = "Independent fixture modules also compile together in native unit tests."
)]
mod directory;
#[cfg(windows)]
use std::sync::atomic::Ordering;
pub type Check = Result<(), Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(1);
static FIXTURES: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub struct Home(
    pub directory::PrivateDirectory,
    #[allow(
        dead_code,
        reason = "Avoids concurrent native image hashing in bounded handshake fixtures."
    )]
    std::sync::MutexGuard<'static, ()>,
);
impl Home {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let guard = FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
        let path = directory::private_directory()?;
        Ok(Self(path, guard))
    }
    pub fn record(&self) -> Result<EndpointRecord, Box<dyn Error>> {
        let observed = se_proc::native_ipc::observe_ipc_self()?;
        #[cfg(unix)]
        let address = IpcEndpoint::UnixSocket(NativePath::from_local(self.0.join("ipc"))?);
        #[cfg(windows)]
        let address = IpcEndpoint::WindowsPipe(format!(
            r"\\.\pipe\se-test-ipc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let epoch = HostEpoch {
            owner: ProcessInstance::from_observation(ProcessFields {
                machine: MachineId::new("ipc-review-host")?,
                boot: BootId::new("native-start-observation")?,
                pid: NonZeroU32::new(observed.pid()).ok_or("PID zero")?,
                started: observed.started().clone(),
                executable: observed.image().clone(),
                argv_sha256: Sha256::from_bytes([0; 32]),
            })?,
            generation: HostGeneration::new(7)?,
        };
        Ok(EndpointRecord {
            schema: 1,
            address,
            epoch,
            generation: Generation::new(11)?,
            kind: HostKind::Standalone,
            listener_port: None,
            api: API_VERSION,
            package_version: "0.0.1".into(),
            image_sha256: observed.image_sha256(),
        })
    }
}
pub fn options(timeout: Duration) -> client::ClientOptions {
    client::ClientOptions {
        expected_generation: None,
        timeout,
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
pub fn bound(timeout: Duration) -> se_proc::native_ipc::IpcIoBound {
    se_proc::native_ipc::IpcIoBound {
        deadline: Instant::now() + timeout,
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
pub fn call() -> Result<IpcEnvelope, Box<dyn Error>> {
    Ok(IpcEnvelope {
        version: API_VERSION,
        request_id: 9,
        generation: Generation::new(11)?,
        authority: None,
        presence: None,
        cli_selections: None,
        request: IpcRequest::Operation(RawOperation {
            name: "working-state.set".into(),
            arguments: serde_json::json!({"text":"a visible effect"}),
            key: Some(IdempotencyKey::new("opaque/key:9-vs-transport-9")?),
        }),
    })
}
pub fn response() -> Result<IpcResponse, Box<dyn Error>> {
    Ok(IpcResponse {
        version: API_VERSION,
        request_id: 9,
        generation: Generation::new(11)?,
        result: IpcResult::Output(Box::new(OperationOutput {
            schema: "se.test/v1".into(),
            value: serde_json::json!({"through":"opaque-position"}),
            window: None,
        })),
    })
}
pub fn payload(frame: &client::wire::WireBytes) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(client::wire::read_payload(
        &mut std::io::Cursor::new(frame.as_bytes()),
        client::wire::MAX_FRAME_BYTES,
    )?
    .as_bytes()
    .to_vec())
}
pub fn refusal() -> Result<ErrorEnvelope, Box<dyn Error>> {
    Ok(ErrorEnvelope::new(
        SeError::invalid("review admission", "a joined runtime authorization").body,
        &RenderCx {
            project: None,
            agent: None,
            commands: None,
        },
    )?)
}
pub fn secret(byte: u8) -> Result<Secret, Box<dyn Error>> {
    Ok(Secret::new(vec![byte; 32])?)
}
pub fn nonzero(value: u32) -> Result<NonZeroU32, Box<dyn Error>> {
    NonZeroU32::new(value).ok_or_else(|| "zero bound".into())
}

#[cfg(unix)]
pub type Raw = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type Raw = se_proc::native_ipc::NativePipeStream;
pub fn raw_connect(endpoint: &EndpointRecord) -> Result<Raw, Box<dyn std::error::Error>> {
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
pub fn listener(
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
pub fn challenge(
    stream: &mut Raw,
    endpoint: &EndpointRecord,
) -> Result<ServerChallenge, Box<dyn std::error::Error>> {
    let frame = client::wire::read_payload(stream, client::wire::MAX_ENDPOINT_BYTES)?;
    Ok(client::auth::decode_challenge(frame.as_bytes(), endpoint)?)
}
