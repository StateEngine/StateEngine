//! A private byte custodian in the existing executable. This isolated transport
//! is not yet wired into agent launch, native scope recovery or durable replay.
pub mod protocol;
mod provider;

use crate::{
    AuthorizedConnection, BlockingPool, EndpointRecord, HandshakeInput, IpcConnection, IpcEnvelope,
    IpcListener, IpcRequest, IpcResponse, IpcResult, OperationOutput,
    client::{
        ClientOptions, endpoint,
        lease::{Deadline, native_error},
        wire,
    },
};
use protocol::Bootstrap;
use provider::Provider;
use se_types::{HostEpoch, ProcessFields, ProcessInstance, Result, SeError, Sha256};
use sha2::{Digest, Sha256 as Hasher};
use std::{
    io,
    num::NonZeroU32,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

pub const ENTRY: &str = "__se_session_runner";

pub fn private_entry() -> Result<()> {
    let payload = wire::read_payload(&mut io::stdin().lock(), protocol::BOOTSTRAP_LIMIT)?;
    let plan: Bootstrap = wire::decode_json(payload.as_bytes(), protocol::BOOTSTRAP_LIMIT)?;
    plan.validate()?;
    let parent = endpoint::decode_endpoint(
        &serde_json::to_vec(&plan.parent_endpoint).map_err(|_| invalid())?,
    )?;
    let bound = deadline()?.native_bound();
    let _parent_image = plan
        .parent_image
        .adopt(&parent.epoch.owner.fields().executable.to_local()?, &bound)
        .map_err(native_error)?;
    let _runner_image = plan
        .runner_image
        .adopt(
            &std::env::current_exe()
                .map_err(|error| wire::io_failure("locate runner image", error))?,
            &bound,
        )
        .map_err(native_error)?;
    let record = child_record(&parent)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        // Windows child stdio uses blocking I/O: two retained output reads
        // need independent slots from stdin writes and native IPC proof work.
        // This is a fixed I/O bound; the reactor stays on the current thread.
        .max_blocking_threads(if cfg!(windows) { 4 } else { 1 })
        .thread_keep_alive(Duration::ZERO)
        .build()
        .map_err(|error| wire::io_failure("start runner reactor", error))?;
    let blocking = BlockingPool::with_jobs(runtime.handle().clone(), positive(1)?)?;
    let listener = IpcListener::bind(
        record.clone(),
        runtime.handle().clone(),
        blocking.foreground_admission(),
    )?;
    let encoded = endpoint::encode_endpoint(&record)?;
    let ready: serde_json::Value = wire::decode_json(encoded.as_bytes(), wire::MAX_ENDPOINT_BYTES)?;
    wire::write_frame(
        &mut io::stdout().lock(),
        &wire::encode_frame(&ready, wire::MAX_ENDPOINT_BYTES)?,
    )?;
    runtime.block_on(run(plan, parent, listener, blocking))
}

fn child_record(parent: &EndpointRecord) -> Result<EndpointRecord> {
    let native = se_proc::current_runtime_identity(parent.epoch.owner.fields().machine.clone())
        .map_err(|error| SeError::invalid("runner native identity", &format!("{error:?}")))?;
    let peer = se_proc::native_ipc::observe_ipc_self().map_err(native_error)?;
    let mut argv = Hasher::new();
    for arg in std::env::args_os() {
        argv.update((arg.as_encoded_bytes().len() as u64).to_be_bytes());
        argv.update(arg.as_encoded_bytes());
    }
    let epoch = HostEpoch {
        owner: ProcessInstance::from_observation(ProcessFields {
            machine: native.process.machine,
            boot: native.boot_id,
            pid: positive(peer.pid())?,
            started: peer.started().clone(),
            executable: peer.image().clone(),
            argv_sha256: Sha256::from_bytes(argv.finalize().into()),
        })?,
        generation: parent.epoch.generation,
    };
    let mut record = parent.clone();
    record.epoch = epoch;
    record.image_sha256 = peer.image_sha256();
    record.package_version = env!("CARGO_PKG_VERSION").into();
    Ok(record)
}

async fn run(
    plan: Bootstrap,
    parent: EndpointRecord,
    mut listener: IpcListener,
    blocking: BlockingPool,
) -> Result<()> {
    let mut provider = None;
    let result = serve(&plan, &parent, &mut listener, &mut provider).await;
    let cleanup = match provider {
        Some(provider) => provider::bounded(provider.close()).await,
        None => Ok(()),
    };
    let close = listener.close_joined(&blocking, &deadline()?).await;
    result.and(cleanup).and(close)
}

async fn serve(
    plan: &Bootstrap,
    parent: &EndpointRecord,
    listener: &mut IpcListener,
    provider: &mut Option<Provider>,
) -> Result<()> {
    loop {
        let accepted = listener.accept(Arc::new(AtomicBool::new(false))).await?;
        let mut pending = match accepted.handshake().await {
            Ok(pending) => pending,
            Err(_) => continue,
        };
        // A purpose-specific per-launch key and the exact parent kernel peer
        // admit only this byte relay. They grant no runtime Owner operations.
        if !matches!(pending.input(), HandshakeInput::Call(_))
            || pending
                .peer()
                .native()
                .verify_instance(&parent.epoch.owner, parent.image_sha256)
                .is_err()
            || pending.verify_owner_mac(&plan.capability).is_err()
        {
            continue;
        }
        let mut connection = pending
            .finish(
                AuthorizedConnection { _private: () },
                positive(wire::DEFAULT_REPLY_BYTES)?,
            )
            .await?;
        if provider.is_none() {
            *provider = Some(Provider::spawn(plan)?);
        }
        let active = provider.as_mut().ok_or_else(invalid)?;
        if relay(&mut connection, active).await? {
            return Ok(());
        }
    }
}

async fn relay(connection: &mut IpcConnection, provider: &mut Provider) -> Result<bool> {
    loop {
        let Some((call, clock)) = (match connection.read_on_activity().await {
            Ok(call) => call,
            // A disconnected client does not close the provider's input.
            Err(_) => return Ok(false),
        }) else {
            return Ok(false);
        };
        let (value, finished) = dispatch(&call, provider).await?;
        let response = IpcResponse {
            version: call.version,
            request_id: call.request_id,
            generation: call.generation,
            result: IpcResult::Output(Box::new(OperationOutput {
                schema: "se.session-runner/v1".into(),
                value,
                window: None,
            })),
        };
        if connection.reply(&response, &clock).await.is_err() {
            return Ok(finished);
        }
        if finished {
            return Ok(true);
        }
    }
}

async fn dispatch(
    call: &IpcEnvelope,
    provider: &mut Provider,
) -> Result<(serde_json::Value, bool)> {
    if call.authority.is_some() || call.presence.is_some() || call.cli_selections.is_some() {
        return Err(invalid());
    }
    let IpcRequest::Operation(operation) = &call.request else {
        return Err(invalid());
    };
    match operation.name.as_str() {
        "relay.status" => Ok((serde_json::json!({"pid": provider.pid()?}), false)),
        "relay.write" => {
            let bytes: protocol::Write =
                serde_json::from_value(operation.arguments.clone()).map_err(|_| invalid())?;
            provider::bounded(provider.write(&bytes.bytes)).await?;
            Ok((serde_json::json!({"written": bytes.bytes.len()}), false))
        }
        "relay.read" => {
            let chunk = provider::bounded(provider.read()).await?;
            Ok((serde_json::to_value(chunk).map_err(|_| invalid())?, false))
        }
        "relay.finish" => Ok((provider::bounded(provider.finish()).await?, true)),
        _ => Err(invalid()),
    }
}

fn positive(value: u32) -> Result<NonZeroU32> {
    NonZeroU32::new(value).ok_or_else(invalid)
}
fn invalid() -> SeError {
    SeError::invalid(
        "session runner protocol",
        "only the bounded private byte relay",
    )
}
fn deadline() -> Result<Deadline> {
    Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(5),
        cancelled: Arc::new(AtomicBool::new(false)),
    })
}
