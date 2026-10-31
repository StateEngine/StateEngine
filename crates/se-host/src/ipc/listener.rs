//! Evented transport on the supplied runtime. Native proof work shares the
//! caller's bounded blocking admission; this module creates no runtime/thread.
use super::*;
#[path = "listener/channel.rs"]
mod channel;
use crate::client::{
    auth, endpoint as codec,
    lease::{Deadline, HELLO_TIMEOUT, WRITE_TIMEOUT, native_error},
    wire,
};
use channel::{bounded, receive, send};
use se_types::{Result, SeError};
use std::sync::{Arc, atomic::AtomicBool};
use tokio::{runtime::Handle, sync::Semaphore};
#[cfg(unix)]
type NativeEndpoint = se_proc::native_ipc::NativeUnixEndpoint;
#[cfg(windows)]
type NativeEndpoint = se_proc::native_ipc::NativePipeReservation;
#[cfg(unix)]
type NativeListener = tokio::net::UnixListener;
#[cfg(windows)]
type NativeListener = tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(unix)]
type NativeStream = tokio::net::UnixStream;
#[cfg(windows)]
type NativeStream = tokio::net::windows::named_pipe::NamedPipeServer;

pub struct IpcListener {
    native: NativeEndpoint,
    listener: NativeListener,
    record: EndpointRecord,
    runtime: Handle,
    blocking: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    preauth: Arc<Semaphore>,
    incoming: Arc<Semaphore>,
}
#[cfg(windows)]
fn evented_pipe(native: &NativeEndpoint) -> Result<NativeListener> {
    let pipe = tokio::net::windows::named_pipe::ServerOptions::new()
        .reject_remote_clients(true)
        .in_buffer_size(65536)
        .out_buffer_size(65536)
        .create(native.name())
        .map_err(|e| wire::io_failure("create protected evented pipe", e))?;
    use std::os::windows::io::AsHandle;
    native
        .verify_reactor_instance(pipe.as_handle())
        .map_err(native_error)?;
    Ok(pipe)
}
impl IpcListener {
    /// Call through bounded native preparation, before publishing endpoint.json.
    /// Windows keeps an occupied, protected first instance while the supplied
    /// Tokio reactor owns all application instances; no host handle cast occurs.
    pub fn bind(record: EndpointRecord, runtime: Handle, blocking: Arc<Semaphore>) -> Result<Self> {
        Self::bind_capacity(record, runtime, blocking, 32, 8)
    }
    /// Separate unauthenticated and authenticated capacities, supplied by the
    /// host configuration. A half-open channel never consumes an active slot.
    pub fn bind_with_limits(
        record: EndpointRecord,
        runtime: Handle,
        blocking: Arc<Semaphore>,
        limits: &crate::HostLimits,
    ) -> Result<Self> {
        Self::bind_capacity(
            record,
            runtime,
            blocking,
            limits.active_connections.get() as usize,
            limits.preauth_connections.get() as usize,
        )
    }
    fn bind_capacity(
        record: EndpointRecord,
        runtime: Handle,
        blocking: Arc<Semaphore>,
        active: usize,
        preauth: usize,
    ) -> Result<Self> {
        if active == 0 || active > 256 || preauth == 0 || preauth > active || preauth > 64 {
            return Err(SeError::invalid(
                "IPC capacities",
                "1..=256 active connections and 1..=min(active,64) pre-authentication connections",
            ));
        }
        codec::encode_endpoint(&record)?;
        if record.api != se_types::API_VERSION {
            return Err(SeError::invalid(
                "endpoint API",
                "this host's exact operation API",
            ));
        }
        se_proc::native_ipc::observe_ipc_self()
            .map_err(native_error)?
            .verify_instance(&record.epoch.owner, record.image_sha256)
            .map_err(native_error)?;
        let _entered = runtime.enter();
        #[cfg(unix)]
        let (native, listener) = match &record.address {
            IpcEndpoint::UnixSocket(path) => {
                let native = NativeEndpoint::bind(&path.to_local()?).map_err(native_error)?;
                let listener =
                    NativeListener::from_std(native.reactor_listener().map_err(native_error)?)
                        .map_err(|e| wire::io_failure("register native IPC listener", e))?;
                (native, listener)
            }
            _ => return Err(SeError::invalid("IPC endpoint", "a native Unix socket")),
        };
        #[cfg(windows)]
        let (native, listener) = match &record.address {
            IpcEndpoint::WindowsPipe(name) => {
                let native =
                    NativeEndpoint::create(std::ffi::OsStr::new(name)).map_err(native_error)?;
                let listener = evented_pipe(&native)?;
                (native, listener)
            }
            _ => return Err(SeError::invalid("IPC endpoint", "a local Windows pipe")),
        };
        drop(_entered);
        Ok(Self {
            native,
            listener,
            record,
            runtime,
            blocking,
            connections: Arc::new(Semaphore::new(active)),
            preauth: Arc::new(Semaphore::new(preauth)),
            // One additional incoming channel can deliver a typed capacity
            // refusal while every pre-authentication slot is occupied.
            incoming: Arc::new(Semaphore::new(preauth + 1)),
        })
    }
    /// The caller can cancel idle accept by dropping its future. No peer JSON
    /// or credential is read until bounded native peer proof has succeeded.
    pub async fn accept(&mut self, cancelled: Arc<AtomicBool>) -> Result<AcceptedIpcStream> {
        // Bound tasks before OS accept. Once a channel is accepted no JSON,
        // proof or refusal write holds up the next accept. Dropping this future
        // cancels the admission wait just as it cancels an idle OS accept.
        let incoming_slot = Arc::clone(&self.incoming)
            .acquire_owned()
            .await
            .map_err(|_| capacity_error("IPC incoming admission is closed"))?;
        #[cfg(unix)]
        let stream = self
            .listener
            .accept()
            .await
            .map_err(|e| wire::io_failure("accept IPC", e))?
            .0;
        #[cfg(windows)]
        let stream = {
            self.listener
                .connect()
                .await
                .map_err(|e| wire::io_failure("accept IPC", e))?;
            let entered = self.runtime.enter();
            let next = evented_pipe(&self.native)?;
            drop(entered);
            std::mem::replace(&mut self.listener, next)
        };
        let deadline = Deadline::from_options(&crate::client::ClientOptions {
            expected_generation: None,
            timeout: HELLO_TIMEOUT,
            cancelled,
        })?;
        let preauth_slot = match Arc::clone(&self.preauth).try_acquire_owned() {
            Ok(slot) => Some(slot),
            Err(tokio::sync::TryAcquireError::NoPermits) => None,
            Err(tokio::sync::TryAcquireError::Closed) => {
                return Err(capacity_error("IPC pre-authentication admission is closed"));
            }
        };
        Ok(AcceptedIpcStream {
            stream: Arc::new(stream),
            record: self.record.clone(),
            runtime: self.runtime.clone(),
            blocking: Arc::clone(&self.blocking),
            preauth_slot,
            incoming_slot,
            connections: Arc::clone(&self.connections),
            deadline,
        })
    }
    pub fn close(self) -> Result<()> {
        let Self {
            native, listener, ..
        } = self;
        drop(listener);
        #[cfg(unix)]
        {
            native.close().map_err(native_error)
        }
        #[cfg(windows)]
        {
            drop(native);
            Ok(())
        }
    }
}
/// OS accept is complete. Drive this handshake in a per-connection task;
/// a silent peer occupies only its own bounded slot and absolute hello clock.
pub struct AcceptedIpcStream {
    stream: Arc<NativeStream>,
    record: EndpointRecord,
    runtime: Handle,
    blocking: Arc<Semaphore>,
    preauth_slot: Option<tokio::sync::OwnedSemaphorePermit>,
    incoming_slot: tokio::sync::OwnedSemaphorePermit,
    connections: Arc<Semaphore>,
    deadline: Deadline,
}
impl AcceptedIpcStream {
    pub async fn handshake(self) -> Result<PendingIpcHandshake> {
        let deadline = self.deadline;
        let incoming_slot = self.incoming_slot;
        deadline.remaining()?;
        let stream = self.stream;
        let Some(preauth_slot) = self.preauth_slot else {
            let error = capacity_error("IPC pre-authentication capacity is occupied");
            let envelope =
                se_types::ErrorEnvelope::new(error.body.clone(), &se_types::RenderCx::default())?;
            send(&stream, &auth::encode_hello_refusal(&envelope)?, &deadline).await?;
            return Err(error);
        };
        let permit = bounded(&deadline, self.blocking.clone().acquire_owned())
            .await?
            .map_err(|_| {
                SeError::invalid("IPC native admission", "an open bounded blocking pool")
            })?;
        let observed = Arc::clone(&stream);
        let native_bound = deadline.native_bound();
        let proof = bounded(
            &deadline,
            self.runtime.spawn_blocking(move || {
                let _permit = permit;
                #[cfg(unix)]
                let channel = {
                    use std::os::fd::AsFd;
                    observed.as_fd()
                };
                #[cfg(windows)]
                let channel = {
                    use std::os::windows::io::AsHandle;
                    observed.as_handle()
                };
                NativeIpcPlatform.peer_bounded(channel, &native_bound)
            }),
        )
        .await?
        .map_err(|_| {
            SeError::invalid(
                "IPC native observation",
                "a successfully joined native peer check",
            )
        })??;
        let challenge = auth::OwnerChallenge::begin(&self.record, auth::ProofDomain::Owner)?;
        send(
            &stream,
            &auth::encode_challenge(challenge.challenge()?)?,
            &deadline,
        )
        .await?;
        let bytes = receive(&stream, &deadline, wire::MAX_ENDPOINT_BYTES).await?;
        let input = crate::client::hello::decode(bytes.as_bytes())?;
        let mut challenge = challenge;
        if matches!(input, HandshakeInput::Stop(_)) {
            challenge.stop_domain();
        }
        Ok(PendingIpcHandshake {
            stream,
            proof,
            challenge,
            input,
            record: self.record.clone(),
            deadline,
            preauth_slot,
            incoming_slot,
            connections: self.connections,
        })
    }
}
pub use crate::client::hello::DecodedHandshake as HandshakeInput;
/// Runtime admission owns this value until it has checked current credentials,
/// ancestry/provenance, revocation and generation. MAC validity alone is not Owner.
pub struct PendingIpcHandshake {
    stream: Arc<NativeStream>,
    proof: PeerProof,
    challenge: auth::OwnerChallenge,
    input: HandshakeInput,
    record: EndpointRecord,
    deadline: Deadline,
    preauth_slot: tokio::sync::OwnedSemaphorePermit,
    incoming_slot: tokio::sync::OwnedSemaphorePermit,
    connections: Arc<Semaphore>,
}
impl PendingIpcHandshake {
    pub fn peer(&self) -> &PeerProof {
        &self.proof
    }
    pub fn input(&self) -> &HandshakeInput {
        &self.input
    }
    pub fn verify_owner_mac(&mut self, key: &se_types::Secret) -> Result<()> {
        if let HandshakeInput::Stop(request) = &self.input
            && (request.expected_epoch != self.record.epoch
                || request.generation != self.record.generation)
        {
            return Err(SeError::invalid(
                "stop target",
                "the exact current epoch and generation",
            ));
        }
        let (nonce, mac) = match &self.input {
            HandshakeInput::Call(ClientHello {
                authority: PresentedAuthority::OwnerProof { nonce, mac },
                ..
            }) => (nonce, mac),
            HandshakeInput::Stop(request) => (&request.nonce, &request.mac),
            _ => {
                return Err(SeError::invalid(
                    "owner proof",
                    "a machine proof, with no fallback from a session credential",
                ));
            }
        };
        self.challenge
            .verify(key, nonce, &self.proof.native().binding(), mac)
    }
    /// A refusal requires no authority grant and transmits its typed reason
    /// without echoing raw credential/JSON bytes into diagnostics.
    pub async fn refuse(self, error: se_types::ErrorEnvelope) -> Result<()> {
        let frame = match self.input {
            HandshakeInput::Call(_) => auth::encode_hello_refusal(&error)?,
            HandshakeInput::Stop(request) => codec::encode_stop_reply(
                &codec::RuntimeStopReply {
                    epoch: request.expected_epoch,
                    generation: request.generation,
                    key: request.key,
                    outcome: codec::RuntimeStopOutcome::Refused { error },
                },
                wire::DEFAULT_REPLY_BYTES as usize,
            )?,
        };
        send(&self.stream, &frame, &self.deadline).await
    }
    /// The unforgeable crate-local admission value comes from the runtime's
    /// current core authorization. No external caller can manufacture it.
    pub async fn finish(
        self,
        _admitted: AuthorizedConnection,
        server_cap: std::num::NonZeroU32,
    ) -> Result<IpcConnection> {
        let HandshakeInput::Call(hello) = self.input else {
            return Err(SeError::invalid("IPC handshake", "an operation hello"));
        };
        let connection_slot = match self.connections.try_acquire_owned() {
            Ok(slot) => slot,
            Err(_) => {
                let error = capacity_error("IPC authenticated connection capacity is occupied");
                let envelope = se_types::ErrorEnvelope::new(
                    error.body.clone(),
                    &se_types::RenderCx::default(),
                )?;
                send(
                    &self.stream,
                    &auth::encode_hello_refusal(&envelope)?,
                    &self.deadline,
                )
                .await?;
                return Err(error);
            }
        };
        let ready = auth::negotiate_hello(&hello, &self.record, server_cap)?;
        send(
            &self.stream,
            &auth::encode_server_hello(&ready)?,
            &self.deadline,
        )
        .await?;
        drop((self.preauth_slot, self.incoming_slot));
        Ok(IpcConnection {
            stream: Some(self.stream),
            peer: self.proof,
            hello: ready,
            authority: hello.authority,
            awaiting: None,
            _connection_slot: connection_slot,
        })
    }
    pub async fn finish_stop(
        self,
        _admitted: AuthorizedConnection,
        reply: &codec::RuntimeStopReply,
        deadline: &Deadline,
    ) -> Result<()> {
        let HandshakeInput::Stop(request) = self.input else {
            return Err(SeError::invalid("IPC stop", "fixed stop control"));
        };
        if reply.epoch != request.expected_epoch
            || reply.generation != request.generation
            || reply.key != request.key
        {
            return Err(SeError::invalid(
                "IPC stop reply",
                "the original key and exact epoch/generation",
            ));
        }
        send(
            &self.stream,
            &codec::encode_stop_reply(reply, wire::DEFAULT_REPLY_BYTES as usize)?,
            &deadline.stage(WRITE_TIMEOUT)?,
        )
        .await
    }
}
pub struct IpcConnection {
    stream: Option<Arc<NativeStream>>,
    peer: PeerProof,
    hello: ServerHello,
    authority: PresentedAuthority,
    awaiting: Option<u64>,
    _connection_slot: tokio::sync::OwnedSemaphorePermit,
}
impl IpcConnection {
    pub fn connection_authority(&self) -> &PresentedAuthority {
        &self.authority
    }
    pub fn peer(&self) -> &PeerProof {
        &self.peer
    }
    pub fn negotiated(&self) -> &ServerHello {
        &self.hello
    }
    /// Runtime rechecks G, revocation and scope for each returned envelope before
    /// dispatch. A per-call invalid credential must not use connection authority.
    pub async fn read_request(&mut self, deadline: &Deadline) -> Result<IpcEnvelope> {
        if self.awaiting.is_some() {
            return Err(SeError::invalid(
                "IPC request",
                "one outstanding operation per connection",
            ));
        }
        let stream = self
            .stream
            .take()
            .ok_or_else(|| SeError::invalid("IPC channel", "a complete prior exchange"))?;
        let bytes = receive(&stream, deadline, wire::MAX_FRAME_BYTES).await?;
        let call = wire::decode_call(bytes.as_bytes())?;
        if call.version != self.hello.version || call.generation != self.hello.generation {
            return Err(SeError::invalid(
                "IPC call",
                "the exact negotiated API and generation",
            ));
        }
        self.awaiting = Some(call.request_id);
        self.stream = Some(stream);
        Ok(call)
    }
    pub async fn reply(&mut self, response: &IpcResponse, deadline: &Deadline) -> Result<()> {
        if self.awaiting != Some(response.request_id)
            || response.version != self.hello.version
            || response.generation != self.hello.generation
        {
            return Err(SeError::invalid(
                "IPC reply",
                "the exact outstanding request ID, API and generation",
            ));
        }
        let frame = wire::encode_response(response, self.hello.maximum_reply_bytes.get() as usize)?;
        let stream = self
            .stream
            .take()
            .ok_or_else(|| SeError::invalid("IPC channel", "a complete prior exchange"))?;
        send(&stream, &frame, &deadline.stage(WRITE_TIMEOUT)?).await?;
        self.awaiting = None;
        self.stream = Some(stream);
        Ok(())
    }
}

fn capacity_error(reason: &str) -> SeError {
    SeError::new(se_types::Detail::StoreBusy(se_types::details::StoreBusy {
        waited_ms: 0,
        reason: reason.into(),
        next_step: "Close an existing connection or wait for a bounded handshake to expire, then retry the original request key.".into(),
    }))
}

#[cfg(test)]
#[path = "listener/capacity_tests.rs"]
mod capacity_tests;
