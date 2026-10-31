//! Evented transport on the supplied runtime. Native proof work shares the
//! caller's bounded blocking admission; this module creates no runtime/thread.
use super::*;
use crate::client::{
    auth, endpoint as codec,
    lease::{Deadline, HELLO_TIMEOUT, WRITE_TIMEOUT, native_error},
    wire,
};
use se_types::{Result, SeError};
use std::{
    io,
    sync::{Arc, atomic::AtomicBool},
};
use tokio::{
    runtime::Handle,
    sync::Semaphore,
    time::{Instant, timeout_at},
};
use zeroize::Zeroizing;
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
        })
    }
    /// The caller can cancel idle accept by dropping its future. No peer JSON
    /// or credential is read until bounded native peer proof has succeeded.
    pub async fn accept(&mut self, cancelled: Arc<AtomicBool>) -> Result<PendingIpcHandshake> {
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
        let stream = Arc::new(stream);
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
        let bytes = receive(&stream, &deadline, wire::MAX_FRAME_BYTES).await?;
        let (challenge, input) = if codec::has_stop_protocol(bytes.as_bytes())? {
            let mut challenge = challenge;
            challenge.stop_domain();
            (
                challenge,
                HandshakeInput::Stop(codec::decode_stop(bytes.as_bytes())?),
            )
        } else {
            (
                challenge,
                HandshakeInput::Call(auth::decode_client_hello(bytes.as_bytes())?),
            )
        };
        Ok(PendingIpcHandshake {
            stream,
            proof,
            challenge,
            input,
            record: self.record.clone(),
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
pub enum HandshakeInput {
    Call(ClientHello),
    Stop(codec::RuntimeStopRequest),
}
/// Runtime admission owns this value until it has checked current credentials,
/// ancestry/provenance, revocation and generation. MAC validity alone is not Owner.
pub struct PendingIpcHandshake {
    stream: Arc<NativeStream>,
    proof: PeerProof,
    challenge: auth::OwnerChallenge,
    input: HandshakeInput,
    record: EndpointRecord,
    deadline: Deadline,
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
        let ready = auth::negotiate_hello(&hello, &self.record, server_cap)?;
        send(
            &self.stream,
            &auth::encode_server_hello(&ready)?,
            &self.deadline,
        )
        .await?;
        Ok(IpcConnection {
            stream: Some(self.stream),
            peer: self.proof,
            hello: ready,
            authority: hello.authority,
            awaiting: None,
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
async fn bounded<T>(
    deadline: &Deadline,
    future: impl std::future::Future<Output = T>,
) -> Result<T> {
    deadline.remaining()?;
    let result = timeout_at(Instant::from_std(deadline.at()), future)
        .await
        .map_err(|_| wire::io_failure("IPC absolute deadline", io::ErrorKind::TimedOut.into()))?;
    deadline.remaining()?;
    Ok(result)
}
async fn exact(stream: &NativeStream, mut bytes: &mut [u8], deadline: &Deadline) -> Result<()> {
    while !bytes.is_empty() {
        bounded(deadline, stream.readable())
            .await?
            .map_err(|e| wire::io_failure("wait IPC read", e))?;
        match stream.try_read(bytes) {
            Ok(0) => {
                return Err(wire::io_failure(
                    "incomplete IPC frame",
                    io::ErrorKind::UnexpectedEof.into(),
                ));
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(wire::io_failure("read IPC frame", e)),
        }
    }
    Ok(())
}
async fn receive(
    stream: &NativeStream,
    deadline: &Deadline,
    limit: usize,
) -> Result<wire::WireBytes> {
    let mut header = [0; 4];
    exact(stream, &mut header, deadline).await?;
    let mut bytes = Zeroizing::new(vec![0; wire::frame_length(header, limit)?]);
    exact(stream, &mut bytes, deadline).await?;
    Ok(wire::WireBytes::from_owned(bytes))
}
async fn send(stream: &NativeStream, frame: &wire::WireBytes, deadline: &Deadline) -> Result<()> {
    let mut bytes = frame.as_bytes();
    while !bytes.is_empty() {
        bounded(deadline, stream.writable())
            .await?
            .map_err(|e| wire::io_failure("wait IPC write", e))?;
        match stream.try_write(bytes) {
            Ok(0) => {
                return Err(wire::io_failure(
                    "incomplete IPC write",
                    io::ErrorKind::WriteZero.into(),
                ));
            }
            Ok(count) => bytes = &bytes[count..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(wire::io_failure("write IPC frame", e)),
        }
    }
    Ok(())
}
