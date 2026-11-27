//! Shared absolute time/cancellation bounds. Native lease/channel operations
//! receive the same deadline; reconnect never renews a request's clock.
use crate::client::ClientOptions;
use se_types::{Result, SeError};
use std::time::{Duration, Instant};

mod follow;

/// Bounded cold-handshake warm-up budget for a freshly started client door
/// connecting to a contended host. Ordinary refusal paths still use HELLO_TIMEOUT.
pub const COLD_HELLO_BUDGET: Duration = Duration::from_secs(15);
const COLD_HELLO_ATTEMPTS: usize = 3;
const COLD_HELLO_PAUSE: Duration = Duration::from_millis(50);
pub use se_harness::{CALL_TIMEOUT, Deadline, HELLO_TIMEOUT, IDLE_TIMEOUT, WRITE_TIMEOUT};

#[cfg(unix)]
type NativeStream = se_proc::native_ipc::NativeUnixStream;
#[cfg(windows)]
type NativeStream = se_proc::native_ipc::NativePipeStream;
pub enum ClientCredential {
    Machine(se_types::Secret),
    Session(se_types::Secret),
    Launch(se_types::Secret),
    GuestBootstrap(se_types::NativePath),
    SessionBootstrap(se_types::Secret),
    ExternalClaim(Box<crate::external::ExternalClaimBootstrap>),
    ExternalSession(se_types::Secret),
}
impl ClientCredential {
    fn for_renewal(&self) -> Result<Self> {
        Ok(match self {
            Self::Machine(key) => Self::Machine(se_types::Secret::new(key.expose().to_vec())?),
            Self::Session(key) => Self::Session(se_types::Secret::new(key.expose().to_vec())?),
            Self::Launch(key) => Self::Launch(se_types::Secret::new(key.expose().to_vec())?),
            Self::GuestBootstrap(cwd) => Self::GuestBootstrap(cwd.clone()),
            Self::SessionBootstrap(key) => {
                Self::SessionBootstrap(se_types::Secret::new(key.expose().to_vec())?)
            }
            Self::ExternalClaim(claim) => Self::ExternalClaim(claim.clone()),
            Self::ExternalSession(key) => {
                Self::ExternalSession(se_types::Secret::new(key.expose().to_vec())?)
            }
        })
    }
}
/// Observable transport progress for keyed callers. A validated error reply is
/// authoritative too; only a post-send failure without a reply is uncertain.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ExchangeProgress {
    #[default]
    NotSent,
    SendAttempted,
    ReplyReceived,
}
/// Mutable borrowing permits one outstanding request. Any incomplete exchange
/// consumes the channel; a caller must rediscover and retain its operation key.
pub struct BlockingConnection {
    stream: Option<NativeStream>,
    hello: crate::ServerHello,
    endpoint: crate::EndpointRecord,
    credential: ClientCredential,
    maximum_reply_bytes: std::num::NonZeroU32,
    last_activity: Instant,
    issued_at: Instant,
    renew_needed: bool,
}
pub(crate) fn native_error(cause: se_proc::native_ipc::IpcNativeError) -> SeError {
    let detail = match cause.code {
        se_proc::native_ipc::IpcNativeErrorCode::Cancelled => {
            se_types::Detail::Cancelled(se_types::details::Cancelled {
                op: "local IPC".into(),
            })
        }
        _ => se_types::Detail::IpcUnavailable(se_types::details::IpcUnavailable {
            endpoint: "protected local endpoint".into(),
            reason: format!(
                "{cause}; restore native access or rediscover the protected live endpoint, then retry the original request key"
            ),
        }),
    };
    let mut error = SeError::new(detail);
    if cause.code == se_proc::native_ipc::IpcNativeErrorCode::PeerChanged {
        error.body = error.body.with_retry(se_types::Retry::AfterReread);
    }
    error.with_cause(cause)
}
fn is_handshake_timeout(error: &SeError) -> bool {
    use std::error::Error as _;
    if matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)) {
        return true;
    }
    let Some(source) = error.source() else {
        return false;
    };
    if let Some(io_error) = source.downcast_ref::<std::io::Error>() {
        return matches!(
            io_error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        );
    }
    source
        .downcast_ref::<se_proc::native_ipc::IpcNativeError>()
        .is_some_and(|native| native.code == se_proc::native_ipc::IpcNativeErrorCode::TimedOut)
}
fn warmup_timeout_error(
    cause: SeError,
    attempts: usize,
    elapsed: Duration,
    warmup_budget: Duration,
) -> SeError {
    SeError::new(se_types::Detail::IpcUnavailable(
        se_types::details::IpcUnavailable {
            endpoint: "protected local endpoint".into(),
            reason: format!(
                "cold IPC handshake timed out after {attempts} attempt(s) ({}ms elapsed, {}ms/attempt, {}ms warm-up budget): {cause}",
                elapsed.as_millis(),
                HELLO_TIMEOUT.as_millis(),
                warmup_budget.as_millis(),
            ),
        },
    ))
    .with_cause(cause)
}
fn native_connect(
    endpoint: &crate::EndpointRecord,
    deadline: &Deadline,
    stop: bool,
) -> Result<NativeStream> {
    deadline.remaining()?;
    #[cfg(unix)]
    let stream = match &endpoint.address {
        crate::IpcEndpoint::UnixSocket(path) => {
            NativeStream::connect(&path.to_local()?, deadline.native_bound())
                .map_err(native_error)?
        }
        _ => return Err(SeError::invalid("IPC endpoint", "a local Unix socket")),
    };
    #[cfg(windows)]
    let stream = match &endpoint.address {
        crate::IpcEndpoint::WindowsPipe(name) => {
            NativeStream::connect(std::ffi::OsStr::new(name), deadline.native_bound())
                .map_err(native_error)?
        }
        _ => return Err(SeError::invalid("IPC endpoint", "a local Windows pipe")),
    };
    if stop {
        se_proc::native_ipc::verify_ipc_stop_server(
            stream.channel(),
            &endpoint.epoch.owner,
            &deadline.native_bound(),
        )
        .map_err(native_error)?;
    } else {
        crate::NativeIpcPlatform.verify_server_bounded(
            stream.channel(),
            endpoint,
            &deadline.native_bound(),
        )?;
    }
    deadline.remaining()?;
    Ok(stream)
}
impl crate::client::BlockingIpcClient {
    pub fn connect_authenticated(
        endpoint: &crate::EndpointRecord,
        credential: ClientCredential,
        maximum_reply_bytes: std::num::NonZeroU32,
        options: &ClientOptions,
    ) -> Result<BlockingConnection> {
        let budget = Deadline::from_options(options)?;
        Self::connect_before(endpoint, credential, maximum_reply_bytes, options, &budget)
    }
    /// Cold-start handshake with bounded retry on handshake timeouts only.
    /// Absent endpoints, auth refusals and cancellations still fail immediately.
    pub fn connect_cold_authenticated(
        endpoint: &crate::EndpointRecord,
        credential: ClientCredential,
        maximum_reply_bytes: std::num::NonZeroU32,
        options: &ClientOptions,
    ) -> Result<BlockingConnection> {
        let budget = Deadline::from_options(options)?;
        let warmup = budget.stage(COLD_HELLO_BUDGET)?;
        let warmup_budget = warmup.budget();
        let started = Instant::now();
        let mut attempt = 0usize;
        loop {
            attempt += 1;
            match Self::connect_before(
                endpoint,
                credential.for_renewal()?,
                maximum_reply_bytes,
                options,
                &warmup,
            ) {
                Ok(connection) => return Ok(connection),
                Err(error) if !is_handshake_timeout(&error) => return Err(error),
                Err(error) => {
                    if attempt < COLD_HELLO_ATTEMPTS
                        && let Ok(remaining) = warmup.remaining()
                    {
                        std::thread::sleep(remaining.min(COLD_HELLO_PAUSE));
                        continue;
                    }
                    return Err(warmup_timeout_error(
                        error,
                        attempt,
                        started.elapsed(),
                        warmup_budget,
                    ));
                }
            }
        }
    }
    fn connect_before(
        endpoint: &crate::EndpointRecord,
        credential: ClientCredential,
        maximum_reply_bytes: std::num::NonZeroU32,
        options: &ClientOptions,
        budget: &Deadline,
    ) -> Result<BlockingConnection> {
        use super::{auth, wire};
        // Start before the handshake: the server cannot begin its idle clock
        // earlier, even if this process is paused while receiving its reply.
        let last_activity = Instant::now();
        budget.remaining()?;
        if matches!(&credential, ClientCredential::Machine(_)) {
            // Cold local file I/O belongs to the caller's original request
            // budget, before a connection holds a server handshake slot. The
            // hello below reobserves native identity through the warmed cache.
            se_proc::native_ipc::observe_ipc_self_bounded(&budget.native_bound())
                .map_err(native_error)?;
        }
        let deadline = budget.stage(HELLO_TIMEOUT)?;
        let mut stream = native_connect(endpoint, &deadline, false)?;
        let bytes = wire::read_payload_bounded(&mut stream, wire::MAX_ENDPOINT_BYTES, &deadline)?;
        let challenge = auth::decode_challenge(bytes.as_bytes(), endpoint)?;
        if challenge.version != se_types::API_VERSION {
            return Err(SeError::new(se_types::Detail::ApiVersionUnsupported(
                se_types::details::ApiVersionUnsupported {
                    client: format!(
                        "{}.{}",
                        se_types::API_VERSION.major,
                        se_types::API_VERSION.minor
                    ),
                    host: format!("{}.{}", challenge.version.major, challenge.version.minor),
                },
            )));
        }
        let authority = match &credential {
            ClientCredential::Machine(key) => {
                let peer = se_proc::native_ipc::observe_ipc_self_bounded(&deadline.native_bound())
                    .map_err(native_error)?;
                let nonce = auth::fresh_nonce()?;
                let mac = auth::create_owner_mac(
                    key,
                    auth::ProofDomain::Owner,
                    &challenge,
                    &nonce,
                    &peer.binding(),
                )?;
                crate::PresentedAuthority::OwnerProof { nonce, mac }
            }
            ClientCredential::Session(token) => {
                crate::PresentedAuthority::Session(se_types::Secret::new(token.expose().to_vec())?)
            }
            ClientCredential::Launch(token) => {
                crate::PresentedAuthority::Launch(se_types::Secret::new(token.expose().to_vec())?)
            }
            ClientCredential::GuestBootstrap(cwd) => {
                crate::PresentedAuthority::GuestBootstrap(cwd.clone())
            }
            ClientCredential::SessionBootstrap(token) => {
                crate::PresentedAuthority::SessionBootstrap(se_types::Secret::new(
                    token.expose().to_vec(),
                )?)
            }
            ClientCredential::ExternalClaim(claim) => {
                crate::PresentedAuthority::ExternalClaim(claim.clone())
            }
            ClientCredential::ExternalSession(token) => crate::PresentedAuthority::ExternalSession(
                se_types::Secret::new(token.expose().to_vec())?,
            ),
        };
        let sent = crate::ClientHello {
            version: se_types::API_VERSION,
            expected_generation: options.expected_generation,
            maximum_reply_bytes,
            authority,
        };
        deadline.remaining()?;
        wire::write_frame_bounded(&mut stream, &auth::encode_client_hello(&sent)?, &deadline)?;
        let bytes = wire::read_payload_bounded(&mut stream, wire::MAX_ENDPOINT_BYTES, &deadline)?;
        let hello = auth::decode_server_hello(bytes.as_bytes(), &sent, &challenge)?;
        deadline.remaining()?;
        Ok(BlockingConnection {
            stream: Some(stream),
            hello,
            endpoint: endpoint.clone(),
            credential,
            maximum_reply_bytes,
            last_activity,
            issued_at: last_activity,
            renew_needed: false,
        })
    }
    /// Recover credentials only from a verified native host connection.
    pub fn rebind(
        endpoint: &crate::EndpointRecord,
        options: &ClientOptions,
        project_id: se_types::ProjectId,
        agent_id: se_types::AgentId,
        control_endpoint: String,
    ) -> Result<super::rebind::RebindReply> {
        use super::{auth, rebind, wire};
        if options
            .expected_generation
            .is_some_and(|g| g != endpoint.generation)
        {
            return Err(SeError::invalid(
                "rebind generation",
                "the exact discovered runtime generation",
            ));
        }
        let deadline = Deadline::from_options(options)?;
        let hello = deadline.stage(HELLO_TIMEOUT)?;
        let mut stream = native_connect(endpoint, &hello, false)?;
        let bytes = wire::read_payload_bounded(&mut stream, wire::MAX_ENDPOINT_BYTES, &hello)?;
        auth::decode_challenge(bytes.as_bytes(), endpoint)?;
        let request = rebind::RebindRequest {
            project_id,
            agent_id,
            expected_epoch: endpoint.epoch.clone(),
            generation: endpoint.generation,
            control_endpoint,
        };
        wire::write_frame_bounded(&mut stream, &rebind::encode_request(&request)?, &hello)?;
        let bytes = wire::read_payload_bounded(&mut stream, wire::MAX_ENDPOINT_BYTES, &deadline)?;
        let reply = rebind::decode_reply(bytes.as_bytes())?;
        if reply.project != request.project_id || reply.agent != request.agent_id {
            return Err(SeError::invalid(
                "rebind reply",
                "the selected project and agent",
            ));
        }
        Ok(reply)
    }

    /// This fixed control is usable across operation API versions. It never
    /// retries, invents a new key, kills by PID, or equates endpoint loss to stop.
    pub fn stop(
        endpoint: &crate::EndpointRecord,
        machine_key: &se_types::Secret,
        key: se_types::IdempotencyKey,
        deadline_at: se_types::UnixMicros,
        options: &ClientOptions,
    ) -> Result<super::endpoint::RuntimeStopReply> {
        use super::{auth, endpoint as codec, wire};
        if options
            .expected_generation
            .is_some_and(|g| g != endpoint.generation)
        {
            return Err(SeError::invalid(
                "stop generation",
                "the exact expected discovered generation",
            ));
        }
        let deadline = Deadline::from_options(options)?;
        // Stop uses the same local-proof preparation as owner operation calls,
        // including when the client executable has changed since host startup.
        se_proc::native_ipc::observe_ipc_self_bounded(&deadline.native_bound())
            .map_err(native_error)?;
        let hello = deadline.stage(HELLO_TIMEOUT)?;
        let mut stream = native_connect(endpoint, &hello, true)?;
        let bytes = wire::read_payload_bounded(&mut stream, wire::MAX_ENDPOINT_BYTES, &hello)?;
        let challenge = auth::decode_challenge(bytes.as_bytes(), endpoint)?;
        let peer = se_proc::native_ipc::observe_ipc_self_bounded(&hello.native_bound())
            .map_err(native_error)?;
        let nonce = auth::fresh_nonce()?;
        let mac = auth::create_owner_mac(
            machine_key,
            auth::ProofDomain::RuntimeStop,
            &challenge,
            &nonce,
            &peer.binding(),
        )?;
        let request = codec::RuntimeStopRequest {
            expected_epoch: endpoint.epoch.clone(),
            generation: endpoint.generation,
            key,
            deadline_at,
            nonce,
            mac,
        };
        let writing = deadline.stage(WRITE_TIMEOUT)?;
        stream.set_bound(writing.native_bound());
        wire::write_frame_bounded(&mut stream, &codec::encode_stop(&request)?, &writing)?;
        stream.set_bound(deadline.native_bound());
        let bytes =
            wire::read_payload_bounded(&mut stream, wire::DEFAULT_REPLY_BYTES as usize, &deadline)?;
        // A complete authenticated stop reply carries achieved facts even if
        // decoding finishes after the clock or a concurrent cancellation.
        codec::decode_stop_reply(
            bytes.as_bytes(),
            &request,
            wire::DEFAULT_REPLY_BYTES as usize,
        )
    }
}
impl BlockingConnection {
    pub fn negotiated(&self) -> &crate::ServerHello {
        &self.hello
    }
    pub fn exchange(
        &mut self,
        call: crate::IpcEnvelope,
        options: &ClientOptions,
    ) -> Result<crate::OperationOutput> {
        self.exchange_with_progress(call, options, &mut ExchangeProgress::NotSent)
    }
    pub fn exchange_with_progress(
        &mut self,
        mut call: crate::IpcEnvelope,
        options: &ClientOptions,
        progress: &mut ExchangeProgress,
    ) -> Result<crate::OperationOutput> {
        *progress = ExchangeProgress::NotSent;
        use super::wire;
        if call.version != self.hello.version
            || call.generation != self.hello.generation
            || options
                .expected_generation
                .is_some_and(|g| g != self.hello.generation)
        {
            return Err(SeError::invalid(
                "IPC call",
                "the exact negotiated API and generation",
            ));
        }
        let deadline = Deadline::from_options(options)?;
        let bound = if let Some(crate::PresentedAuthority::Lease(secret)) = &call.authority {
            let guest = self.hello.lease.as_ref().ok_or_else(|| {
                SeError::invalid("guest connection", "the ticket issued to this channel")
            })?;
            if secret.expose() != guest.secret.expose() {
                return Err(SeError::invalid(
                    "guest credential",
                    "the ticket issued to this channel",
                ));
            }
            Some((
                guest.project.clone(),
                guest.agent.clone(),
                guest.session.clone(),
            ))
        } else {
            None
        };
        // Refuse malformed or oversized calls before reconnecting or sending.
        let mut frame = wire::encode_call(&call)?;
        // Renew before the first send, allowing the whole write stage before
        // the server's idle expiry. Never retry an incomplete exchange: its
        // operation may already have committed, with or without a reply.
        if self.renew_needed
            || self.hello.lease.as_ref().is_some_and(|guest| {
                self.issued_at.elapsed().saturating_add(WRITE_TIMEOUT)
                    >= Duration::from_millis(guest.lifetime_ms)
            })
            || (self.stream.is_some()
                && self.last_activity.elapsed().saturating_add(WRITE_TIMEOUT) >= IDLE_TIMEOUT)
        {
            // A failed renewal sent no operation and can be attempted on the
            // next call. This is distinct from a consumed incomplete exchange.
            self.renew_needed = true;
            drop(self.stream.take());
            *self = crate::client::BlockingIpcClient::connect_before(
                &self.endpoint,
                self.credential.for_renewal()?,
                self.maximum_reply_bytes,
                options,
                &deadline,
            )?;
        }
        if matches!(call.authority, Some(crate::PresentedAuthority::Lease(_))) {
            let guest = self.hello.lease.as_ref().ok_or_else(|| {
                SeError::invalid("guest connection", "a current channel-bound ticket")
            })?;
            if Some((&guest.project, &guest.agent, &guest.session))
                != bound
                    .as_ref()
                    .map(|(project, agent, session)| (project, agent, session))
            {
                return Err(SeError::invalid(
                    "guest renewal",
                    "the original registered project",
                ));
            }
            call.authority = Some(crate::PresentedAuthority::Lease(se_types::Secret::new(
                guest.secret.expose().to_vec(),
            )?));
            frame = wire::encode_call(&call)?;
        }
        let mut stream = self.stream.take().ok_or_else(|| {
            SeError::invalid(
                "IPC channel",
                "rediscovery after an incomplete exchange, keeping the original operation key",
            )
        })?;
        let writing = deadline.stage(WRITE_TIMEOUT)?;
        stream.set_bound(writing.native_bound());
        self.last_activity = Instant::now();
        *progress = ExchangeProgress::SendAttempted;
        wire::write_frame_bounded(&mut stream, &frame, &writing)?;
        stream.set_bound(deadline.native_bound());
        let limit = self.hello.maximum_reply_bytes.get() as usize;
        let bytes = wire::read_payload_bounded(&mut stream, limit, &deadline)?;
        let response = wire::decode_response(
            bytes.as_bytes(),
            call.version,
            call.generation,
            call.request_id,
            limit,
        )?;
        // Preserve a fully received and validated outcome. The native reads
        // were deadline-bound; a late decode cannot erase a confirmed commit.
        *progress = ExchangeProgress::ReplyReceived;
        self.stream = Some(stream);
        match response.result {
            crate::IpcResult::Output(output) => Ok(*output),
            crate::IpcResult::Error(error) => Err(error.body().clone().into()),
        }
    }
}
