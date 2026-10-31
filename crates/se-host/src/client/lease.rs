//! Shared absolute time/cancellation bounds. Native lease/channel operations
//! receive the same deadline; reconnect never renews a request's clock.
use crate::client::ClientOptions;
use se_types::{Result, SeError};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
pub const CALL_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Deadline {
    at: Instant,
    budget: Duration,
    cancelled: Arc<AtomicBool>,
}
impl Deadline {
    pub fn from_options(options: &ClientOptions) -> Result<Self> {
        let timeout = options.timeout.min(CALL_TIMEOUT);
        if timeout.is_zero() {
            return Err(SeError::invalid(
                "IPC timeout",
                "a positive bounded duration",
            ));
        }
        let at = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| SeError::invalid("IPC deadline", "a representable absolute deadline"))?;
        let deadline = Self {
            at,
            budget: timeout,
            cancelled: Arc::clone(&options.cancelled),
        };
        deadline.remaining()?;
        Ok(deadline)
    }
    pub fn at(&self) -> Instant {
        self.at
    }
    pub fn stage(&self, maximum: Duration) -> Result<Self> {
        let budget = maximum.min(self.remaining()?);
        let at = Instant::now()
            .checked_add(budget)
            .ok_or_else(|| SeError::invalid("IPC stage", "a representable deadline"))?
            .min(self.at);
        Ok(Self {
            at,
            budget,
            cancelled: Arc::clone(&self.cancelled),
        })
    }
    pub fn remaining(&self) -> Result<Duration> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(SeError::new(se_types::Detail::Cancelled(
                se_types::details::Cancelled {
                    op: "local IPC".into(),
                },
            )));
        }
        self.at
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| {
                SeError::new(se_types::Detail::DeadlineExceeded(
                    se_types::details::DeadlineExceeded {
                        op: "local IPC".into(),
                        deadline_ms: self.budget.as_millis() as u64,
                    },
                ))
            })
    }
}

#[cfg(unix)]
type NativeStream = se_proc::native_ipc::NativeUnixStream;
#[cfg(windows)]
type NativeStream = se_proc::native_ipc::NativePipeStream;
pub enum ClientCredential {
    Machine(se_types::Secret),
    Session(se_types::Secret),
    Launch(se_types::Secret),
}
/// Mutable borrowing permits one outstanding request. Any incomplete exchange
/// consumes the channel; a caller must rediscover and retain its operation key.
pub struct BlockingConnection {
    stream: Option<NativeStream>,
    hello: crate::ServerHello,
}
impl Deadline {
    pub fn native_bound(&self) -> se_proc::native_ipc::IpcIoBound {
        se_proc::native_ipc::IpcIoBound {
            deadline: self.at,
            cancelled: Arc::clone(&self.cancelled),
        }
    }
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
            reason: cause.to_string(),
        }),
    };
    SeError::new(detail).with_cause(cause)
}
fn native_connect(endpoint: &crate::EndpointRecord, deadline: &Deadline) -> Result<NativeStream> {
    use crate::IpcPlatform;
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
    crate::NativeIpcPlatform.verify_server(stream.channel(), endpoint)?;
    deadline.remaining()?;
    Ok(stream)
}
impl crate::client::BlockingIpcClient {
    /// Does not read ambient authority or fall back from a present credential.
    /// The caller obtains exactly one credential from its protected native path.
    pub fn connect_authenticated(
        endpoint: &crate::EndpointRecord,
        credential: ClientCredential,
        maximum_reply_bytes: std::num::NonZeroU32,
        options: &ClientOptions,
    ) -> Result<BlockingConnection> {
        use super::{auth, wire};
        let deadline = Deadline::from_options(options)?.stage(HELLO_TIMEOUT)?;
        let mut stream = native_connect(endpoint, &deadline)?;
        let bytes = wire::read_payload(&mut stream, wire::MAX_ENDPOINT_BYTES)?;
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
        let authority = match credential {
            ClientCredential::Machine(key) => {
                let peer = se_proc::native_ipc::observe_ipc_self().map_err(native_error)?;
                let nonce = auth::fresh_nonce()?;
                let mac = auth::create_owner_mac(
                    &key,
                    auth::ProofDomain::Owner,
                    &challenge,
                    &nonce,
                    &peer.binding(),
                )?;
                crate::PresentedAuthority::OwnerProof { nonce, mac }
            }
            ClientCredential::Session(token) => crate::PresentedAuthority::Session(token),
            ClientCredential::Launch(token) => crate::PresentedAuthority::Launch(token),
        };
        let sent = crate::ClientHello {
            version: se_types::API_VERSION,
            expected_generation: options.expected_generation,
            maximum_reply_bytes,
            authority,
        };
        deadline.remaining()?;
        wire::write_frame(&mut stream, &auth::encode_client_hello(&sent)?)?;
        let bytes = wire::read_payload(&mut stream, wire::MAX_ENDPOINT_BYTES)?;
        let hello = auth::decode_server_hello(bytes.as_bytes(), &sent, &challenge)?;
        deadline.remaining()?;
        Ok(BlockingConnection {
            stream: Some(stream),
            hello,
        })
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
        let hello = deadline.stage(HELLO_TIMEOUT)?;
        let mut stream = native_connect(endpoint, &hello)?;
        let bytes = wire::read_payload(&mut stream, wire::MAX_ENDPOINT_BYTES)?;
        let challenge = auth::decode_challenge(bytes.as_bytes(), endpoint)?;
        let peer = se_proc::native_ipc::observe_ipc_self().map_err(native_error)?;
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
        stream.set_bound(deadline.stage(WRITE_TIMEOUT)?.native_bound());
        wire::write_frame(&mut stream, &codec::encode_stop(&request)?)?;
        stream.set_bound(deadline.native_bound());
        let bytes = wire::read_payload(&mut stream, wire::DEFAULT_REPLY_BYTES as usize)?;
        deadline.remaining()?;
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
        // Encode/refuse before taking custody of the connection or writing.
        let frame = wire::encode_call(&call)?;
        let mut stream = self.stream.take().ok_or_else(|| {
            SeError::invalid(
                "IPC channel",
                "rediscovery after an incomplete exchange, keeping the original operation key",
            )
        })?;
        stream.set_bound(deadline.stage(WRITE_TIMEOUT)?.native_bound());
        wire::write_frame(&mut stream, &frame)?;
        stream.set_bound(deadline.native_bound());
        let limit = self.hello.maximum_reply_bytes.get() as usize;
        let bytes = wire::read_payload(&mut stream, limit)?;
        let response = wire::decode_response(
            bytes.as_bytes(),
            call.version,
            call.generation,
            call.request_id,
            limit,
        )?;
        deadline.remaining()?;
        self.stream = Some(stream);
        match response.result {
            crate::IpcResult::Output(output) => Ok(*output),
            crate::IpcResult::Error(error) => Err(error.body().clone().into()),
        }
    }
}
