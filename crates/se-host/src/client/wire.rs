//! Shared blocking/async IPC codec. A transport supplies deadline-aware I/O;
//! this module never dispatches an operation or interprets a request key.
use super::auth::{AuthorityRef, AuthorityWire};
use super::endpoint::VersionWire;
use se_types::{Result, SeError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, Write};
use std::num::NonZeroU64;
use zeroize::Zeroizing;

#[path = "wire/framing.rs"]
mod framing;
pub use framing::{frame_length, read_payload, write_frame};
pub(crate) use framing::{read_payload_bounded, write_frame_bounded};

pub use se_mcp::wire::{MAX_FRAME_BYTES, MAX_JSON_DEPTH};
pub const DEFAULT_REPLY_BYTES: u32 = 262_144;
pub const MAX_ENDPOINT_BYTES: usize = 16 * 1024;

fn invalid(expected: &str) -> SeError {
    SeError::invalid("IPC frame", expected)
}

/// Protected frame bytes deliberately omit Debug, Clone and Serialize.
/// Copies retained for channel I/O are erased when their buffer is dropped.
pub struct WireBytes(Zeroizing<Vec<u8>>);
impl WireBytes {
    #[cfg(feature = "listener")]
    pub(crate) fn from_owned(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

struct LimitedBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("IPC JSON exceeds its byte budget"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ByteCount {
    bytes: usize,
    limit: usize,
}
impl Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes) {
            return Err(io::Error::other("IPC JSON exceeds its byte budget"));
        }
        self.bytes += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Count the entire JSON envelope, including window/marker/error metadata.
/// A refusal writes no prefix or partial JSON to the channel.
pub fn encode_json<T: Serialize>(value: &T, limit: usize) -> Result<WireBytes> {
    if limit == 0 || limit > MAX_FRAME_BYTES {
        return Err(invalid("a nonzero budget at most 1 MiB"));
    }
    let mut count = ByteCount { bytes: 0, limit };
    serde_json::to_writer(&mut count, value)
        .map_err(|_| invalid("complete JSON within the negotiated byte budget"))?;
    // Size without retaining bytes, then forbid growth of the protected buffer.
    // Erasure covers its full allocation, including unused capacity.
    let mut output = LimitedBuffer {
        bytes: Zeroizing::new(Vec::with_capacity(count.bytes)),
        limit: count.bytes,
    };
    serde_json::to_writer(&mut output, value)
        .map_err(|_| invalid("complete JSON within the negotiated byte budget"))?;
    if output.bytes.len() != count.bytes {
        return Err(invalid(
            "the same JSON byte count during sizing and encoding",
        ));
    }
    Ok(WireBytes(output.bytes))
}

pub use se_mcp::wire::decode_json;

#[cfg(feature = "listener")]
struct ExactByteCount {
    bytes: usize,
}
#[cfg(feature = "listener")]
impl Write for ExactByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes.saturating_add(bytes.len());
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Encode a length-prefixed JSON frame, returning `Ok(Err(exact_bytes))` when
/// the serialized JSON exceeds `limit` without allocating the payload buffer.
#[cfg(feature = "listener")]
pub(crate) fn encode_frame_checked<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<std::result::Result<WireBytes, usize>> {
    if limit == 0 || limit > MAX_FRAME_BYTES {
        return Err(invalid("a nonzero budget at most 1 MiB"));
    }
    let mut exact = ExactByteCount { bytes: 0 };
    serde_json::to_writer(&mut exact, value)
        .map_err(|_| invalid("serializable JSON for IPC frame"))?;
    if exact.bytes > limit {
        return Ok(Err(exact.bytes));
    }
    let mut output = LimitedBuffer {
        bytes: Zeroizing::new(Vec::with_capacity(exact.bytes)),
        limit: exact.bytes,
    };
    serde_json::to_writer(&mut output, value)
        .map_err(|_| invalid("complete JSON within the negotiated byte budget"))?;
    if output.bytes.len() != exact.bytes {
        return Err(invalid(
            "the same JSON byte count during sizing and encoding",
        ));
    }
    let length =
        u32::try_from(output.bytes.len()).map_err(|_| invalid("a bounded frame length"))?;
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + output.bytes.len()));
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&output.bytes);
    Ok(Ok(WireBytes(frame)))
}

pub fn encode_frame<T: Serialize>(value: &T, limit: usize) -> Result<WireBytes> {
    let payload = encode_json(value, limit)?;
    let length =
        u32::try_from(payload.as_bytes().len()).map_err(|_| invalid("a bounded frame length"))?;
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + payload.as_bytes().len()));
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload.as_bytes());
    Ok(WireBytes(frame))
}

pub(crate) fn io_failure(stage: &str, error: io::Error) -> SeError {
    let detail = se_types::Detail::IpcUnavailable(se_types::details::IpcUnavailable {
        endpoint: "verified local IPC channel".into(),
        reason: format!("{stage}: {error}"),
    });
    SeError::new(detail).with_cause(error)
}

#[derive(Serialize)]
struct CallRef<'a> {
    version: VersionWire,
    request_id: NonZeroU64,
    generation: se_types::Generation,
    authority: Option<AuthorityRef<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    presence: &'a Option<super::presence::OwnerPresence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cli_selections: &'a Option<Value>,
    request: RequestRef<'a>,
}
#[derive(Serialize)]
#[serde(tag = "kind", content = "input", rename_all = "snake_case")]
enum RequestRef<'a> {
    Adopt(&'a crate::adoption::Input),
    #[cfg(feature = "remote")]
    RemoteOwner(&'a crate::remote::OwnerInput),
    External(&'a crate::external::ExternalRequest),
    Subscribe(&'a crate::events::SubscribeRequest),
    Operation(OperationRef<'a>),
    Hook(HookRef<'a>),
}
#[derive(Serialize)]
struct OperationRef<'a> {
    name: &'a str,
    arguments: &'a Value,
    key: &'a Option<se_types::IdempotencyKey>,
}
#[derive(Serialize)]
struct HookRef<'a> {
    kind: HookKind,
    conversation: &'a se_types::ProviderSessionId,
    claimed_transcript: &'a se_types::NativePath,
    payload: &'a Value,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HookKind {
    SessionStart,
    Prompt,
    Stop,
    StopFailure,
}
impl From<crate::ClaudeHookKind> for HookKind {
    fn from(kind: crate::ClaudeHookKind) -> Self {
        match kind {
            crate::ClaudeHookKind::SessionStart => Self::SessionStart,
            crate::ClaudeHookKind::Prompt => Self::Prompt,
            crate::ClaudeHookKind::Stop => Self::Stop,
            crate::ClaudeHookKind::StopFailure => Self::StopFailure,
        }
    }
}
impl From<HookKind> for crate::ClaudeHookKind {
    fn from(kind: HookKind) -> Self {
        match kind {
            HookKind::SessionStart => Self::SessionStart,
            HookKind::Prompt => Self::Prompt,
            HookKind::Stop => Self::Stop,
            HookKind::StopFailure => Self::StopFailure,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallWire {
    version: VersionWire,
    request_id: NonZeroU64,
    generation: se_types::Generation,
    authority: Option<AuthorityWire>,
    presence: Option<super::presence::OwnerPresence>,
    cli_selections: Option<Value>,
    request: RequestWire,
}
#[derive(Deserialize)]
#[serde(
    tag = "kind",
    content = "input",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum RequestWire {
    Adopt(crate::adoption::Input),
    #[cfg(feature = "remote")]
    RemoteOwner(Box<crate::remote::OwnerInput>),
    External(Box<crate::external::ExternalRequest>),
    Subscribe(Box<crate::events::SubscribeRequest>),
    Operation(OperationWire),
    Hook(HookWire),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationWire {
    name: String,
    arguments: Value,
    key: Option<se_types::IdempotencyKey>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HookWire {
    kind: HookKind,
    conversation: se_types::ProviderSessionId,
    #[serde(deserialize_with = "super::endpoint::deserialize_path")]
    claimed_transcript: se_types::NativePath,
    payload: Value,
}

pub fn encode_call(call: &crate::IpcEnvelope) -> Result<WireBytes> {
    super::endpoint::validate_selections(
        &call.cli_selections,
        matches!(&call.request, crate::IpcRequest::Hook(_)),
    )?;
    let request_id =
        NonZeroU64::new(call.request_id).ok_or_else(|| invalid("a positive request ID"))?;
    let request = match &call.request {
        crate::IpcRequest::Adopt(input) => RequestRef::Adopt(input),
        #[cfg(feature = "remote")]
        crate::IpcRequest::RemoteOwner(input) => RequestRef::RemoteOwner(input),
        crate::IpcRequest::External(input) => RequestRef::External(input),
        crate::IpcRequest::Subscribe(input) => RequestRef::Subscribe(input),
        crate::IpcRequest::Operation(operation) => RequestRef::Operation(OperationRef {
            name: &operation.name,
            arguments: &operation.arguments,
            key: &operation.key,
        }),
        crate::IpcRequest::Hook(hook) => RequestRef::Hook(HookRef {
            kind: hook.kind.into(),
            conversation: &hook.conversation,
            claimed_transcript: &hook.claimed_transcript,
            payload: &hook.payload,
        }),
    };
    encode_frame(
        &CallRef {
            version: call.version.into(),
            request_id,
            generation: call.generation,
            authority: call.authority.as_ref().map(AuthorityRef::from),
            presence: &call.presence,
            cli_selections: &call.cli_selections,
            request,
        },
        MAX_FRAME_BYTES,
    )
}

pub fn decode_call(payload: &[u8]) -> Result<crate::IpcEnvelope> {
    let wire: CallWire = decode_json(payload, MAX_FRAME_BYTES)?;
    super::endpoint::validate_selections(
        &wire.cli_selections,
        matches!(&wire.request, RequestWire::Hook(_)),
    )?;
    let request = match wire.request {
        RequestWire::Adopt(input) => crate::IpcRequest::Adopt(input),
        #[cfg(feature = "remote")]
        RequestWire::RemoteOwner(input) => crate::IpcRequest::RemoteOwner(input),
        RequestWire::External(input) => crate::IpcRequest::External(input),
        RequestWire::Subscribe(input) => crate::IpcRequest::Subscribe(input),
        RequestWire::Operation(operation) => crate::IpcRequest::Operation(crate::RawOperation {
            name: operation.name,
            arguments: operation.arguments,
            key: operation.key,
        }),
        RequestWire::Hook(hook) => crate::IpcRequest::Hook(crate::ClaudeHookInput {
            kind: hook.kind.into(),
            conversation: hook.conversation,
            claimed_transcript: hook.claimed_transcript,
            payload: hook.payload,
        }),
    };
    Ok(crate::IpcEnvelope {
        version: wire.version.into(),
        request_id: wire.request_id.get(),
        generation: wire.generation,
        authority: wire.authority.map(Into::into),
        presence: wire.presence,
        cli_selections: wire.cli_selections,
        request,
    })
}

#[derive(Serialize)]
struct ResponseRef<'a> {
    version: VersionWire,
    request_id: NonZeroU64,
    generation: se_types::Generation,
    result: ResultRef<'a>,
}
#[derive(Serialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
enum ResultRef<'a> {
    Output(OutputRef<'a>),
    Error(&'a se_types::ErrorEnvelope),
}
#[derive(Serialize)]
struct OutputRef<'a> {
    schema: &'a str,
    value: &'a Value,
    window: &'a Option<se_types::Window>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseWire {
    version: VersionWire,
    request_id: NonZeroU64,
    generation: se_types::Generation,
    result: ResultWire,
}
#[derive(Deserialize)]
#[serde(
    tag = "state",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ResultWire {
    Output(Box<OutputWire>),
    Error(se_types::ErrorEnvelope),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputWire {
    schema: String,
    value: Value,
    window: Option<se_types::Window>,
}

#[cfg(feature = "listener")]
pub(crate) fn encode_response_checked(
    response: &crate::IpcResponse,
    limit: usize,
) -> Result<std::result::Result<WireBytes, usize>> {
    let request_id =
        NonZeroU64::new(response.request_id).ok_or_else(|| invalid("a positive request ID"))?;
    let result = match &response.result {
        crate::IpcResult::Output(output) => ResultRef::Output(OutputRef {
            schema: &output.schema,
            value: &output.value,
            window: &output.window,
        }),
        crate::IpcResult::Error(error) => ResultRef::Error(error),
    };
    encode_frame_checked(
        &ResponseRef {
            version: response.version.into(),
            request_id,
            generation: response.generation,
            result,
        },
        limit,
    )
}

pub fn encode_response(response: &crate::IpcResponse, limit: usize) -> Result<WireBytes> {
    let request_id =
        NonZeroU64::new(response.request_id).ok_or_else(|| invalid("a positive request ID"))?;
    let result = match &response.result {
        crate::IpcResult::Output(output) => ResultRef::Output(OutputRef {
            schema: &output.schema,
            value: &output.value,
            window: &output.window,
        }),
        crate::IpcResult::Error(error) => ResultRef::Error(error),
    };
    encode_frame(
        &ResponseRef {
            version: response.version.into(),
            request_id,
            generation: response.generation,
            result,
        },
        limit,
    )
}

pub fn decode_response(
    payload: &[u8],
    version: se_types::ApiVersion,
    generation: se_types::Generation,
    request_id: u64,
    limit: usize,
) -> Result<crate::IpcResponse> {
    let wire: ResponseWire = decode_json(payload, limit)?;
    if se_types::ApiVersion::from(wire.version) != version
        || wire.generation != generation
        || wire.request_id.get() != request_id
    {
        return Err(invalid(
            "a reply matching the original request ID, exact API and generation",
        ));
    }
    let result = match wire.result {
        ResultWire::Output(output) => crate::IpcResult::Output(Box::new(crate::OperationOutput {
            schema: output.schema,
            value: output.value,
            window: output.window,
        })),
        ResultWire::Error(error) => crate::IpcResult::Error(error),
    };
    Ok(crate::IpcResponse {
        version: wire.version.into(),
        request_id: wire.request_id.get(),
        generation: wire.generation,
        result,
    })
}
