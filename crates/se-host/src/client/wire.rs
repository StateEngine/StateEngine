//! Shared blocking/async IPC codec. A transport supplies deadline-aware I/O;
//! this module never dispatches an operation or interprets a request key.
use se_types::{Result, SeError};
use serde::{Deserialize, Serialize, de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor}};
use serde_json::{Map, Number, Value};
use std::{fmt, io::{self, Read, Write}};
use std::num::NonZeroU64;

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const DEFAULT_REPLY_BYTES: u32 = 262_144;
pub const MAX_JSON_DEPTH: u8 = 64;
pub const MAX_ENDPOINT_BYTES: usize = 16 * 1024;

fn invalid(expected: &str) -> SeError {
    SeError::invalid("IPC frame", expected)
}

struct LimitedBuffer {
    bytes: Vec<u8>,
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
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

/// Count the entire JSON envelope, including window/marker/error metadata.
/// A refusal writes no prefix or partial JSON to the channel.
pub fn encode_json<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
    if limit == 0 || limit > MAX_FRAME_BYTES {
        return Err(invalid("a nonzero budget at most 1 MiB"));
    }
    let mut output = LimitedBuffer { bytes: Vec::new(), limit };
    serde_json::to_writer(&mut output, value)
        .map_err(|_| invalid("complete JSON within the negotiated byte budget"))?;
    Ok(output.bytes)
}

/// Reject duplicates throughout arguments too; Value's ordinary decoder would
/// overwrite an earlier key before the closed core DTO could inspect it.
pub fn decode_json<T: DeserializeOwned>(bytes: &[u8], limit: usize) -> Result<T> {
    if bytes.is_empty() || bytes.len() > limit || limit > MAX_FRAME_BYTES {
        return Err(invalid("nonempty JSON within the negotiated byte budget"));
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = JsonSeed { depth: 0 }.deserialize(&mut decoder)
        .map_err(|_| invalid("UTF-8 JSON, unique fields and depth at most 64"))?;
    decoder.end().map_err(|_| invalid("one complete JSON value"))?;
    serde_json::from_value(value).map_err(|_| invalid("the closed versioned IPC envelope"))
}

pub fn encode_frame<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>> {
    let payload = encode_json(value, limit)?;
    let length = u32::try_from(payload.len()).map_err(|_| invalid("a bounded frame length"))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

pub fn frame_length(header: [u8; 4], limit: usize) -> Result<usize> {
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > limit || limit > MAX_FRAME_BYTES {
        return Err(invalid("a positive frame length within the byte budget"));
    }
    Ok(length)
}

/// Read an exact frame. EOF (including mid-header/body) remains an error, never
/// an empty operation/result. The native channel applies the absolute deadline.
pub fn read_frame<R: Read, T: DeserializeOwned>(reader: &mut R, limit: usize) -> Result<T> {
    let mut header = [0; 4];
    reader.read_exact(&mut header).map_err(|error| io_failure("read header", error))?;
    let mut payload = vec![0; frame_length(header, limit)?];
    reader.read_exact(&mut payload).map_err(|error| io_failure("read body", error))?;
    decode_json(&payload, limit)
}

pub fn write_frame<W: Write, T: Serialize>(writer: &mut W, value: &T, limit: usize) -> Result<()> {
    let frame = encode_frame(value, limit)?;
    writer.write_all(&frame).map_err(|error| io_failure("write frame", error))?;
    writer.flush().map_err(|error| io_failure("flush frame", error))
}

pub(crate) fn io_failure(stage: &str, error: io::Error) -> SeError {
    SeError::new(se_types::Detail::IpcUnavailable(se_types::details::IpcUnavailable {
        endpoint: "verified local IPC channel".into(),
        reason: format!("{stage}: {error}"),
    }))
}

/// Secret serialization is confined to protected IPC frames, never implemented
/// on Secret itself and never used for endpoint records or diagnostics.
pub(crate) mod secret_bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(secret: &se_types::Secret, serializer: S)
        -> std::result::Result<S::Ok, S::Error> {
        secret.expose().serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(decoder: D)
        -> std::result::Result<se_types::Secret, D::Error> {
        se_types::Secret::new(Vec::<u8>::deserialize(decoder)?).map_err(de::Error::custom)
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "proof", rename_all = "snake_case")]
pub(crate) enum AuthorityRef<'a> {
    OwnerProof { nonce: &'a [u8; 32], #[serde(serialize_with = "secret_bytes::serialize")] mac: &'a se_types::Secret },
    Session(#[serde(serialize_with = "secret_bytes::serialize")] &'a se_types::Secret),
    Launch(#[serde(serialize_with = "secret_bytes::serialize")] &'a se_types::Secret),
}
impl<'a> From<&'a crate::PresentedAuthority> for AuthorityRef<'a> {
    fn from(authority: &'a crate::PresentedAuthority) -> Self {
        match authority {
            crate::PresentedAuthority::OwnerProof { nonce, mac } => Self::OwnerProof { nonce, mac },
            crate::PresentedAuthority::Session(token) => Self::Session(token),
            crate::PresentedAuthority::Launch(token) => Self::Launch(token),
        }
    }
}
#[derive(Deserialize)]
#[serde(tag = "kind", content = "proof", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum AuthorityWire {
    OwnerProof { nonce: [u8; 32], #[serde(deserialize_with = "secret_bytes::deserialize")] mac: se_types::Secret },
    Session(#[serde(deserialize_with = "secret_bytes::deserialize")] se_types::Secret),
    Launch(#[serde(deserialize_with = "secret_bytes::deserialize")] se_types::Secret),
}
impl From<AuthorityWire> for crate::PresentedAuthority {
    fn from(authority: AuthorityWire) -> Self {
        match authority {
            AuthorityWire::OwnerProof { nonce, mac } => Self::OwnerProof { nonce, mac },
            AuthorityWire::Session(token) => Self::Session(token),
            AuthorityWire::Launch(token) => Self::Launch(token),
        }
    }
}

#[derive(Serialize)]
struct CallRef<'a> {
    version: se_types::ApiVersion,
    request_id: NonZeroU64,
    generation: se_types::Generation,
    authority: Option<AuthorityRef<'a>>,
    request: RequestRef<'a>,
}
#[derive(Serialize)]
#[serde(tag = "kind", content = "input", rename_all = "snake_case")]
enum RequestRef<'a> { Operation(OperationRef<'a>), Hook(HookRef<'a>) }
#[derive(Serialize)]
struct OperationRef<'a> { name: &'a str, arguments: &'a Value, key: &'a Option<se_types::IdempotencyKey> }
#[derive(Serialize)]
struct HookRef<'a> {
    kind: HookKind,
    conversation: &'a se_types::ProviderSessionId,
    claimed_transcript: &'a se_types::NativePath,
    payload: &'a Value,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HookKind { SessionStart, Prompt, Stop, StopFailure }
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
    version: se_types::ApiVersion,
    request_id: NonZeroU64,
    generation: se_types::Generation,
    authority: Option<AuthorityWire>,
    request: RequestWire,
}
#[derive(Deserialize)]
#[serde(tag = "kind", content = "input", rename_all = "snake_case", deny_unknown_fields)]
enum RequestWire { Operation(OperationWire), Hook(HookWire) }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationWire { name: String, arguments: Value, key: Option<se_types::IdempotencyKey> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HookWire {
    kind: HookKind,
    conversation: se_types::ProviderSessionId,
    claimed_transcript: se_types::NativePath,
    payload: Value,
}

pub fn encode_call(call: &crate::IpcEnvelope) -> Result<Vec<u8>> {
    let request_id = NonZeroU64::new(call.request_id).ok_or_else(|| invalid("a positive request ID"))?;
    let request = match &call.request {
        crate::IpcRequest::Operation(operation) => RequestRef::Operation(OperationRef {
            name: &operation.name, arguments: &operation.arguments, key: &operation.key,
        }),
        crate::IpcRequest::Hook(hook) => RequestRef::Hook(HookRef { kind: hook.kind.into(),
            conversation: &hook.conversation, claimed_transcript: &hook.claimed_transcript, payload: &hook.payload }),
    };
    encode_frame(&CallRef { version: call.version, request_id, generation: call.generation,
        authority: call.authority.as_ref().map(AuthorityRef::from), request }, MAX_FRAME_BYTES)
}

pub fn decode_call(payload: &[u8]) -> Result<crate::IpcEnvelope> {
    let wire: CallWire = decode_json(payload, MAX_FRAME_BYTES)?;
    let request = match wire.request {
        RequestWire::Operation(operation) => crate::IpcRequest::Operation(crate::RawOperation {
            name: operation.name, arguments: operation.arguments, key: operation.key,
        }),
        RequestWire::Hook(hook) => crate::IpcRequest::Hook(crate::ClaudeHookInput {
            kind: hook.kind.into(), conversation: hook.conversation,
            claimed_transcript: hook.claimed_transcript, payload: hook.payload,
        }),
    };
    Ok(crate::IpcEnvelope { version: wire.version, request_id: wire.request_id.get(), generation: wire.generation,
        authority: wire.authority.map(Into::into), request })
}

#[derive(Serialize)]
struct ResponseRef<'a> {
    version: se_types::ApiVersion, request_id: NonZeroU64, generation: se_types::Generation, result: ResultRef<'a>,
}
#[derive(Serialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
enum ResultRef<'a> { Output(OutputRef<'a>), Error(&'a se_types::ErrorEnvelope) }
#[derive(Serialize)]
struct OutputRef<'a> { schema: &'a str, value: &'a Value, window: &'a Option<se_types::Window> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseWire {
    version: se_types::ApiVersion, request_id: NonZeroU64, generation: se_types::Generation, result: ResultWire,
}
#[derive(Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case", deny_unknown_fields)]
enum ResultWire { Output(OutputWire), Error(se_types::ErrorEnvelope) }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutputWire { schema: String, value: Value, window: Option<se_types::Window> }

pub fn encode_response(response: &crate::IpcResponse, limit: usize) -> Result<Vec<u8>> {
    let request_id = NonZeroU64::new(response.request_id).ok_or_else(|| invalid("a positive request ID"))?;
    let result = match &response.result {
        crate::IpcResult::Output(output) => ResultRef::Output(OutputRef { schema: &output.schema, value: &output.value, window: &output.window }),
        crate::IpcResult::Error(error) => ResultRef::Error(error),
    };
    encode_frame(&ResponseRef { version: response.version, request_id, generation: response.generation, result }, limit)
}

pub fn decode_response(payload: &[u8], version: se_types::ApiVersion, generation: se_types::Generation,
    request_id: u64, limit: usize) -> Result<crate::IpcResponse> {
    let wire: ResponseWire = decode_json(payload, limit)?;
    if wire.version != version || wire.generation != generation || wire.request_id.get() != request_id {
        return Err(invalid("a reply matching the original request ID, exact API and generation"));
    }
    let result = match wire.result {
        ResultWire::Output(output) => crate::IpcResult::Output(crate::OperationOutput {
            schema: output.schema, value: output.value, window: output.window,
        }),
        ResultWire::Error(error) => crate::IpcResult::Error(error),
    };
    Ok(crate::IpcResponse { version: wire.version, request_id: wire.request_id.get(), generation: wire.generation, result })
}

struct JsonSeed { depth: u8 }
impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, decoder: D) -> std::result::Result<Value, D::Error> {
        decoder.deserialize_any(JsonVisitor { depth: self.depth })
    }
}
struct JsonVisitor { depth: u8 }
impl JsonVisitor {
    fn child<E: de::Error>(&self) -> std::result::Result<JsonSeed, E> {
        if self.depth >= MAX_JSON_DEPTH {
            return Err(E::custom("IPC JSON depth exceeded"));
        }
        Ok(JsonSeed { depth: self.depth + 1 })
    }
}
impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Value;
    fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result { out.write_str("bounded JSON") }
    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Value, E> { Ok(Value::Bool(value)) }
    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Value, E> { Ok(value.into()) }
    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Value, E> { Ok(value.into()) }
    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Value, E> {
        Number::from_f64(value).map(Value::Number).ok_or_else(|| E::custom("non-finite number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Value, E> { Ok(Value::String(value.into())) }
    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Value, E> { Ok(Value::String(value)) }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> { Ok(Value::Null) }
    fn visit_none<E: de::Error>(self) -> std::result::Result<Value, E> { Ok(Value::Null) }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<Value, A::Error> {
        self.child::<A::Error>()?;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(self.child()?)? { values.push(value); }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> std::result::Result<Value, A::Error> {
        self.child::<A::Error>()?;
        let mut values = Map::new();
        while let Some(key) = fields.next_key::<String>()? {
            if values.contains_key(&key) { return Err(de::Error::custom("duplicate IPC JSON field")); }
            let value = fields.next_value_seed(self.child()?)?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
