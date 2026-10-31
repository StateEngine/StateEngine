//! Endpoint representation only. Protected publication, ownership and actual
//! server identity are native se-proc operations, not inferred from these bytes.
use super::wire::{MAX_ENDPOINT_BYTES, decode_json, encode_json};
use crate::{EndpointRecord, HostKind, IpcEndpoint};
use se_types::{
    Generation, HostEpoch, IdempotencyKey, NativePath, PathEncoding, Result, SeError, Secret,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordWire {
    schema: u16,
    address: AddressWire,
    #[serde(deserialize_with = "deserialize_epoch")]
    epoch: HostEpoch,
    generation: se_types::Generation,
    kind: KindWire,
    listener_port: Option<u16>,
    api: VersionWire,
    package_version: String,
    image_sha256: se_types::Sha256,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AddressWire {
    UnixSocket {
        #[serde(deserialize_with = "deserialize_path")]
        path: NativePath,
    },
    WindowsPipe {
        name: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum KindWire {
    Standalone,
    EmbeddedSecode,
}

fn invalid() -> SeError {
    SeError::invalid(
        "endpoint record",
        "schema 1, closed fields and a local native address",
    )
}
fn validate(record: &RecordWire) -> Result<()> {
    if record.schema != 1 || record.package_version.is_empty() || record.listener_port == Some(0) {
        return Err(invalid());
    }
    match &record.address {
        AddressWire::UnixSocket { path }
            if matches!(path.encoded(), PathEncoding::UnixBytes(_)) => {}
        AddressWire::WindowsPipe { name }
            if name.strip_prefix(r"\\.\pipe\").is_some_and(|tail| {
                !tail.is_empty() && !tail.contains('\0') && tail.len() <= 1024
            }) => {}
        _ => return Err(invalid()),
    }
    Ok(())
}

pub fn encode_endpoint(record: &EndpointRecord) -> Result<super::wire::WireBytes> {
    let wire = RecordWire {
        schema: record.schema,
        address: match &record.address {
            IpcEndpoint::UnixSocket(path) => AddressWire::UnixSocket { path: path.clone() },
            IpcEndpoint::WindowsPipe(name) => AddressWire::WindowsPipe { name: name.clone() },
        },
        epoch: record.epoch.clone(),
        generation: record.generation,
        kind: match record.kind {
            HostKind::Standalone => KindWire::Standalone,
            HostKind::EmbeddedSecode => KindWire::EmbeddedSecode,
        },
        listener_port: record.listener_port,
        api: record.api.into(),
        package_version: record.package_version.clone(),
        image_sha256: record.image_sha256,
    };
    validate(&wire)?;
    encode_json(&wire, MAX_ENDPOINT_BYTES)
}
pub fn decode_endpoint(bytes: &[u8]) -> Result<EndpointRecord> {
    let wire: RecordWire = decode_json(bytes, MAX_ENDPOINT_BYTES)?;
    validate(&wire)?;
    Ok(EndpointRecord {
        schema: wire.schema,
        address: match wire.address {
            AddressWire::UnixSocket { path } => IpcEndpoint::UnixSocket(path),
            AddressWire::WindowsPipe { name } => IpcEndpoint::WindowsPipe(name),
        },
        epoch: wire.epoch,
        generation: wire.generation,
        kind: match wire.kind {
            KindWire::Standalone => HostKind::Standalone,
            KindWire::EmbeddedSecode => HostKind::EmbeddedSecode,
        },
        listener_port: wire.listener_port,
        api: wire.api.into(),
        package_version: wire.package_version,
        image_sha256: wire.image_sha256,
    })
}

fn keys(value: &Value, allowed: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn deserialize_path<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<NativePath, D::Error> {
    let value = Value::deserialize(decoder)?;
    keys(&value, &["encoding", "units"]).map_err(serde::de::Error::custom)?;
    serde_json::from_value(value).map_err(|_| serde::de::Error::custom("invalid native IPC path"))
}
pub(crate) fn deserialize_epoch<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<HostEpoch, D::Error> {
    let value = Value::deserialize(decoder)?;
    let validate = || -> Result<()> {
        keys(&value, &["owner", "generation"])?;
        let owner = &value["owner"];
        keys(
            owner,
            &[
                "machine",
                "boot",
                "pid",
                "started",
                "executable",
                "argv_sha256",
            ],
        )?;
        keys(&owner["executable"], &["encoding", "units"])?;
        let started = &owner["started"];
        let fields: &[&str] = match started["os"].as_str() {
            Some("windows") => &["os", "creation_filetime"],
            Some("linux") => &["os", "start_ticks"],
            Some("macos") => &["os", "start_seconds", "start_micros"],
            _ => return Err(invalid()),
        };
        keys(started, fields)
    };
    validate().map_err(serde::de::Error::custom)?;
    serde_json::from_value(value).map_err(|_| serde::de::Error::custom("invalid native IPC epoch"))
}

// The fixed stop control is selected before ordinary API negotiation. It
// transports coordinator facts only; there is no stop/kill implementation here.
#[derive(Serialize, Deserialize)]
enum StopProtocol {
    #[serde(rename = "se.runtime.stop/v1")]
    V1,
}
#[derive(Serialize)]
struct StopRef<'a> {
    protocol: StopProtocol,
    expected_epoch: &'a HostEpoch,
    generation: se_types::Generation,
    key: &'a se_types::IdempotencyKey,
    deadline_at: se_types::UnixMicros,
    nonce: &'a [u8; 32],
    #[serde(serialize_with = "super::auth::secret_bytes::serialize")]
    mac: &'a se_types::Secret,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopWire {
    protocol: StopProtocol,
    #[serde(deserialize_with = "deserialize_epoch")]
    expected_epoch: HostEpoch,
    generation: se_types::Generation,
    key: se_types::IdempotencyKey,
    deadline_at: se_types::UnixMicros,
    nonce: [u8; 32],
    #[serde(deserialize_with = "super::auth::secret_bytes::deserialize")]
    mac: se_types::Secret,
}
pub fn encode_stop(request: &RuntimeStopRequest) -> Result<super::wire::WireBytes> {
    super::wire::encode_frame(
        &StopRef {
            protocol: StopProtocol::V1,
            expected_epoch: &request.expected_epoch,
            generation: request.generation,
            key: &request.key,
            deadline_at: request.deadline_at,
            nonce: &request.nonce,
            mac: &request.mac,
        },
        MAX_ENDPOINT_BYTES,
    )
}
/// An operation request or session credential cannot decode as stop control.
/// Runtime admission must check the deadline/epoch/G and verify the MAC in the
/// RuntimeStop domain against this channel's one-use native challenge.
pub fn decode_stop(bytes: &[u8]) -> Result<RuntimeStopRequest> {
    let wire: StopWire = decode_json(bytes, MAX_ENDPOINT_BYTES)?;
    let StopProtocol::V1 = wire.protocol;
    Ok(RuntimeStopRequest {
        expected_epoch: wire.expected_epoch,
        generation: wire.generation,
        key: wire.key,
        deadline_at: wire.deadline_at,
        nonce: wire.nonce,
        mac: wire.mac,
    })
}
#[derive(Serialize)]
struct StopReplyRef<'a> {
    protocol: StopProtocol,
    epoch: &'a HostEpoch,
    generation: se_types::Generation,
    key: &'a se_types::IdempotencyKey,
    outcome: &'a RuntimeStopOutcome,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StopReplyWire {
    protocol: StopProtocol,
    #[serde(deserialize_with = "deserialize_epoch")]
    epoch: HostEpoch,
    generation: se_types::Generation,
    key: se_types::IdempotencyKey,
    outcome: RuntimeStopOutcome,
}
pub fn encode_stop_reply(reply: &RuntimeStopReply, limit: usize) -> Result<super::wire::WireBytes> {
    super::wire::encode_frame(
        &StopReplyRef {
            protocol: StopProtocol::V1,
            epoch: &reply.epoch,
            generation: reply.generation,
            key: &reply.key,
            outcome: &reply.outcome,
        },
        limit,
    )
}
pub fn decode_stop_reply(
    bytes: &[u8],
    request: &RuntimeStopRequest,
    limit: usize,
) -> Result<RuntimeStopReply> {
    let wire: StopReplyWire = decode_json(bytes, limit)?;
    let StopProtocol::V1 = wire.protocol;
    if wire.epoch != request.expected_epoch
        || wire.generation != request.generation
        || wire.key != request.key
    {
        return Err(SeError::invalid(
            "stop control reply",
            "the exact original stop key, epoch and generation",
        ));
    }
    Ok(RuntimeStopReply {
        epoch: wire.epoch,
        generation: wire.generation,
        key: wire.key,
        outcome: wire.outcome,
    })
}

/// Fixed owner-only control request; deliberately has no operation API or
/// session/launch authority variant. OS/owner proof precedes decoding it.
pub struct RuntimeStopRequest {
    pub expected_epoch: HostEpoch,
    pub generation: Generation,
    pub key: IdempotencyKey,
    pub deadline_at: se_types::UnixMicros,
    pub nonce: [u8; 32],
    pub mac: Secret,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStopResume {
    pub project: se_types::ProjectId,
    pub agent: se_types::AgentId,
    pub conversation: se_types::ProviderSessionId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStopFact {
    AgentsStopped,
    ResumeSaved,
    CaptureFlushed,
    DebtFlushed,
    WriterJoined,
    ResourcesClosed,
    LeaseReleased,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeStopOutcome {
    Facts {
        achieved: Vec<RuntimeStopFact>,
        retained_resume: Vec<RuntimeStopResume>,
        pending: Vec<String>,
    },
    Refused {
        error: se_types::ErrorEnvelope,
    },
}
/// Facts must come from the ordinary shutdown coordinator's outside readbacks;
/// successful decoding and endpoint disappearance do not witness shutdown.
pub struct RuntimeStopReply {
    pub epoch: HostEpoch,
    pub generation: Generation,
    pub key: IdempotencyKey,
    pub outcome: RuntimeStopOutcome,
}

/// Routing probe only; the selected closed codec subsequently validates every
/// field/duplicate/depth before admission. Ignored credential bytes are never
/// materialized as a generic Value merely to choose the fixed control family.
#[cfg(feature = "listener")]
pub(crate) fn has_stop_protocol(bytes: &[u8]) -> Result<bool> {
    #[derive(Deserialize)]
    struct Probe {
        protocol: Option<String>,
    }
    serde_json::from_slice::<Probe>(bytes)
        .map(|p| p.protocol.is_some())
        .map_err(|_| SeError::invalid("IPC handshake", "one UTF-8 JSON object"))
}

/// Only the authenticated CLI core route decodes/applies this object; the
/// transport neither invents a selection DTO nor accepts metadata for hooks.
pub(crate) fn validate_selections(value: &Option<Value>, hook: bool) -> Result<()> {
    if value.as_ref().is_some_and(|v| hook || !v.is_object()) {
        return Err(SeError::invalid(
            "CLI selections",
            "an optional operation-only CLI routing object",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VersionWire {
    pub major: u16,
    pub minor: u16,
}
impl From<se_types::ApiVersion> for VersionWire {
    fn from(version: se_types::ApiVersion) -> Self {
        Self {
            major: version.major,
            minor: version.minor,
        }
    }
}
impl From<VersionWire> for se_types::ApiVersion {
    fn from(version: VersionWire) -> Self {
        Self {
            major: version.major,
            minor: version.minor,
        }
    }
}
