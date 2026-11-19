//! Native restart rebind envelopes. Peer identity comes only from the channel.
use super::{auth::secret_bytes, endpoint::deserialize_epoch, wire};
use se_types::{
    AgentId, Cursor, Generation, HostEpoch, ProjectId, Read, Result, Secret, SessionId,
};
use serde::{Deserialize, Serialize};

const PROTOCOL: &str = "se.session.rebind/v1";

/// The named seat is checked against the peer's registered image.
pub struct RebindRequest {
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub expected_epoch: HostEpoch,
    pub generation: Generation,
    pub control_endpoint: String,
}

/// Credential bytes must remain protected throughout framing and transport.
pub struct RebindReply {
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
    pub capability: Secret,
    pub http_bearer: Secret,
    pub restart_key: String,
    pub cursor: Read<Cursor>,
}

#[derive(Serialize)]
struct RequestRef<'a> {
    protocol: &'static str,
    project_id: &'a ProjectId,
    agent_id: &'a AgentId,
    expected_epoch: &'a HostEpoch,
    generation: Generation,
    control_endpoint: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestWire {
    protocol: String,
    project_id: ProjectId,
    agent_id: AgentId,
    #[serde(deserialize_with = "deserialize_epoch")]
    expected_epoch: HostEpoch,
    generation: Generation,
    control_endpoint: String,
}

pub fn encode_request(request: &RebindRequest) -> Result<wire::WireBytes> {
    wire::encode_frame(
        &RequestRef {
            protocol: PROTOCOL,
            project_id: &request.project_id,
            agent_id: &request.agent_id,
            expected_epoch: &request.expected_epoch,
            generation: request.generation,
            control_endpoint: &request.control_endpoint,
        },
        wire::MAX_ENDPOINT_BYTES,
    )
}

pub fn decode_request(bytes: &[u8]) -> Result<RebindRequest> {
    let wire: RequestWire = wire::decode_json(bytes, wire::MAX_ENDPOINT_BYTES)?;
    if wire.protocol != PROTOCOL {
        return Err(se_types::SeError::invalid(
            "rebind request",
            "the supported local rebind protocol",
        ));
    }
    Ok(RebindRequest {
        project_id: wire.project_id,
        agent_id: wire.agent_id,
        expected_epoch: wire.expected_epoch,
        generation: wire.generation,
        control_endpoint: wire.control_endpoint,
    })
}

#[derive(Serialize)]
struct ReplyRef<'a> {
    protocol: &'static str,
    project: &'a ProjectId,
    agent: &'a AgentId,
    session: &'a SessionId,
    #[serde(serialize_with = "secret_bytes::serialize")]
    capability: &'a Secret,
    #[serde(serialize_with = "secret_bytes::serialize")]
    http_bearer: &'a Secret,
    restart_key: &'a str,
    cursor: &'a Read<Cursor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyWire {
    protocol: String,
    project: ProjectId,
    agent: AgentId,
    session: SessionId,
    #[serde(deserialize_with = "secret_bytes::deserialize")]
    capability: Secret,
    #[serde(deserialize_with = "secret_bytes::deserialize")]
    http_bearer: Secret,
    restart_key: String,
    cursor: Read<Cursor>,
}

pub fn encode_reply(reply: &RebindReply) -> Result<wire::WireBytes> {
    wire::encode_frame(
        &ReplyRef {
            protocol: PROTOCOL,
            project: &reply.project,
            agent: &reply.agent,
            session: &reply.session,
            capability: &reply.capability,
            http_bearer: &reply.http_bearer,
            restart_key: &reply.restart_key,
            cursor: &reply.cursor,
        },
        wire::MAX_ENDPOINT_BYTES,
    )
}

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Outcome {
    Granted(ReplyWire),
    Refused { error: se_types::ErrorEnvelope },
}

pub fn decode_reply(bytes: &[u8]) -> Result<RebindReply> {
    let wire = match wire::decode_json::<Outcome>(bytes, wire::MAX_ENDPOINT_BYTES)? {
        Outcome::Granted(value) => value,
        Outcome::Refused { error } => return Err(error.body().clone().into()),
    };
    if wire.protocol != PROTOCOL
        || wire.restart_key.len() != 64
        || !wire
            .restart_key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(se_types::SeError::invalid(
            "rebind reply",
            "the supported local rebind protocol",
        ));
    }
    Ok(RebindReply {
        project: wire.project,
        agent: wire.agent,
        session: wire.session,
        capability: wire.capability,
        http_bearer: wire.http_bearer,
        restart_key: wire.restart_key,
        cursor: wire.cursor,
    })
}
