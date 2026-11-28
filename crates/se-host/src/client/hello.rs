//! One closed pre-authentication envelope decoder. Family selection never first
//! builds a generic JSON value containing credentials or parses a routing probe.
use super::{
    auth::{AuthorityWire, ProtectedSecret},
    endpoint::VersionWire,
    wire,
};
use crate::ClientHello;
use se_types::{Result, SeError};
use serde::{Deserialize, Deserializer};

pub enum DecodedHandshake {
    Call(ClientHello),
    Stop(Box<super::endpoint::RuntimeStopRequest>),
    Rebind(Box<super::rebind::RebindRequest>),
}
#[derive(Default)]
enum Field<T> {
    #[default]
    Missing,
    Present(T),
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for Field<T> {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> std::result::Result<Self, D::Error> {
        T::deserialize(decoder).map(Self::Present)
    }
}
impl<T> Field<T> {
    fn missing(&self) -> bool {
        matches!(self, Self::Missing)
    }
    fn required(self) -> Result<T> {
        match self {
            Self::Present(value) => Ok(value),
            Self::Missing => Err(invalid()),
        }
    }
}
#[derive(Deserialize)]
struct Epoch(#[serde(deserialize_with = "super::endpoint::deserialize_epoch")] se_types::HostEpoch);
#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct Envelope {
    protocol: Field<String>,
    version: Field<VersionWire>,
    expected_generation: Field<Option<se_types::Generation>>,
    maximum_reply_bytes: Field<std::num::NonZeroU32>,
    authority: Field<AuthorityWire>,
    client_capabilities: Field<Option<Vec<String>>>,
    control_endpoint: Field<String>,
    project_id: Field<se_types::ProjectId>,
    agent_id: Field<se_types::AgentId>,
    expected_epoch: Field<Epoch>,
    generation: Field<se_types::Generation>,
    key: Field<se_types::IdempotencyKey>,
    deadline_at: Field<se_types::UnixMicros>,
    nonce: Field<[u8; 32]>,
    mac: Field<ProtectedSecret>,
}
pub fn decode(bytes: &[u8]) -> Result<DecodedHandshake> {
    let input: Envelope = wire::decode_json(bytes, wire::MAX_ENDPOINT_BYTES)?;
    match input.protocol {
        Field::Missing => {
            if !input.project_id.missing()
                || !input.agent_id.missing()
                || !input.control_endpoint.missing()
                || !input.expected_epoch.missing()
                || !input.generation.missing()
                || !input.key.missing()
                || !input.deadline_at.missing()
                || !input.nonce.missing()
                || !input.mac.missing()
            {
                return Err(invalid());
            }
            let maximum_reply_bytes = input.maximum_reply_bytes.required()?;
            if maximum_reply_bytes.get() as usize > wire::MAX_FRAME_BYTES {
                return Err(invalid());
            }
            let client_capabilities = match input.client_capabilities {
                Field::Missing | Field::Present(None) => None,
                Field::Present(Some(caps)) => {
                    super::auth::validate_capabilities(&caps)?;
                    Some(caps)
                }
            };
            Ok(DecodedHandshake::Call(ClientHello {
                version: input.version.required()?.into(),
                expected_generation: match input.expected_generation {
                    Field::Missing => None,
                    Field::Present(value) => value,
                },
                maximum_reply_bytes,
                authority: input.authority.required()?.into(),
                client_capabilities,
            }))
        }
        Field::Present(protocol) => {
            if protocol == "se.session.rebind/v1" {
                if !input.version.missing()
                    || !input.expected_generation.missing()
                    || !input.maximum_reply_bytes.missing()
                    || !input.authority.missing()
                    || !input.client_capabilities.missing()
                    || !input.key.missing()
                    || !input.deadline_at.missing()
                    || !input.nonce.missing()
                    || !input.mac.missing()
                {
                    return Err(invalid());
                }
                return Ok(DecodedHandshake::Rebind(Box::new(
                    super::rebind::RebindRequest {
                        project_id: input.project_id.required()?,
                        agent_id: input.agent_id.required()?,
                        expected_epoch: input.expected_epoch.required()?.0,
                        generation: input.generation.required()?,
                        control_endpoint: input.control_endpoint.required()?,
                    },
                )));
            }
            if !input.project_id.missing()
                || !input.agent_id.missing()
                || !input.control_endpoint.missing()
                || protocol != "se.runtime.stop/v1"
                || !input.version.missing()
                || !input.expected_generation.missing()
                || !input.maximum_reply_bytes.missing()
                || !input.authority.missing()
                || !input.client_capabilities.missing()
            {
                return Err(invalid());
            }
            Ok(DecodedHandshake::Stop(Box::new(
                super::endpoint::RuntimeStopRequest {
                    expected_epoch: input.expected_epoch.required()?.0,
                    generation: input.generation.required()?,
                    key: input.key.required()?,
                    deadline_at: input.deadline_at.required()?,
                    nonce: input.nonce.required()?,
                    mac: input.mac.required()?.into_secret(),
                },
            )))
        }
    }
}
fn invalid() -> SeError {
    SeError::invalid(
        "IPC handshake",
        "one closed operation hello or fixed stop control within 16 KiB, without mixed family fields",
    )
}
