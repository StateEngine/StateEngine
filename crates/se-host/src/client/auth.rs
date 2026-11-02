//! Common challenge MAC. Native peer/owner provenance comes from se-proc;
//! session/launch revocation and operation admission stay in the runtime.
use super::endpoint::VersionWire;
use super::wire::{MAX_ENDPOINT_BYTES, MAX_FRAME_BYTES, decode_json, encode_frame, encode_json};
use crate::{EndpointRecord, ServerChallenge};
use hmac::{Hmac, Mac};
use se_types::{Result, SeError, Secret};
use serde::de;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::num::NonZeroU32;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeWire {
    version: VersionWire,
    #[serde(deserialize_with = "super::endpoint::deserialize_epoch")]
    epoch: se_types::HostEpoch,
    nonce: [u8; 32],
    image_sha256: se_types::Sha256,
}
#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum ChallengeReply {
    Challenge(ChallengeWire),
    Refused { error: se_types::ErrorEnvelope },
}
pub fn encode_challenge(challenge: &ServerChallenge) -> Result<super::wire::WireBytes> {
    encode_frame(
        &ChallengeWire {
            version: challenge.version.into(),
            epoch: challenge.epoch.clone(),
            nonce: challenge.nonce,
            image_sha256: challenge.image_sha256,
        },
        MAX_ENDPOINT_BYTES,
    )
}
/// Called after native server proof. These fields must also match the protected
/// routing record; their JSON cannot substitute for OS peer/start/image proof.
pub fn decode_challenge(bytes: &[u8], expected: &EndpointRecord) -> Result<ServerChallenge> {
    let wire = match decode_json::<ChallengeReply>(bytes, MAX_ENDPOINT_BYTES)? {
        ChallengeReply::Challenge(wire) => wire,
        ChallengeReply::Refused { error } => return Err(error.body().clone().into()),
    };
    let challenge = ServerChallenge {
        version: wire.version.into(),
        epoch: wire.epoch,
        nonce: wire.nonce,
        image_sha256: wire.image_sha256,
    };
    if challenge.epoch != expected.epoch
        || challenge.image_sha256 != expected.image_sha256
        || challenge.version != expected.api
    {
        return Err(refused(
            "challenge differs from the verified native server record",
        ));
    }
    Ok(challenge)
}

#[derive(Serialize)]
struct HelloRef<'a> {
    version: VersionWire,
    expected_generation: Option<se_types::Generation>,
    maximum_reply_bytes: NonZeroU32,
    authority: AuthorityRef<'a>,
}
pub fn encode_client_hello(hello: &crate::ClientHello) -> Result<super::wire::WireBytes> {
    if hello.maximum_reply_bytes.get() as usize > MAX_FRAME_BYTES {
        return Err(refused("reply cap exceeds 1 MiB"));
    }
    encode_frame(
        &HelloRef {
            version: hello.version.into(),
            expected_generation: hello.expected_generation,
            maximum_reply_bytes: hello.maximum_reply_bytes,
            authority: (&hello.authority).into(),
        },
        MAX_ENDPOINT_BYTES,
    )
}
pub fn decode_client_hello(bytes: &[u8]) -> Result<crate::ClientHello> {
    match super::hello::decode(bytes)? {
        super::hello::DecodedHandshake::Call(hello) => Ok(hello),
        _ => Err(refused("an operation hello, not stop control")),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyWire {
    version: VersionWire,
    #[serde(deserialize_with = "super::endpoint::deserialize_epoch")]
    epoch: se_types::HostEpoch,
    generation: se_types::Generation,
    maximum_reply_bytes: NonZeroU32,
}
/// Negotiation alone confers no authority; runtime admission validates the
/// presented credential and rechecks revocation/scope for every request.
pub fn negotiate_hello(
    hello: &crate::ClientHello,
    endpoint: &EndpointRecord,
    server_cap: NonZeroU32,
) -> Result<crate::ServerHello> {
    if hello.version != endpoint.api {
        return Err(SeError::new(se_types::Detail::ApiVersionUnsupported(
            se_types::details::ApiVersionUnsupported {
                client: format!("{}.{}", hello.version.major, hello.version.minor),
                host: format!("{}.{}", endpoint.api.major, endpoint.api.minor),
            },
        )));
    }
    if hello
        .expected_generation
        .is_some_and(|generation| generation != endpoint.generation)
    {
        return Err(refused(
            "expected runtime generation is stale; rediscover without replacing the request key",
        ));
    }
    let effective = hello
        .maximum_reply_bytes
        .min(server_cap)
        .get()
        .min(MAX_FRAME_BYTES as u32);
    let maximum_reply_bytes =
        NonZeroU32::new(effective).ok_or_else(|| refused("invalid reply cap"))?;
    Ok(crate::ServerHello {
        version: endpoint.api,
        epoch: endpoint.epoch.clone(),
        generation: endpoint.generation,
        maximum_reply_bytes,
    })
}
pub fn encode_server_hello(hello: &crate::ServerHello) -> Result<super::wire::WireBytes> {
    if hello.maximum_reply_bytes.get() as usize > MAX_FRAME_BYTES {
        return Err(refused("reply cap exceeds 1 MiB"));
    }
    encode_frame(
        &ReadyWire {
            version: hello.version.into(),
            epoch: hello.epoch.clone(),
            generation: hello.generation,
            maximum_reply_bytes: hello.maximum_reply_bytes,
        },
        MAX_ENDPOINT_BYTES,
    )
}
#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum ReadyReply {
    Ready(ReadyWire),
    Refused { error: se_types::ErrorEnvelope },
}
#[derive(Serialize)]
struct HelloRefusal<'a> {
    error: &'a se_types::ErrorEnvelope,
}
pub fn encode_hello_refusal(error: &se_types::ErrorEnvelope) -> Result<super::wire::WireBytes> {
    encode_frame(&HelloRefusal { error }, MAX_ENDPOINT_BYTES)
}
pub fn decode_server_hello(
    bytes: &[u8],
    sent: &crate::ClientHello,
    challenge: &ServerChallenge,
) -> Result<crate::ServerHello> {
    let wire = match decode_json::<ReadyReply>(bytes, MAX_ENDPOINT_BYTES)? {
        ReadyReply::Ready(wire) => wire,
        ReadyReply::Refused { error } => return Err(error.body().clone().into()),
    };
    if se_types::ApiVersion::from(wire.version) != sent.version
        || wire.epoch != challenge.epoch
        || wire.maximum_reply_bytes > sent.maximum_reply_bytes
        || wire.maximum_reply_bytes.get() as usize > MAX_FRAME_BYTES
        || sent
            .expected_generation
            .is_some_and(|generation| generation != wire.generation)
    {
        return Err(refused(
            "server hello differs from the channel challenge or request bounds",
        ));
    }
    Ok(crate::ServerHello {
        version: wire.version.into(),
        epoch: wire.epoch,
        generation: wire.generation,
        maximum_reply_bytes: wire.maximum_reply_bytes,
    })
}

#[derive(Clone, Copy)]
pub enum ProofDomain {
    Owner,
    RuntimeStop,
}
impl ProofDomain {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Owner => b"se.ipc.owner/v1",
            Self::RuntimeStop => b"se.runtime.stop/v1",
        }
    }
}

fn refused(reason: &str) -> SeError {
    SeError::new(se_types::Detail::CapabilityInvalid(
        se_types::details::CapabilityInvalid {
            subject: "local IPC proof".into(),
            reason: reason.into(),
            next_step: "Reconnect to the verified local runtime with the original request key"
                .into(),
        },
    ))
}

pub fn fresh_nonce() -> Result<[u8; 32]> {
    let mut nonce = [0; 32];
    se_proc::fill_entropy(&mut nonce).map_err(|_| refused("OS randomness is unavailable"))?;
    Ok(nonce)
}

fn field(mac: &mut Hmac<Sha256>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| refused("proof field is oversized"))?;
    mac.update(&length.to_be_bytes());
    mac.update(bytes);
    Ok(())
}

fn mac_state(
    key: &Secret,
    domain: ProofDomain,
    challenge: &ServerChallenge,
    client_nonce: &[u8; 32],
    verified_peer: &[u8],
) -> Result<Hmac<Sha256>> {
    if key.expose().len() < 32
        || verified_peer.is_empty()
        || verified_peer.len() > MAX_ENDPOINT_BYTES
    {
        return Err(refused(
            "missing native peer binding or invalid machine key",
        ));
    }
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.expose()).map_err(|_| refused("invalid machine key"))?;
    field(&mut mac, domain.bytes())?;
    let mut version = [0; 4];
    version[..2].copy_from_slice(&challenge.version.major.to_be_bytes());
    version[2..].copy_from_slice(&challenge.version.minor.to_be_bytes());
    field(&mut mac, &version)?;
    // Explicitly sort objects: serde_json's preserve_order feature can be
    // enabled by an embedding consumer without changing this proof encoding.
    let mut epoch =
        serde_json::to_value(&challenge.epoch).map_err(|_| refused("invalid host epoch"))?;
    sort_objects(&mut epoch);
    field(
        &mut mac,
        encode_json(&epoch, MAX_ENDPOINT_BYTES)?.as_bytes(),
    )?;
    field(&mut mac, challenge.image_sha256.as_bytes())?;
    field(&mut mac, &challenge.nonce)?;
    field(&mut mac, client_nonce)?;
    field(&mut mac, verified_peer)?;
    Ok(mac)
}

/// The binding is canonical native peer identity, never a peer ID from JSON.
/// This function creates bytes only; it grants no owner or operation authority.
pub fn create_owner_mac(
    key: &Secret,
    domain: ProofDomain,
    challenge: &ServerChallenge,
    client_nonce: &[u8; 32],
    verified_peer: &[u8],
) -> Result<Secret> {
    Secret::new(
        mac_state(key, domain, challenge, client_nonce, verified_peer)?
            .finalize()
            .into_bytes()
            .to_vec(),
    )
}

pub fn verify_owner_mac(
    key: &Secret,
    domain: ProofDomain,
    challenge: &ServerChallenge,
    client_nonce: &[u8; 32],
    verified_peer: &[u8],
    supplied: &Secret,
) -> Result<()> {
    mac_state(key, domain, challenge, client_nonce, verified_peer)?
        .verify_slice(supplied.expose())
        .map_err(|_| refused("machine proof does not match this channel challenge"))
}

/// One-use challenge state retained by one accepted native channel. Taking the
/// challenge consumes it even when the subsequent proof fails.
pub struct OwnerChallenge {
    challenge: Option<ServerChallenge>,
    domain: ProofDomain,
}
impl OwnerChallenge {
    #[cfg(feature = "listener")]
    pub(crate) fn stop_domain(&mut self) {
        self.domain = ProofDomain::RuntimeStop;
    }
    pub fn begin(endpoint: &EndpointRecord, domain: ProofDomain) -> Result<Self> {
        Ok(Self {
            challenge: Some(ServerChallenge {
                version: endpoint.api,
                epoch: endpoint.epoch.clone(),
                image_sha256: endpoint.image_sha256,
                nonce: fresh_nonce()?,
            }),
            domain,
        })
    }
    pub fn challenge(&self) -> Result<&ServerChallenge> {
        self.challenge
            .as_ref()
            .ok_or_else(|| refused("challenge was already consumed"))
    }
    pub fn verify(
        &mut self,
        key: &Secret,
        client_nonce: &[u8; 32],
        verified_peer: &[u8],
        supplied: &Secret,
    ) -> Result<()> {
        let challenge = self
            .challenge
            .take()
            .ok_or_else(|| refused("challenge was already consumed"))?;
        verify_owner_mac(
            key,
            self.domain,
            &challenge,
            client_nonce,
            verified_peer,
            supplied,
        )
    }
}

fn sort_objects(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let mut fields: Vec<_> = std::mem::take(map).into_iter().collect();
            fields.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (key, mut value) in fields {
                sort_objects(&mut value);
                map.insert(key, value);
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(sort_objects),
        _ => (),
    }
}

/// Secret serialization is confined to protected IPC frames, never implemented
/// on Secret itself and never used for endpoint records or diagnostics.
pub(crate) mod secret_bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        secret: &se_types::Secret,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        secret.expose().serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        decoder: D,
    ) -> std::result::Result<se_types::Secret, D::Error> {
        struct SecretVisitor;
        impl<'de> de::Visitor<'de> for SecretVisitor {
            type Value = se_types::Secret;
            fn expecting(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("1..65536 protected credential bytes")
            }
            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(65536));
                while let Some(byte) = seq.next_element::<u8>()? {
                    if bytes.len() == 65536 {
                        return Err(de::Error::custom("credential exceeds protected byte bound"));
                    }
                    bytes.push(byte);
                }
                se_types::Secret::new(std::mem::take(&mut *bytes)).map_err(de::Error::custom)
            }
        }
        decoder.deserialize_seq(SecretVisitor)
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", content = "proof", rename_all = "snake_case")]
pub(crate) enum AuthorityRef<'a> {
    OwnerProof {
        nonce: &'a [u8; 32],
        #[serde(serialize_with = "secret_bytes::serialize")]
        mac: &'a se_types::Secret,
    },
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
#[serde(transparent)]
pub(crate) struct ProtectedSecret(
    #[serde(deserialize_with = "secret_bytes::deserialize")] se_types::Secret,
);

impl ProtectedSecret {
    pub(crate) fn into_secret(self) -> se_types::Secret {
        self.0
    }
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    content = "proof",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum AuthorityWire {
    OwnerProof {
        nonce: [u8; 32],
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        mac: se_types::Secret,
    },
    Session(ProtectedSecret),
    Launch(ProtectedSecret),
}
impl From<AuthorityWire> for crate::PresentedAuthority {
    fn from(authority: AuthorityWire) -> Self {
        match authority {
            AuthorityWire::OwnerProof { nonce, mac } => Self::OwnerProof { nonce, mac },
            AuthorityWire::Session(token) => Self::Session(token.0),
            AuthorityWire::Launch(token) => Self::Launch(token.0),
        }
    }
}
