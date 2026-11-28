//! Ready-frame encoding and verification for protected native connections.
use crate::ServerChallenge;
use crate::client::{
    auth::{refused, secret_bytes},
    endpoint::VersionWire,
    wire::{self, MAX_ENDPOINT_BYTES, MAX_FRAME_BYTES, decode_json, encode_frame},
};
use se_types::Result;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadyWire {
    version: VersionWire,
    #[serde(deserialize_with = "crate::client::endpoint::deserialize_epoch")]
    epoch: se_types::HostEpoch,
    generation: se_types::Generation,
    maximum_reply_bytes: NonZeroU32,
    #[serde(default)]
    lease: Option<ConnectionTicketWire>,
    #[serde(default)]
    package_version: Option<String>,
    #[serde(default)]
    store_id: Option<String>,
    #[serde(default)]
    capabilities: Option<Vec<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionTicketWire {
    project: se_types::ProjectId,
    agent: Option<se_types::AgentId>,
    session: Option<se_types::SessionId>,
    #[serde(deserialize_with = "secret_bytes::deserialize")]
    secret: se_types::Secret,
    lifetime_ms: u64,
}
#[derive(Serialize)]
struct ReadyRef<'a> {
    version: VersionWire,
    epoch: &'a se_types::HostEpoch,
    generation: se_types::Generation,
    maximum_reply_bytes: NonZeroU32,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease: Option<ConnectionTicketRef<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    store_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<&'a [String]>,
}
#[derive(Serialize)]
struct ConnectionTicketRef<'a> {
    project: &'a se_types::ProjectId,
    agent: &'a Option<se_types::AgentId>,
    session: &'a Option<se_types::SessionId>,
    #[serde(serialize_with = "secret_bytes::serialize")]
    secret: &'a se_types::Secret,
    lifetime_ms: u64,
}
fn validate_metadata(
    package_version: Option<&str>,
    store_id: Option<&str>,
    capabilities: Option<&[String]>,
) -> Result<()> {
    if let Some(version) = package_version
        && (version.is_empty() || version.len() > 128)
    {
        return Err(refused("invalid server package version"));
    }
    if let Some(id) = store_id
        && (id.is_empty() || id.len() > 128)
    {
        return Err(refused("invalid server store ID"));
    }
    if let Some(caps) = capabilities {
        crate::client::auth::validate_capabilities(caps)?;
    }
    Ok(())
}
pub fn encode_server_hello(hello: &crate::ServerHello) -> Result<wire::WireBytes> {
    if hello.maximum_reply_bytes.get() as usize > MAX_FRAME_BYTES {
        return Err(refused("reply cap exceeds 1 MiB"));
    }
    validate_metadata(
        hello.package_version.as_deref(),
        hello.store_id.as_deref(),
        hello.capabilities.as_deref(),
    )?;
    encode_frame(
        &ReadyRef {
            version: hello.version.into(),
            epoch: &hello.epoch,
            generation: hello.generation,
            maximum_reply_bytes: hello.maximum_reply_bytes,
            lease: hello.lease.as_ref().map(|guest| ConnectionTicketRef {
                project: &guest.project,
                agent: &guest.agent,
                session: &guest.session,
                secret: &guest.secret,
                lifetime_ms: guest.lifetime_ms,
            }),
            package_version: hello.package_version.as_deref(),
            store_id: hello.store_id.as_deref(),
            capabilities: hello.capabilities.as_deref(),
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
    match (&sent.authority, &wire.lease) {
        (crate::PresentedAuthority::GuestBootstrap(_), Some(guest))
            if guest.agent.is_none()
                && guest.session.is_none()
                && guest.secret.expose().len() == 32
                && (1..=300_000).contains(&guest.lifetime_ms) => {}
        (crate::PresentedAuthority::SessionBootstrap(_), Some(lease))
            if lease.agent.is_some()
                && lease.session.is_some()
                && lease.secret.expose().len() == 32
                && (1..=300_000).contains(&lease.lifetime_ms) => {}
        (
            crate::PresentedAuthority::GuestBootstrap(_)
            | crate::PresentedAuthority::SessionBootstrap(_),
            _,
        )
        | (_, Some(_)) => {
            return Err(refused(
                "guest ticket does not match the native bootstrap request",
            ));
        }
        (_, None) => {}
    }
    validate_metadata(
        wire.package_version.as_deref(),
        wire.store_id.as_deref(),
        wire.capabilities.as_deref(),
    )?;
    Ok(crate::ServerHello {
        version: wire.version.into(),
        epoch: wire.epoch,
        generation: wire.generation,
        maximum_reply_bytes: wire.maximum_reply_bytes,
        lease: wire.lease.map(|guest| crate::ConnectionTicket {
            project: guest.project,
            agent: guest.agent,
            session: guest.session,
            secret: std::sync::Arc::new(guest.secret),
            lifetime_ms: guest.lifetime_ms,
        }),
        package_version: wire.package_version,
        store_id: wire.store_id,
        capabilities: wire.capabilities,
    })
}
