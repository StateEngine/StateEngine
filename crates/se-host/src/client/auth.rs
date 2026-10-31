//! Common challenge MAC. Native peer/owner provenance comes from se-proc;
//! session/launch revocation and operation admission stay in the runtime.
use crate::{EndpointRecord, ServerChallenge};
use hmac::{Hmac, Mac};
use se_types::{Result, Secret, SeError};
use sha2::Sha256;
use super::wire::{encode_json, MAX_ENDPOINT_BYTES};

#[derive(Clone, Copy)]
pub enum ProofDomain { Owner, RuntimeStop }
impl ProofDomain {
    fn bytes(self) -> &'static [u8] {
        match self {
            Self::Owner => b"se.ipc.owner/v1",
            Self::RuntimeStop => b"se.runtime.stop/v1",
        }
    }
}

fn refused(reason: &str) -> SeError {
    SeError::new(se_types::Detail::CapabilityInvalid(se_types::details::CapabilityInvalid {
        subject: "local IPC proof".into(), reason: reason.into(),
        next_step: "Reconnect to the verified local runtime with the original request key".into(),
    }))
}

pub fn fresh_nonce() -> Result<[u8; 32]> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| refused("OS randomness is unavailable"))?;
    Ok(nonce)
}

fn field(mac: &mut Hmac<Sha256>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| refused("proof field is oversized"))?;
    mac.update(&length.to_be_bytes());
    mac.update(bytes);
    Ok(())
}

fn mac_state(key: &Secret, domain: ProofDomain, challenge: &ServerChallenge,
    client_nonce: &[u8; 32], verified_peer: &[u8]) -> Result<Hmac<Sha256>> {
    if key.expose().len() < 32 || verified_peer.is_empty() || verified_peer.len() > MAX_ENDPOINT_BYTES {
        return Err(refused("missing native peer binding or invalid machine key"));
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key.expose()).map_err(|_| refused("invalid machine key"))?;
    field(&mut mac, domain.bytes())?;
    let mut version = [0; 4];
    version[..2].copy_from_slice(&challenge.version.major.to_be_bytes());
    version[2..].copy_from_slice(&challenge.version.minor.to_be_bytes());
    field(&mut mac, &version)?;
    // Explicitly sort objects: serde_json's preserve_order feature can be
    // enabled by an embedding consumer without changing this proof encoding.
    let mut epoch = serde_json::to_value(&challenge.epoch).map_err(|_| refused("invalid host epoch"))?;
    sort_objects(&mut epoch);
    field(&mut mac, &encode_json(&epoch, MAX_ENDPOINT_BYTES)?)?;
    field(&mut mac, challenge.image_sha256.as_bytes())?;
    field(&mut mac, &challenge.nonce)?;
    field(&mut mac, client_nonce)?;
    field(&mut mac, verified_peer)?;
    Ok(mac)
}

/// The binding is canonical native peer identity, never a peer ID from JSON.
/// This function creates bytes only; it grants no owner or operation authority.
pub fn create_owner_mac(key: &Secret, domain: ProofDomain, challenge: &ServerChallenge,
    client_nonce: &[u8; 32], verified_peer: &[u8]) -> Result<Secret> {
    Secret::new(mac_state(key, domain, challenge, client_nonce, verified_peer)?.finalize().into_bytes().to_vec())
}

pub fn verify_owner_mac(key: &Secret, domain: ProofDomain, challenge: &ServerChallenge,
    client_nonce: &[u8; 32], verified_peer: &[u8], supplied: &Secret) -> Result<()> {
    mac_state(key, domain, challenge, client_nonce, verified_peer)?
        .verify_slice(supplied.expose()).map_err(|_| refused("machine proof does not match this channel challenge"))
}

/// One-use challenge state retained by one accepted native channel. Taking the
/// challenge consumes it even when the subsequent proof fails.
pub struct OwnerChallenge {
    challenge: Option<ServerChallenge>,
    domain: ProofDomain,
}
impl OwnerChallenge {
    pub fn begin(endpoint: &EndpointRecord, domain: ProofDomain) -> Result<Self> {
        Ok(Self {
            challenge: Some(ServerChallenge { version: endpoint.api, epoch: endpoint.epoch.clone(),
                image_sha256: endpoint.image_sha256, nonce: fresh_nonce()? }),
            domain,
        })
    }
    pub fn challenge(&self) -> Result<&ServerChallenge> {
        self.challenge.as_ref().ok_or_else(|| refused("challenge was already consumed"))
    }
    pub fn verify(&mut self, key: &Secret, client_nonce: &[u8; 32], verified_peer: &[u8], supplied: &Secret) -> Result<()> {
        let challenge = self.challenge.take().ok_or_else(|| refused("challenge was already consumed"))?;
        verify_owner_mac(key, self.domain, &challenge, client_nonce, verified_peer, supplied)
    }
}

fn sort_objects(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let mut fields: Vec<_> = std::mem::take(map).into_iter().collect();
            fields.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (key, mut value) in fields { sort_objects(&mut value); map.insert(key, value); }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(sort_objects),
        _ => (),
    }
}
