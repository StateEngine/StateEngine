//! Stable native descriptor encoding, separate from the durable store v1 codec.
use secode_stateengine_api as api;
use sha2::{Digest, Sha256};

/// SHA-256 of compact UTF-8 JSON for this exact ordered tuple. Ordered message
/// IDs and the original cursor are significant. Native epoch and both transient
/// generations are excluded; the adapter checks epoch independently. Neither
/// this digest nor any constructor proves a reservation, admission or delivery.
/// SE Code's API-only queue can encode the same tuple without linking se-host.
pub fn native_notice_digest(notice: &api::MailNotice) -> se_types::Result<api::Sha256> {
    let target = &notice.target;
    let bytes = serde_json::to_vec(&(
        "stateengine.native-mail/v1",
        &notice.id.0,
        &target.session.0,
        &target.binding.project.0,
        &target.binding.agent.0,
        &target.binding.session.0,
        se_types::hex_lower(&target.binding_fingerprint.0),
        notice
            .messages
            .iter()
            .map(|message| &message.0)
            .collect::<Vec<_>>(),
        &notice.through.0,
    ))
    .map_err(|error| se_core::scope::unreadable("native notice encoding", &error.to_string()))?;
    Ok(api::Sha256(Sha256::digest(bytes).into()))
}
