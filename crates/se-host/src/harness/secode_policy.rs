//! Read the original launch proof from the protected, digest-pinned session policy.
use se_types::Result;
use serde_json::Value;
use sha2::Digest;
use std::io::Read;

fn unreadable(subject: &str, cause: impl std::fmt::Display) -> se_types::SeError {
    se_core::scope::unreadable(subject, &cause.to_string())
}

pub(crate) fn saved_session_capability(
    profile: &std::path::Path,
    expected: se_types::Sha256,
) -> Result<se_types::Secret> {
    let files = se_proc::NativeProfileFiles::open(profile)
        .map_err(|cause| unreadable("SE Code capability policy", cause))?;
    let mut file = files
        .readback(&profile.join("host-policy.json"))
        .map_err(|cause| unreadable("SE Code capability policy", cause))?
        .ok_or_else(|| unreadable("SE Code capability policy", "original policy is absent"))?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    std::io::Read::by_ref(&mut file)
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|cause| unreadable("SE Code capability policy", cause))?;
    if bytes.len() > 1_048_576
        || <[u8; 32]>::from(sha2::Sha256::digest(bytes.as_slice())) != *expected.as_bytes()
    {
        return Err(unreadable(
            "SE Code capability policy",
            "original policy digest differs or exceeds its bound",
        ));
    }
    let mut policy: Value = serde_json::from_slice(&bytes)
        .map_err(|cause| unreadable("SE Code capability policy", cause))?;
    let proof = policy
        .pointer_mut("/mcp/stateengine/headers/X-StateEngine-Session-Proof")
        .map(Value::take)
        .ok_or_else(|| unreadable("SE Code capability policy", "session proof is absent"))?;
    let Value::String(proof) = proof else {
        return Err(unreadable(
            "SE Code capability policy",
            "session proof is not a string",
        ));
    };
    let proof = zeroize::Zeroizing::new(proof);
    se_types::Secret::new(proof.as_bytes().to_vec())
}
