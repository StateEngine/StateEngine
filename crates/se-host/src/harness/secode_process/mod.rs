//! External SE Code service control. Native lifecycle effects remain with the
//! launch coordinator; these readers never start a service or replay input.
//! Image and bundle qualification live beside this module in `secode_image`.
mod contract;
mod control;
mod managed;
mod registration;
mod reprovision;
mod stream;
pub use crate::harness::secode_image::Images;
pub mod probe;
pub(crate) mod sandbox;
pub use contract::{
    Acceptance, AcceptedInput, NoticeBinding, NoticeStatus, ServiceIdentity, notice_text,
};
pub use control::Control;
pub(crate) use managed::{Binding, Managed, SecodeHarness};
pub(crate) use managed::{input as initial_input, session as vendor_session};
pub(crate) use registration::{registration_fields, service_registration};
pub(crate) use reprovision::{CapabilityRepair, LiveBinding, QualifiedControl, RepairPlan};

pub(crate) fn service_key(project: &se_types::ProjectId, agent: &se_types::AgentId) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for part in [project.as_str(), agent.as_str()] {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part.as_bytes());
    }
    se_types::hex_lower(&hash.finalize())
}
pub(crate) fn private_profile(
    home: &std::path::Path,
    project: &se_types::ProjectId,
    agent: &se_types::AgentId,
) -> std::path::PathBuf {
    home.join("secode-profiles")
        .join(service_key(project, agent))
        .join("profile")
}

/// The provider's supported login variables survive both runtime detachment
/// and its second child filter. Launcher identity is never inherited.
pub fn provider_environment() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    let mut entries = crate::provider_environment();
    for name in ["OPENAI_API_KEY", "OPENAI_BASE_URL"] {
        if let Some(value) = std::env::var_os(name) {
            entries.push((name.into(), value));
        }
    }
    entries
}

fn unreadable(subject: &str, reason: impl std::fmt::Display) -> se_types::SeError {
    se_core::scope::unreadable(subject, &reason.to_string())
}

pub(crate) use crate::harness::secode_image::incompatible;
