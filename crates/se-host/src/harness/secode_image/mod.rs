//! Qualify the provider's native images and release bundle before launch, and
//! carry the compatible-bundle refusal those decisions share. Process control
//! and provider planning read these pins; neither re-derives a digest.
pub mod bundle;
mod images;
pub use images::Images;

fn unreadable(subject: &str, reason: impl std::fmt::Display) -> se_types::SeError {
    se_core::scope::unreadable(subject, &reason.to_string())
}

pub(crate) fn incompatible(reason: impl Into<String>) -> se_types::SeError {
    se_types::SeError::new(se_types::Detail::ProviderIncompatible(
        se_types::details::ProviderIncompatible {
            subject: "SE Code external-host contract".into(),
            reason: reason.into(),
            next_step: "Install a compatible native SE Code bundle and set providers.secode.command to its secode executable; retain the original service and input identities while a previous operation is uncertain.".into(),
        },
    ))
}
