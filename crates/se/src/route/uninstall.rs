//! One native claim owner supplies achieved effects to the core receipt policy.
use se_core::ops::{Uninstall, UninstallOutput, inputs::Validate, installation::finish_uninstall};
use se_types::Result;

#[path = "uninstall/home.rs"]
mod home;

pub fn execute(
    context: &crate::bootstrap::Bootstrap,
    input: Uninstall,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<UninstallOutput> {
    input.validate()?;
    if let Some(mut result) = home::execute(context, &input, diagnostic)? {
        result
            .integrations
            .extend(super::adoption::uninstall(context)?);
        return Ok(result);
    }
    let (plan, mut effects) =
        crate::runtime::uninstall(context, &input.idempotency_key, diagnostic)?;
    effects
        .integrations
        .extend(super::adoption::uninstall(context)?);
    finish_uninstall(&plan, input.idempotency_key, effects)
}
