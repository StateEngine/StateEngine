//! One native claim owner supplies achieved effects to the core receipt policy.
use se_core::ops::{Uninstall, UninstallOutput, inputs::Validate, installation::finish_uninstall};
use se_types::Result;

pub fn execute(
    context: &crate::bootstrap::Bootstrap,
    input: Uninstall,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<UninstallOutput> {
    input.validate()?;
    let (plan, effects) = crate::runtime::uninstall(context, diagnostic)?;
    finish_uninstall(&plan, input.idempotency_key, effects)
}
