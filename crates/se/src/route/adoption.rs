//! Command dispatch into the shared provider adoption installer.
use crate::{bootstrap::Bootstrap, config::Origin};
use se_core::ops::*;
pub(crate) use se_host::adoption::install::Plan;
use se_types::{Result, SeError};
use std::path::Path;
pub(crate) fn prepare(cx: &Bootstrap, input: &ProjectInit) -> Result<Plan> {
    se_host::adoption::install::prepare(
        &cx.home,
        &cx.config.value,
        match &cx.config.origin {
            Origin::File(path) => Some(path.as_path()),
            _ => None,
        },
        input.provider,
    )
}
pub(crate) fn install(
    cx: &Bootstrap,
    root: &Path,
    plan: Plan,
    output: &mut AnyOutput,
) -> Result<()> {
    let AnyOutput::ProjectInit(output) = output else {
        return Err(SeError::invalid(
            "adoption setup",
            "the committed project setup result",
        ));
    };
    let result =
        se_host::adoption::install::install(&cx.home, root, plan, &output.value.project.id)?;
    output.value.integrations.push(result.integration);
    output.value.next = result.next;
    output.value.changed.extend(result.changed);
    Ok(())
}
pub(crate) fn uninstall(cx: &Bootstrap) -> Result<Vec<IntegrationEffect>> {
    se_host::adoption::install::uninstall(&cx.home)
}
