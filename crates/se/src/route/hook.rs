//! Native hook writes always use a host. A cold call gets one finite bootstrap
//! clock, joins a concurrent starter and never writes through a direct store.
#[cfg(any(target_os = "linux", windows))]
use super::execute;
use super::files::Files;
use crate::bootstrap::Bootstrap;
use se_types::{Result, SeError};
#[cfg(any(target_os = "linux", windows))]
use {
    se_host::client::{ClientOptions, lease::Deadline},
    std::{sync::Arc, time::Duration},
};

#[cfg(any(target_os = "linux", windows))]
pub fn forward(
    cx: &Bootstrap,
    files: &Files,
    input: se_host::ClaudeHookInput,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<se_core::ops::AnyOutput> {
    if cx.session.is_none() {
        return Err(SeError::new(se_types::Detail::SessionRequired(
            se_types::details::SessionRequired {
                op: "hook.claude".into(),
            },
        )));
    }
    let mut options = execute::options();
    options.timeout = Duration::from_secs(10);
    let bound = Deadline::from_options(&options)?;
    let target = super::autostart::endpoint(cx, files, &bound, diagnostic)?;
    // Authenticated discovery and frame exchange use the original clock too.
    se_proc::native_ipc::restore_image_cache(&cx.home, target.image_sha256, &bound.native_bound())
        .map_err(|error| {
            se_core::scope::unreadable("protected executable cache", &error.to_string())
                .with_cause(error)
        })?;
    crate::ipc::forward_hook(
        &target,
        execute::credential(cx, files)?,
        input,
        &ClientOptions {
            expected_generation: Some(target.generation),
            timeout: bound.remaining()?,
            cancelled: Arc::clone(&bound.native_bound().cancelled),
        },
    )
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn forward(
    _cx: &Bootstrap,
    _files: &Files,
    _input: se_host::ClaudeHookInput,
    _diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<se_core::ops::AnyOutput> {
    Err(SeError::new(se_types::Detail::FeatureUnavailable(
        se_types::details::FeatureUnavailable {
            subject: "hook host bootstrap".into(),
            reason: "native detached runtime bootstrap is not available on this platform".into(),
            next_step: "Use a supported Linux or Windows installation for managed Claude capture"
                .into(),
        },
    )))
}
