//! Both launch modes recognize an existing host through the same native route
//! and authenticated endpoint; an endpoint file alone is never a live claim.
use super::*;

pub(super) fn route(cx: &Bootstrap) -> Result<se_host::EndpointRoute> {
    #[cfg(unix)]
    let expected = se_host::IpcEndpoint::UnixSocket(se_types::NativePath::from_local(
        crate::config::unix_socket_paths()?
            .expected_path(&cx.home)
            .map_err(|error| {
                scope::unreadable("expected runtime socket address", &error.to_string())
                    .with_cause(error)
            })?,
    )?);
    #[cfg(unix)]
    let expected = Some(&expected);
    #[cfg(windows)]
    let expected = None;
    se_host::route_endpoint(&cx.home, expected)
}

pub(super) fn authenticate(
    cx: &Bootstrap,
    files: &Files,
    endpoint: &se_host::EndpointRecord,
    options: &se_host::client::ClientOptions,
    bound: &Deadline,
) -> Result<ProcessView> {
    BlockingIpcClient::connect_authenticated(
        endpoint,
        execute::credential(cx, files)?,
        NonZeroU32::new(se_host::client::wire::DEFAULT_REPLY_BYTES)
            .ok_or_else(|| SeError::invalid("runtime reply budget", "positive"))?,
        options,
    )
    .map_err(|error| {
        // Keep the endpoint failure as a typed cause for the released-lease retry.
        if error.code() == se_types::Code::IpcUnavailable {
            SeError::new(se_types::Detail::StateConflict(
                se_types::details::StateConflict {
                    subject: cx.home.join("runtime.lock").display().to_string(),
                    reason: format!("the published runtime endpoint could not be authenticated: {error}"),
                    next_step: "Run se up again for this same data home; a released lease starts the replacement host and re-adopts the preserved provider. If it refuses again, run se down for this same home before retrying; the endpoint and saved conversations are preserved.".into(),
                },
            ))
            .with_cause(error)
        } else {
            error
        }
    })?;
    process::observe(endpoint, bound)
}

/// Credential and process-observation errors cannot authorize a retry.
pub(super) fn endpoint_unreachable(error: &SeError) -> bool {
    error
        .cause
        .as_ref()
        .and_then(|cause| cause.downcast_ref::<SeError>())
        .is_some_and(|cause| cause.code() == se_types::Code::IpcUnavailable)
}
pub(super) fn after_recovery(
    cx: &Bootstrap,
    recovery: Option<&EndpointRecovery>,
    error: SeError,
) -> SeError {
    let Some(retained) = recovery else {
        return error;
    };
    let retained_path = match retained.retained.to_local() {
        Ok(path) => path.display().to_string(),
        Err(path_error) => format!(
            "{:?} (path decoding failed: {path_error})",
            retained.retained
        ),
    };
    SeError::new(se_types::Detail::StateConflict(se_types::details::StateConflict {
        subject: cx.home.display().to_string(),
        reason: format!("Retained stale endpoint {} as {retained_path}, but the runtime startup response could not be completed: {error}", cx.home.join("endpoint.json").display()),
        next_step: "Keep the retained endpoint record and run se status for this same home before retrying se up; use se down first if another host is running.".into(),
    })).with_cause(error)
}
