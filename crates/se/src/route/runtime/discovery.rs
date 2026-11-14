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
        // The refusal this refusal shapes is the only one later recovery may act
        // on. A credential or observation failure in the same call is not an
        // answer from the published endpoint, so it keeps its own code and its
        // own non-retryable phase.
        if error.code() == se_types::Code::IpcUnavailable {
            SeError::new(se_types::Detail::StateConflict(
                se_types::details::StateConflict {
                    subject: cx.home.join("runtime.lock").display().to_string(),
                    reason: format!("the published runtime endpoint could not be authenticated: {error}"),
                    // A published endpoint can outlive the host that wrote it: a
                    // runtime killed between publication and the next request
                    // leaves this record behind while its lease is free again.
                    // Reading that as a live host and sending the user to `se
                    // down` stops the provider the crash preserved. Retrying is
                    // what starts the replacement host, and the lease decides:
                    // a freed lease starts and re-adopts, a held lease refuses
                    // again, so this names the step that works without assuming.
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

/// Whether this refusal was produced because the published endpoint could not be
/// reached.
///
/// `authenticate` returns this refusal for an endpoint that answered nothing, but
/// the same call also reads the credential and observes the process, and neither
/// of those is an answer from the endpoint. The refusal keeps the unreachable
/// error as its cause, so the cause is what recovery may act on: the rendered code
/// is `state-conflict` for the intended refusal and unchanged for the others.
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
