//! Retry::AfterReread and Retry::WhenRuntimeReady both become AfterRefresh:
//! callers must refresh the failed observation rather than automatically retry
//! a mutation. Their original error code and remedy remain available.
//! ApiFailure::NotIncluded, EnginePanicked and GenerationPoisoned have no
//! producer in ErrorBody/Class; inclusion and lifecycle wrappers own those arms.
use se_types as core;
use secode_stateengine_api as api;

/// Render the original typed cause with the caller's registry-backed remedy.
/// Rendering failure is returned, never replaced with a success or empty remedy.
pub fn error_body(
    value: &core::ErrorBody,
    context: &core::RenderCx<'_>,
) -> core::Result<api::ApiError> {
    let remedy = value.remedy(context)?;
    let mut text = remedy.text;
    let command = match remedy.command {
        Some(core::Cmd::Tool { name, args }) => Some(api::ApiCommand::Tool { name, args }),
        Some(core::Cmd::Manual) => Some(api::ApiCommand::Manual),
        Some(core::Cmd::Se { argv }) => {
            // The API has no executable CLI remedy. Retain each literal token
            // as JSON data for a human; never flatten argv into shell source.
            let arguments = serde_json::to_string(argv.as_slice()).map_err(|_| {
                core::SeError::invalid("linked remedy", "serializable literal arguments")
            })?;
            text.push_str("\nRun se with these literal arguments: ");
            text.push_str(&arguments);
            Some(api::ApiCommand::Manual)
        }
        None => None,
    };
    let retry = match value.retry() {
        core::Retry::Never => api::ApiRetry::Never,
        core::Retry::AfterReread | core::Retry::WhenRuntimeReady => api::ApiRetry::AfterRefresh,
        core::Retry::After(duration) => api::ApiRetry::AfterMillis(
            u64::try_from(duration.as_millis())
                .map_err(|_| core::SeError::invalid("retry duration", "u64 milliseconds"))?,
        ),
    };
    let kind = match value.class() {
        core::Class::Usage => api::ApiFailure::Usage,
        core::Class::Refused => api::ApiFailure::Refused,
        core::Class::Unauthorized => api::ApiFailure::Unauthorized,
        core::Class::Unknown => api::ApiFailure::Unknown,
        core::Class::Unreadable => api::ApiFailure::Unreadable,
        core::Class::Conflict => api::ApiFailure::Conflict,
        core::Class::Incomplete => api::ApiFailure::Incomplete,
        core::Class::Unavailable => api::ApiFailure::Unavailable,
        core::Class::Internal => api::ApiFailure::Internal,
        core::Class::Cancelled => api::ApiFailure::Cancelled,
    };
    Ok(api::ApiError {
        kind,
        code: value.code().as_str().to_owned(),
        message: value.message(),
        remedy: api::ApiRemedy { text, command },
        retry,
    })
}

/// Translate a host error without losing its original cause if remedy rendering fails.
pub fn api_error(error: &core::SeError) -> api::ApiError {
    crate::linked::error_body(&error.body, &se_types::RenderCx::default()).unwrap_or_else(
        |render| api::ApiError {
            kind: api::ApiFailure::Internal,
            code: "internal".into(),
            message: format!("{error} (rendering its remedy failed: {render})"),
            remedy: api::ApiRemedy {
                text: "Report this StateEngine host error; the original cause is in the message."
                    .into(),
                command: None,
            },
            retry: api::ApiRetry::Never,
        },
    )
}
