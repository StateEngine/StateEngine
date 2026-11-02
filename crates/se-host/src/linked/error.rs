use se_types as core;
use secode_stateengine_api as api;

/// Render the original typed cause with the caller's registry-backed remedy.
/// Rendering failure is returned, never replaced with a success or empty remedy.
pub fn error_body(
    value: &core::ErrorBody,
    context: &core::RenderCx<'_>,
) -> core::Result<api::ApiError> {
    let remedy = value.remedy(context)?;
    let command = match remedy.command {
        Some(core::Cmd::Tool { name, args }) => Some(api::ApiCommand::Tool { name, args }),
        Some(core::Cmd::Manual) => Some(api::ApiCommand::Manual),
        // CLI argv is already rendered into the remedy text. Linked consumers
        // cannot execute a CLI command as if it were an authorized model tool.
        Some(core::Cmd::Se { .. }) | None => None,
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
        remedy: api::ApiRemedy {
            text: remedy.text,
            command,
        },
        retry,
    })
}
