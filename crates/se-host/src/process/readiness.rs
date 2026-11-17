//! Preserve launch failures through readiness and retained-cleanup responses.
use se_types::{AgentId, Detail, ErrorBody, Retry, SeError, details};

pub(super) fn refused(agent: &AgentId, subject: &str, reason: impl Into<String>) -> SeError {
    ErrorBody::new(Detail::LaunchFailed(details::LaunchFailed {
        subject: subject.into(),
        reason: reason.into(),
        next_step: format!(
            "Use the same home and project with `se agent show {agent}`. Reread the original launch request key to inspect its retained outcome; resolve any pending stop before starting another launch."
        ),
    }))
    .with_retry(Retry::AfterReread)
    .into()
}
