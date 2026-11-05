//! Installer and uninstaller native lock contention is retryable, not unreadable.
use se_types::{Detail, Retry, SeError, details};

pub(crate) fn map(
    error: se_proc::StateFileError,
    fallback: impl FnOnce(&se_proc::StateFileError) -> SeError,
) -> SeError {
    let mapped = if error.is_contended() {
        let mut value = SeError::new(Detail::StateConflict(details::StateConflict {
            subject: format!("installation lock {}", error.path.display()),
            reason: "Native installation custody is contended by another operation".into(),
            next_step: "Wait for that operation to finish, then retry the same command; keep the lock file in place".into(),
        }));
        value.body = value.body.with_retry(Retry::AfterReread);
        value
    } else {
        fallback(&error)
    };
    mapped.with_cause(error)
}
