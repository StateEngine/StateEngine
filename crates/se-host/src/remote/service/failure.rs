//! Internal native phase keys are not a remote caller's retry identity.
use se_types::{Detail, ErrorBody, IdempotencyKey, SeError};
pub(super) fn original_key(error: SeError, operation: &str, key: &IdempotencyKey) -> SeError {
    let detail = match error.body.detail() {
        Detail::CommitOutcomeUnknown(value) => {
            let mut value = value.clone();
            value.operation = operation.into();
            value.key = Some(key.to_string());
            Detail::CommitOutcomeUnknown(value)
        }
        Detail::CommittedResponseUnavailable(value) => {
            let mut value = value.clone();
            value.operation = operation.into();
            value.key = Some(key.to_string());
            Detail::CommittedResponseUnavailable(value)
        }
        _ => return error,
    };
    let body = ErrorBody::new(detail).with_retry(error.body.retry().clone());
    SeError::from(body).with_cause(error)
}
