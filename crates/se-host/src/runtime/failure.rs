//! Request identities survive dropped waiters and known-commit response failures.
use super::CommittedWrite;
use se_core::store_error::write_error;
use se_types::{Result, SeError};
use std::sync::{Arc, Mutex};
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WriteIdentity {
    pub(crate) operation: &'static str,
    pub(crate) natural_key: Option<String>,
    pub(crate) key: Option<se_types::IdempotencyKey>,
    pub(crate) natural_events: Vec<se_types::EventId>,
}
impl WriteIdentity {
    fn same_request(&self, other: &Self) -> bool {
        self.operation == other.operation
            && match (&self.natural_key, &other.natural_key) {
                (Some(left), Some(right)) => left == right,
                (None, None) => {
                    self.key == other.key && self.natural_events == other.natural_events
                }
                _ => false,
            }
    }
    pub(crate) fn store_error(&self, error: &se_store::StoreError) -> SeError {
        write_error(
            error,
            self.operation,
            self.key.as_ref(),
            &self.natural_events,
        )
    }
    pub(crate) fn wait_error(&self, cause: SeError) -> SeError {
        SeError::from(
            se_types::ErrorBody::new(se_types::Detail::CommitOutcomeUnknown(
                se_types::details::CommitOutcomeUnknown {
                    operation: self.operation.into(),
                    key: self.key.as_ref().map(ToString::to_string),
                    natural_events: self.natural_events.clone(),
                },
            ))
            .with_retry(se_types::Retry::AfterReread),
        )
        .with_cause(cause)
    }
}

impl CommittedWrite {
    pub(crate) fn response_error(&self, cause: SeError) -> SeError {
        SeError::from(
            se_types::ErrorBody::new(se_types::Detail::CommittedResponseUnavailable(
                se_types::details::CommittedResponseUnavailable {
                    operation: self.operation.clone().into_boxed_str(),
                    key: self.key.as_ref().map(ToString::to_string),
                    natural_events: self.natural_events.clone().into_boxed_slice(),
                    committed_events: self.committed_events.clone().into_boxed_slice(),
                    reason: cause.to_string().into_boxed_str(),
                },
            ))
            .with_retry(se_types::Retry::AfterReread),
        )
        .with_cause(cause)
    }
}
/// Bounded by the configured writer admission capacity. An abandoned waiter
/// leaves its original identity until the independent completion observer or a
/// successful drain resolves it. Uncertain store results retain their identity.
#[derive(Clone)]
pub(crate) struct PendingWrites {
    maximum: usize,
    values: Arc<Mutex<Vec<(WriteIdentity, u32)>>>,
}
impl PendingWrites {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            maximum,
            values: Arc::new(Mutex::new(Vec::new())),
        }
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<(WriteIdentity, u32)>>> {
        self.values.lock().map_err(|_| {
            se_core::scope::unreadable(
                "pending write identities",
                "identity registry poisoned; retain the lease",
            )
        })
    }
    pub(crate) fn register(&self, identity: &WriteIdentity) -> Result<()> {
        let mut values = self.lock()?;
        if let Some((_, attempts)) = values
            .iter_mut()
            .find(|(value, _)| value.same_request(identity))
        {
            *attempts = attempts.checked_add(1).ok_or_else(|| {
                se_core::scope::unreadable(
                    "pending write identities",
                    "unresolved retry accounting exhausted; retain original identities",
                )
            })?;
        } else {
            if values.len() >= self.maximum {
                let error = SeError::new(se_types::Detail::StoreBusy(
                    se_types::details::StoreBusy {
                        waited_ms: 0,
                        operation: None,
                        key: None,
                        natural_events: None,
                        reason: "Bounded unresolved write capacity is occupied.".into(),
                        next_step: "Wait for accepted writes to complete, then reread or retry the original operation key; unresolved store outcomes require reconciliation before new submissions.".into(),
                    },
                ));
                return Err(se_core::store_error::retain_write_identity(
                    error,
                    identity.operation,
                    identity.key.as_ref(),
                    &identity.natural_events,
                ));
            }
            values.push((identity.clone(), 1));
        }
        Ok(())
    }
    pub(crate) fn resolve(&self, identity: &WriteIdentity) -> Result<()> {
        self.lock()?
            .retain(|(value, _)| !value.same_request(identity));
        Ok(())
    }
    pub(crate) fn failed_attempt(&self, identity: &WriteIdentity) -> Result<()> {
        let mut values = self.lock()?;
        if let Some((_, attempts)) = values
            .iter_mut()
            .find(|(value, _)| value.same_request(identity))
        {
            *attempts -= 1;
        }
        values.retain(|(_, attempts)| *attempts != 0);
        Ok(())
    }
    pub(crate) fn describe(&self) -> Result<Vec<String>> {
        Ok(self
            .lock()?
            .iter()
            .map(|(value, attempts)| {
                format!(
                    "Unresolved {} ({attempts} unacknowledged attempt(s)): original key {:?}, natural key {:?}, natural events {:?}",
                    value.operation,
                    value.key.as_ref().map(ToString::to_string),
                    value.natural_key,
                    value.natural_events
                )
            })
            .collect())
    }
    pub(crate) fn clear(&self) -> Result<()> {
        self.lock()?.clear();
        Ok(())
    }
}
