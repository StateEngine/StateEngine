//! One store-domain to public-catalogue mapping; the original cause is never dropped.
use se_store::{StoreError, StoreErrorCode as C};
use se_types::{Detail, SeError, details};
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub fn store_error(error: &StoreError) -> SeError {
    if let se_store::StoreDetail::PrincipalNameConflict {
        project,
        name,
        existing,
    } = &error.detail
    {
        let se_store::Actor::Agent(agent) = existing else {
            return SeError::new(Detail::StateConflict(details::StateConflict {
                subject: format!("principal name {name}"),
                reason: "this name belongs to an existing human in the selected project".into(),
                next_step: "Choose another name for the new agent.".into(),
            }))
            .with_cause(error.clone());
        };
        let command = match se_types::Argv::from_op(&ExistingAgent { project, agent }) {
            Ok(argv) => se_types::Cmd::Se { argv },
            Err(cause) => return cause.with_cause(error.clone()),
        };
        return SeError::from(
            se_types::ErrorBody::new(Detail::AgentNameConflict(details::AgentNameConflict {
                name: name.clone(),
                agent: agent.clone(),
                project: project.clone(),
            }))
            .with_remedy(se_types::Remedy {
                text: "Choose another name for the new agent, or use the existing agent.".into(),
                command: Some(command),
            }),
        )
        .with_cause(error.clone());
    }
    let subject = format!("store {:?}", error.code);
    let reason = error.cause.clone();
    let next_step = error.remedy.text.clone();
    let mut mapped = SeError::new(match error.code {
        C::Absent | C::ReferenceMissing => Detail::TargetUnknown(details::TargetUnknown {
            subject,
            reason,
            next_step,
        }),
        C::Corrupt => Detail::StoreCorrupt(details::StoreCorrupt {
            path: match &error.detail {
                se_store::StoreDetail::Io { path, .. } => path.clone(),
                _ => subject,
            },
            check: reason,
        }),
        C::Busy | C::Backpressure => Detail::StoreBusy(details::StoreBusy {
            waited_ms: match error.detail {
                se_store::StoreDetail::NativeContention { waited_ms }
                | se_store::StoreDetail::BusyWait { waited_ms, .. } => waited_ms,
                _ => 0,
            },
            replay: None,
            reason,
            next_step,
        }),
        C::WriterClosed | C::NotReady | C::GenerationChanged => {
            Detail::RuntimeNotRunning(details::RuntimeNotRunning {
                op: subject,
                reason,
            })
        }
        C::CursorInvalid | C::CursorStale => Detail::CursorInvalid(details::CursorInvalid {
            reason,
            next_step: "Remove or replace the invalid cursor used by this read.".into(),
        }),
        C::LocationUnsafe => Detail::StateConflict(details::StateConflict {
            subject,
            reason,
            next_step,
        }),
        C::DiskFull => Detail::StoreDiskFull(details::StoreDiskFull {
            path: match &error.detail {
                se_store::StoreDetail::Io { opened_path, .. } => opened_path.clone(),
                _ => reason,
            },
            free_bytes: None,
        }),
        C::TooNew | C::VersionUnsupported => match &error.detail {
            se_store::StoreDetail::Version { found, maximum, .. } => {
                Detail::StoreTooNew(details::StoreTooNew {
                    store_version: u64::from(*found),
                    supported: u64::from(*maximum),
                })
            }
            _ => Detail::StateConflict(details::StateConflict {
                subject,
                reason,
                next_step,
            }),
        },
        C::MigrationRequired => match &error.detail {
            se_store::StoreDetail::Version { found, minimum, .. } => {
                Detail::StoreMigrationRequired(details::StoreMigrationRequired {
                    from: u64::from(*found),
                    to: u64::from(*minimum),
                })
            }
            _ => Detail::StateConflict(details::StateConflict {
                subject,
                reason,
                next_step,
            }),
        },
        C::RevisionConflict => match &error.detail {
            se_store::StoreDetail::Conflict { expected, observed } => {
                Detail::RevisionConflict(details::RevisionConflict {
                    entity: subject,
                    expected: format!("{expected:?}"),
                    current: observed
                        .map(|r| r.value.to_string())
                        .unwrap_or_else(|| "absent".into()),
                })
            }
            _ => Detail::StateConflict(details::StateConflict {
                subject,
                reason,
                next_step,
            }),
        },
        C::ProjectRemoved => match &error.detail {
            se_store::StoreDetail::ProjectRemoved { project, at } => {
                Detail::ProjectRemoved(details::ProjectRemoved {
                    project: project.clone(),
                    at: *at,
                })
            }
            _ => Detail::StateConflict(details::StateConflict {
                subject,
                reason,
                next_step,
            }),
        },
        C::ScopeMismatch | C::CreatorControlRefused => {
            Detail::CapabilityInvalid(details::CapabilityInvalid {
                subject,
                reason,
                next_step,
            })
        }
        C::EventInvalid | C::BodyTooLarge => {
            Detail::UsageInvalidValue(details::UsageInvalidValue {
                argument: subject,
                got: reason,
                expected: next_step,
            })
        }
        C::CommitOutcomeUnknown => Detail::CommitOutcomeUnknown(details::CommitOutcomeUnknown {
            operation: subject,
            key: match &error.detail {
                se_store::StoreDetail::Request { key, .. } => Some(key.to_string()),
                _ => None,
            },
            natural_events: vec![],
        }),
        C::IdempotencyKeyReused => match &error.detail {
            se_store::StoreDetail::Request {
                key,
                original_event: Some(original_event),
                ..
            } => Detail::IdempotencyKeyReused(details::IdempotencyKeyReused {
                key: key.to_string(),
                original_event: original_event.clone(),
            }),
            _ => Detail::SourceUnreadable(details::SourceUnreadable {
                subject,
                reason: format!("{reason}; retained key conflict has no original event"),
                next_step,
            }),
        },
        C::AlreadyExists | C::EventIdConflict | C::NaturalKeyConflict | C::InvalidTransition => {
            Detail::StateConflict(details::StateConflict {
                subject,
                reason,
                next_step,
            })
        }
        C::Unreadable
        | C::ApplicationMismatch
        | C::PragmaRefused
        | C::ProjectionInconsistent
        | C::ReadBudgetTooSmall
        | C::ReadIncomplete
        | C::SourceChanged
        | C::MigrationFailed
        | C::BackupFailed
        | C::RecoveryIncomplete
        | C::ContentErased
        | C::ErasureIncomplete
        | C::ErasureExternalCopies
        | C::ErasurePhysicalGuaranteeUnavailable => {
            Detail::SourceUnreadable(details::SourceUnreadable {
                subject,
                reason,
                next_step,
            })
        }
    })
    .with_cause(error.clone());
    if matches!(
        error.detail,
        se_store::StoreDetail::NativeContention { .. } | se_store::StoreDetail::BusyWait { .. }
    ) {
        mapped.body = mapped.body.with_retry(error.retry.clone());
    }
    mapped
}

/// The adapter retains these submitted identities around append/await; lost ACK
/// never mints a key or claims a definite rollback.
pub fn write_error(
    error: &StoreError,
    operation: &str,
    key: Option<&se_types::IdempotencyKey>,
    natural_events: &[se_types::EventId],
) -> SeError {
    if error.code == C::CommitOutcomeUnknown {
        return SeError::new(Detail::CommitOutcomeUnknown(
            details::CommitOutcomeUnknown {
                operation: operation.into(),
                key: key.map(ToString::to_string),
                natural_events: natural_events.to_vec(),
            },
        ))
        .with_cause(error.clone());
    }
    retain_write_identity(store_error(error), operation, key, natural_events)
}

/// A refused write retains the caller's original replay identity. Reads and
/// pre-authentication capacity errors have no admitted write identity to attach.
pub fn retain_write_identity(
    mut error: SeError,
    operation: &str,
    key: Option<&se_types::IdempotencyKey>,
    natural_events: &[se_types::EventId],
) -> SeError {
    if let Detail::StoreBusy(detail) = error.body.detail() {
        let mut detail = detail.clone();
        detail.replay = Some(Box::new(se_types::WriteRetryIdentity {
            operation: operation.into(),
            key: key.map(ToString::to_string),
            natural_events: natural_events.to_vec(),
        }));
        let replay = match key {
            Some(key) => format!(
                "Original operation {operation}; repeat the same command with --key {key} (CLI) or idempotency_key {key} (MCP)."
            ),
            None => format!(
                "Repeat the same natural operation {operation}, retaining original event IDs: {}.",
                natural_events
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        };
        detail.next_step = format!("{} {replay}", detail.next_step);
        error.body = se_types::ErrorBody::new(Detail::StoreBusy(detail))
            .with_retry(se_types::Retry::AfterReread);
    }
    error
}

struct ExistingAgent<'a> {
    project: &'a se_types::ProjectId,
    agent: &'a se_types::AgentId,
}
impl se_types::OperationCommand for ExistingAgent<'_> {
    fn cli_argv(&self) -> Vec<String> {
        crate::ops::AgentCommand::launch(self.agent, None, Some(self.project), false).argv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use se_store::{StoreDetail, StoreErrorCode};
    use se_types::{Remedy, Retry};

    fn busy(detail: StoreDetail) -> Box<StoreError> {
        Box::new(StoreError {
            code: StoreErrorCode::Busy,
            cause: "database is locked".into(),
            detail,
            remedy: Remedy {
                text: "retry the original operation".into(),
                command: None,
            },
            retry: Retry::AfterReread,
        })
    }
    fn waited_ms(error: &StoreError) -> u64 {
        let mapped = store_error(error);
        let Detail::StoreBusy(detail) = mapped.body.detail() else {
            panic!("expected StoreBusy, got {:?}", mapped.body.detail())
        };
        detail.waited_ms
    }
    #[test]
    fn a_consumed_busy_wait_reports_the_configured_bound() {
        let error = busy(StoreDetail::BusyWait {
            waited_ms: 250,
            extended_code: 5,
        });
        assert_eq!(waited_ms(&error), 250);
    }
    #[test]
    fn an_unmeasured_busy_refusal_stays_zero() {
        let error = busy(StoreDetail::None);
        assert_eq!(waited_ms(&error), 0);
    }
    #[test]
    fn native_contention_keeps_its_measured_wait() {
        let error = busy(StoreDetail::NativeContention { waited_ms: 7 });
        assert_eq!(waited_ms(&error), 7);
    }
}
