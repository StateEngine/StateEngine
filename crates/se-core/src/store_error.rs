//! One store-domain to public-catalogue mapping; the original cause is never dropped.
use se_store::{StoreError, StoreErrorCode as C};
use se_types::{Detail, SeError, details};
pub fn store_error(error: &StoreError) -> SeError {
    let subject = format!("store {:?}", error.code);
    let reason = error.cause.clone();
    let next_step = error.remedy.text.clone();
    SeError::new(match error.code {
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
            waited_ms: 0,
            reason,
            next_step,
        }),
        C::WriterClosed | C::NotReady | C::GenerationChanged => {
            Detail::RuntimeNotRunning(details::RuntimeNotRunning {
                op: subject,
                reason,
            })
        }
        C::CursorInvalid | C::CursorStale => {
            Detail::CursorInvalid(details::CursorInvalid { reason })
        }
        C::LocationUnsafe => Detail::StateConflict(details::StateConflict {
            subject,
            reason,
            next_step,
        }),
        C::DiskFull => Detail::StoreDiskFull(details::StoreDiskFull {
            path: reason,
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
    .with_cause(error.clone())
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
    store_error(error)
}
