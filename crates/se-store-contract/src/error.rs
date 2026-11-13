use crate::*;
use se_types::{EventId, IdempotencyKey, NativePath, ProjectId, Remedy, Retry, UnixMicros};
pub fn fail(code: StoreErrorCode, cause: impl Into<String>) -> Box<StoreError> {
    let remedy = match code {
        StoreErrorCode::ReferenceMissing => {
            "Correct the named identifier or reread the referenced entity before retrying."
        }
        StoreErrorCode::Corrupt => {
            "Preserve the database and its WAL/SHM; diagnose corruption and use the owner's validated backup restore."
        }
        StoreErrorCode::Unreadable => {
            "Inspect the store and protected temp-directory access, sharing and filesystem support; retry the original request after restoring access. Unreadable state is not absent; do not initialize over it."
        }
        StoreErrorCode::ApplicationMismatch
        | StoreErrorCode::TooNew
        | StoreErrorCode::VersionUnsupported => {
            "Use the compatible application version or the correct state directory; preserve this source rather than initialize over it."
        }
        StoreErrorCode::ProjectRemoved => {
            "The project was removed and its history retained; `se init --repo <root>` re-adopts the repository as a new project."
        }
        StoreErrorCode::PragmaRefused => {
            "Restore the required SQLite/filesystem setting or use a compatible build before admitting writes."
        }
        _ => "Preserve the original request key; reread the named state before retrying.",
    };
    Box::new(StoreError {
        code,
        cause: cause.into(),
        detail: StoreDetail::None,
        remedy: Remedy {
            text: remedy.into(),
            command: None,
        },
        retry: match code {
            StoreErrorCode::Busy | StoreErrorCode::Backpressure => Retry::AfterReread,
            _ => Retry::Never,
        },
    })
}
impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.cause)
    }
}
impl std::error::Error for StoreError {}

pub(crate) fn invalid(e: impl std::fmt::Display) -> Box<StoreError> {
    fail(StoreErrorCode::EventInvalid, e.to_string())
}

#[derive(Clone, Debug)]
pub struct StoreError {
    pub code: StoreErrorCode,
    pub cause: String,
    pub detail: StoreDetail,
    pub remedy: se_types::Remedy,
    pub retry: se_types::Retry,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreIoStage {
    Open,
    PragmaReadback,
    BeginSnapshot,
    HeaderReadback,
    ReadSnapshot,
    Commit,
    Stage,
}
#[derive(Clone, Debug, PartialEq)]
pub enum StoreDetail {
    None,
    /// Time spent acquiring native file custody before its bounded refusal.
    NativeContention {
        waited_ms: u64,
    },
    /// The connection's configured busy timeout, fully consumed by SQLite's busy
    /// handler before a bounded BUSY-family refusal (extended 5 and 261).
    /// LOCKED refusals ran no retry loop and keep their existing detail.
    BusyWait {
        waited_ms: u64,
        extended_code: i32,
    },
    PrincipalNameConflict {
        project: ProjectId,
        name: String,
        existing: Actor,
    },
    Sqlite {
        extended_code: i32,
        native_os_code: Option<i32>,
    },
    Io {
        /// Path relative to the state directory; never an absolute home or request path.
        path: String,
        /// Exact SQLite filename for trusted diagnostics, including native path prefixes.
        opened_path: String,
        stage: StoreIoStage,
        sqlite_extended_code: Option<i32>,
        /// Captured from the failing native call, never ambient last-error state.
        native_os_code: Option<i32>,
    },
    Conflict {
        expected: Expected,
        observed: Option<Revision>,
    },
    Version {
        application_id: u32,
        found: u32,
        minimum: u32,
        maximum: u32,
    },
    Request {
        scope: Scope,
        actor: Actor,
        key: IdempotencyKey,
        /// Present for a conflicting retained caller key; never a minted ID.
        original_event: Option<EventId>,
    },
    Entity {
        family: HistoryFamily,
        event: Option<EventId>,
        record: Option<RecordId>,
    },
    Source {
        path: NativePath,
        offset: Option<u64>,
        length: Option<u64>,
        sqlite_extended_code: Option<i32>,
    },
    Budget {
        allowed: u64,
        required: Option<u64>,
    },
    Space {
        required: Option<u64>,
        available: Option<u64>,
    },
    Maintenance {
        state: StoreState,
        operation: Option<RecordId>,
    },
    /// The removed project and when its tombstone was recorded.
    ProjectRemoved {
        project: ProjectId,
        at: UnixMicros,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreErrorCode {
    Absent,
    AlreadyExists,
    Unreadable,
    Corrupt,
    ApplicationMismatch,
    TooNew,
    VersionUnsupported,
    MigrationRequired,
    NotReady,
    GenerationChanged,
    LocationUnsafe,
    PragmaRefused,
    Busy,
    Backpressure,
    WriterClosed,
    CommitOutcomeUnknown,
    DiskFull,
    IdempotencyKeyReused,
    EventIdConflict,
    NaturalKeyConflict,
    RevisionConflict,
    InvalidTransition,
    ReferenceMissing,
    ScopeMismatch,
    CreatorControlRefused,
    /// The project was tombstoned; its history stays readable, writes refuse.
    ProjectRemoved,
    EventInvalid,
    BodyTooLarge,
    ProjectionInconsistent,
    CursorInvalid,
    CursorStale,
    ReadBudgetTooSmall,
    ReadIncomplete,
    SourceChanged,
    MigrationFailed,
    BackupFailed,
    RecoveryIncomplete,
    ContentErased,
    ErasureIncomplete,
    ErasureExternalCopies,
    ErasurePhysicalGuaranteeUnavailable,
}
pub type StoreResult<T> = std::result::Result<T, Box<StoreError>>;
