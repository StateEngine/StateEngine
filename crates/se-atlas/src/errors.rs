pub use se_types::SeError as AtlasError;
use std::time::Duration;

pub type AtlasResult<T> = Result<T, AtlasError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtlasErrorCode {
    FeatureDisabled,
    ConfigurationInvalid,
    RootUnavailable,
    RootIdentityChanged,
    CacheIo,
    CacheCorrupt,
    CacheTooNew,
    CacheScopeMismatch,
    CacheBusy,
    CacheLinkRefused,
    InvalidPath,
    UnsupportedPathEncoding,
    InvalidQuery,
    InvalidLimit,
    AmbiguousSymbol,
    InvalidCursor,
    CursorEpochMismatch,
    CursorExpired,
    CursorQueryMismatch,
    CursorSnapshotChanged,
    BaselineUnavailable,
    WatchUnavailable,
    ResourceBudgetUnavailable,
    SourceReadFailed,
    SourceChangedDuringRead,
    ParserFailed,
    ShuttingDown,
    Cancelled,
    InternalInvariant,
    EmbeddedUnavailable,
    WorkerLost,
    WorkerProtocol,
    WorkerLeaseStale,
    WorkerDeadline,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AtlasErrorDetail {
    pub path: Option<String>,
    pub observed: Option<String>,
    pub expected: Option<String>,
    pub retry_after: Option<Duration>,
}

/// One wire error remains se-types::SeError. The final central Code allocation
/// maps every AtlasErrorCode exhaustively; no catch-all or separate envelope.
pub trait AtlasErrors {
    fn error(&self, code: AtlasErrorCode, detail: AtlasErrorDetail) -> AtlasError;
}
