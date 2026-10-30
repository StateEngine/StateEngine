pub use se_types::{Detail as AtlasErrorDetail, ErrorBody as AtlasFailure, SeError as AtlasError};

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
    IndexAbsent,
    PathUnknown,
    SymbolUnknown,
    AmbiguousSymbol,
    LanguageUnsupported,
    FileOverBudget,
    InvalidCursor,
    CursorEpochMismatch,
    CursorExpired,
    CursorQueryMismatch,
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

/// One wire error remains se-types::SeError. The final central Code allocation
/// maps every AtlasErrorCode exhaustively to typed shared Detail. A mismatched
/// cause/detail is an invariant failure, never a generic string-payload escape.
pub trait AtlasErrors {
    fn error(&self, code: AtlasErrorCode, detail: AtlasErrorDetail) -> AtlasError;
}
