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

pub(crate) fn cache_error(reason: impl std::fmt::Display) -> AtlasError {
    se_types::SeError::new(se_types::Detail::AtlasUnreadable(
        se_types::details::AtlasUnreadable {
            path: "atlas.db".into(),
            reason: reason.to_string(),
        },
    ))
}
pub(crate) fn capacity(resource: &str, requested: u64, available: u64) -> AtlasError {
    se_types::SeError::new(se_types::Detail::AtlasResourceBudget(
        se_types::details::AtlasResourceBudget {
            resource: resource.into(),
            requested,
            available,
        },
    ))
}
