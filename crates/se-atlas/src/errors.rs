pub use se_types::{ErrorBody as AtlasFailure, SeError as AtlasError};

pub type AtlasResult<T> = Result<T, AtlasError>;

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
