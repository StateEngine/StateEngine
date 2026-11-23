pub use se_types::{ErrorBody as AtlasFailure, SeError as AtlasError};

pub type AtlasResult<T> = Result<T, AtlasError>;

pub(crate) fn capacity(resource: &str, requested: u64, available: u64) -> AtlasError {
    se_types::SeError::new(se_types::Detail::AtlasResourceBudget(
        se_types::details::AtlasResourceBudget {
            resource: resource.into(),
            requested,
            available,
        },
    ))
}
