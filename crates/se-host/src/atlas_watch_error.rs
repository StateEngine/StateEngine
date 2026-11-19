//! Shared errors for source and metadata watch adapters.
use se_atlas::errors::AtlasResult;
use se_types::{Detail, SeError, details};
use std::time::Instant;

pub(crate) fn source_error(path: &str, error: impl std::fmt::Display) -> SeError {
    SeError::new(Detail::AtlasSourceUnreadable(
        details::AtlasSourceUnreadable {
            path: path.into(),
            reason: error.to_string(),
        },
    ))
}
pub(crate) fn limit(resource: &str, requested: u64, available: u64) -> SeError {
    SeError::new(Detail::AtlasResourceBudget(details::AtlasResourceBudget {
        resource: resource.into(),
        requested,
        available,
    }))
}
pub(crate) fn timely(deadline: Instant) -> AtlasResult<()> {
    if se_atlas::clock::now() >= deadline {
        Err(limit("renewal work deadline", 1, 0))
    } else {
        Ok(())
    }
}
