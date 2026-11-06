//! Preserve source adoption where the contained Git reader is not available.
use super::*;
pub(super) struct Plan;
impl Plan {
    pub(super) fn new(_: GitMetadataRegistration, _: Option<&SqlProfile>) -> AtlasResult<Self> {
        Err(failure(
            "Contained Git history is unavailable on this platform; source indexing remains available",
        ))
    }
    pub(super) fn seed(
        self,
        _: &NativeAtlasCache,
        _: &protocol::Request,
        _: Instant,
    ) -> AtlasResult<(Generation, Option<se_types::ErrorBody>)> {
        Err(failure("Git history was not admitted on this platform"))
    }
}
