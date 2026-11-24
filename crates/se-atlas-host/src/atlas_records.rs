//! Check Atlas record hits against core's authoritative snapshot.
use se_atlas::errors::AtlasResult;
use se_atlas_records::RecordAccess;
use se_store::{Admission, Snapshot};
use se_types::{ProjectId, Read, SeError, code::*};
use std::cell::RefCell;
/// Every record and derived count is rechecked against its authoritative
/// event for this verified viewer; cached audiences are only hints.
pub struct AtlasRecordReader<'a, R: Snapshot> {
    access: RefCell<RecordAccess<'a, R>>,
}
impl<'a, R: Snapshot> AtlasRecordReader<'a, R> {
    pub fn new(read: &'a mut R, admission: &'a Admission) -> Self {
        Self {
            access: RefCell::new(RecordAccess::new(read, admission)),
        }
    }
    pub fn read(
        &self,
        project: &ProjectId,
        viewer: &AtlasPrincipal,
        pointer: &RecordPointer,
        query: Option<&QueryText>,
    ) -> AtlasResult<Read<RecordHit>> {
        self.access
            .try_borrow_mut()
            .map_err(|_| {
                SeError::invalid("Atlas record snapshot", "one synchronous read at a time")
            })?
            .hit(project, viewer, pointer, query)
    }
    pub fn body(
        &self,
        project: &ProjectId,
        viewer: &AtlasPrincipal,
        pointer: &RecordPointer,
        query: Option<&QueryText>,
    ) -> AtlasResult<Read<HitBody>> {
        self.access
            .try_borrow_mut()
            .map_err(|_| {
                SeError::invalid("Atlas record snapshot", "one synchronous read at a time")
            })?
            .body(project, viewer, pointer, query)
    }
}
