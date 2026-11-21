//! Connect the scoped Atlas query reader to core's authoritative snapshot.
use se_atlas::{errors::AtlasResult, query::RecordReader};
use se_core::atlas_records::RecordAccess;
use se_store::{Admission, Snapshot};
use se_types::{ProjectId, Read, SeError, code::*};
use std::cell::RefCell;
pub struct AtlasRecordReader<'a, R: Snapshot> {
    access: RefCell<RecordAccess<'a, R>>,
}
impl<'a, R: Snapshot> AtlasRecordReader<'a, R> {
    pub fn new(read: &'a mut R, admission: &'a Admission) -> Self {
        Self {
            access: RefCell::new(RecordAccess::new(read, admission)),
        }
    }
}
impl<R: Snapshot> RecordReader for AtlasRecordReader<'_, R> {
    fn read(
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
    fn literal_read(
        &self,
        project: &ProjectId,
        viewer: &AtlasPrincipal,
        pointer: &RecordPointer,
        query: &QueryText,
    ) -> AtlasResult<Read<RecordHit>> {
        self.access
            .try_borrow_mut()
            .map_err(|_| {
                SeError::invalid("Atlas record snapshot", "one synchronous read at a time")
            })?
            .literal_hit(project, viewer, pointer, query)
    }
    fn body(
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

/// The automatic owner's root-scoped feed. Only explicit successful native
/// paths are considered; registration and no-follow custody supply authority.
pub fn next_feed<R: Snapshot>(
    read: &mut R,
    admission: &Admission,
    after: Option<se_types::EventId>,
    source: &se_atlas::source::RegisteredSource<crate::atlas_source::NativeAtlasSource>,
) -> se_types::Result<Option<RecordFeed>> {
    if admission.scope != se_store::Scope::Project(source.scope.registration.project.clone()) {
        return Err(SeError::invalid(
            "Atlas tool feed",
            "the registered root's admitted project",
        ));
    }
    se_core::atlas_records::feed::next_with_paths(read, admission, after, &mut |path| {
        tool_path(source, path)
    })
}
fn tool_path(
    source: &se_atlas::source::RegisteredSource<crate::atlas_source::NativeAtlasSource>,
    path: &se_core::ops::transcript::tool::ObservedPath,
) -> se_types::Result<Option<RelativePath>> {
    use std::path::{Component, Path};
    let root = &source.scope.registration.canonical_source_root;
    let spelling = Path::new(&path.spelling);
    if spelling
        .components()
        .any(|p| matches!(p, Component::ParentDir))
    {
        return Ok(None);
    }
    let absolute = if spelling.is_absolute() {
        spelling.to_path_buf()
    } else {
        let Some(cwd) = path
            .cwd
            .as_deref()
            .map(Path::new)
            .filter(|p| p.is_absolute())
        else {
            return Ok(None);
        };
        if cwd.components().any(|p| matches!(p, Component::ParentDir)) {
            return Ok(None);
        }
        cwd.join(spelling)
    };
    let Ok(relative) = absolute.strip_prefix(root) else {
        return Ok(None);
    };
    let Some(relative) = relative.to_str() else {
        return Ok(None);
    };
    let Ok(relative) = RelativePath::new(relative.replace(std::path::MAIN_SEPARATOR, "/")) else {
        return Ok(None);
    };
    if se_atlas::policy::built_in_denied(&relative) {
        return Ok(None);
    }
    let Some(file) = source.open(&relative)? else {
        return Ok(None);
    };
    if !file.validate_path()? {
        return Err(SeError::invalid(
            "captured tool path",
            "the retained file at its registered spelling",
        ));
    }
    Ok(Some(relative))
}
