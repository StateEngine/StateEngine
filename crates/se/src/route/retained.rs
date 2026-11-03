//! Removed registrations are a fallback after active project selection.
use se_store::{Admission, ProjectionRecord, ReadStore, RemovedProjectQuery};
use se_types::{NativePath, Result};
use std::path::Path;

pub(super) fn select<R: ReadStore>(
    reader: &R,
    admission: &Admission,
    requested: Option<&str>,
    cwd: &Path,
) -> Result<Vec<ProjectionRecord>> {
    if let Some(name) = requested {
        return super::select::inventory(
            reader,
            admission,
            Some(RemovedProjectQuery::Name(name.into())),
        );
    }
    for (depth, ancestor) in cwd.ancestors().enumerate() {
        if depth == 64 {
            return Err(se_core::scope::unreadable(
                "retained project selection",
                "current directory exceeds the 64-ancestor lookup budget",
            ));
        }
        let records = super::select::inventory(
            reader,
            admission,
            Some(RemovedProjectQuery::Root(NativePath::from_local(
                ancestor.into(),
            )?)),
        )?;
        if !records.is_empty() {
            return Ok(records);
        }
    }
    Ok(Vec::new())
}
