//! Removed registrations are a fallback after active project selection.
use se_store::{ProjectionRecord, RemovedProjectQuery, Snapshot};
use se_types::{NativePath, Result};
use std::path::Path;

pub(super) fn select<S: Snapshot>(
    snapshot: &mut S,
    requested: Option<&str>,
    cwd: &Path,
) -> Result<Vec<ProjectionRecord>> {
    if let Some(name) = requested {
        return super::select::inventory_at(snapshot, Some(RemovedProjectQuery::Name(name.into())));
    }
    for (depth, ancestor) in cwd.ancestors().enumerate() {
        if depth == 64 {
            return Err(se_core::scope::unreadable(
                "retained project selection",
                "current directory exceeds the 64-ancestor lookup budget",
            ));
        }
        let root = se_proc::canonicalize_path(ancestor).map_err(|error| {
            se_core::scope::unreadable("retained project root", &error.to_string())
        })?;
        let records = super::select::inventory_at(
            snapshot,
            Some(RemovedProjectQuery::Root(NativePath::from_local(root)?)),
        )?;
        if !records.is_empty() {
            return Ok(records);
        }
    }
    Ok(Vec::new())
}
