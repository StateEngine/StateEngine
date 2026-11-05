//! A status view of the already-published index, never a cache query.
use crate::ops::outputs::AtlasView;
use se_types::{
    Read,
    code::{IndexState, IndexSummary},
};

pub fn atlas_view(observed: se_types::Result<Read<IndexSummary>>) -> AtlasView {
    let mut view = AtlasView {
        state: "unknown".into(),
        history: "unavailable".into(),
        reason: None,
        summary: None,
    };
    let summary = match observed {
        Ok(Read::Present { value }) => value,
        Ok(Read::Absent { checked }) => {
            view.state = "unavailable".into();
            view.reason = Some(checked);
            return view;
        }
        Ok(Read::Unknown { what }) => {
            view.state = "preparing".into();
            view.reason = Some(what);
            return view;
        }
        Ok(Read::Unreadable { source, reason, .. }) => {
            view.state = "unreadable".into();
            view.reason = Some(format!("{source}: {reason}"));
            return view;
        }
        Err(error) => {
            view.state = "unreadable".into();
            view.reason = Some(error.body.message());
            return view;
        }
    };
    let coverage = &summary.coverage;
    let partial = !coverage.discovery_complete
        || coverage.partial_files > 0
        || coverage.deferred_files > 0
        || coverage.failed_files > 0
        || coverage.stale_files > 0
        || coverage.unwatched_directories > 0
        || !coverage.watch_discovery_complete;
    view.state = match &summary.state {
        IndexState::NotBuilt => "not-built",
        IndexState::Disabled => "disabled",
        IndexState::Dormant => "dormant",
        IndexState::Absent => "absent",
        IndexState::Opening | IndexState::ColdIndexing { .. } => {
            view.reason = Some(if summary.epoch.is_none() {
                "Preparing the first index; file counts are not available until it is published."
            } else {
                "Preparing an index; file counts describe the previously published snapshot."
            }.into());
            "preparing"
        }
        IndexState::Updating { .. } => "updating",
        IndexState::Current if partial => "partial",
        IndexState::Current => "current",
        IndexState::Partial { error } => {
            view.reason = Some(error.message());
            "partial"
        }
        IndexState::VerificationNeeded { .. } => "partial",
        IndexState::Suspended { reason } => {
            view.reason = Some(reason.message());
            "suspended"
        }
        IndexState::Unreadable { error } => {
            view.reason = Some(error.message());
            "unreadable"
        }
        IndexState::Draining => "draining",
        IndexState::Closed => "closed",
    }
    .into();
    // A source epoch alone does not prove complete Git history; retain unknown.
    if summary.epoch.is_some()
        && !matches!(
            summary.state,
            IndexState::Disabled
                | IndexState::NotBuilt
                | IndexState::Absent
                | IndexState::Opening
                | IndexState::ColdIndexing { .. }
                | IndexState::Unreadable { .. }
                | IndexState::Closed
        )
    {
        view.history = if coverage.history_unavailable.is_some() {
            "unavailable"
        } else {
            "unknown"
        }
        .into();
    }
    view.summary = Some(summary);
    view
}
