//! Feed one worktree's engine the next chunk of its project's committed
//! records. The ticket predates the core snapshot; only an exhausted feed
//! certifies this root and store epoch as current.
use super::*;
use crate::atlas_runtime::record_fence::RecordFeedScope;
use se_core::{admission::read_scope, ops::transcript::tool::ObservedPath};
use se_types::code::RelativePath;
use std::path::{Component, Path};

/// Bound for one feed chunk's write.
const FEED_WRITE: Duration = Duration::from_secs(1);

/// What one chunk did for a worktree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fed {
    /// Every committed record is in the store, certified for this ticket.
    Current,
    /// A chunk was written and more remain.
    More,
    /// Nothing can progress now: a core write is pending, the store has no
    /// epoch yet, or a write intervened before certification.
    Waiting,
}

pub fn chunk(host: &dyn AtlasHost, owner: &HumanId, root: &Root) -> Result<Fed> {
    let Some(ticket) = host.records().ticket()? else {
        return Ok(Fed::Waiting);
    };
    let Some(epoch) = root.summary()?.epoch else {
        return Ok(Fed::Waiting);
    };
    let spec = root.spec();
    let admitted = admission(host, owner, Scope::Project(spec.project.clone()));
    let phase = host.checked_read_phase()?;
    let mut snapshot = phase
        .into_snapshot(read_scope(&admitted))
        .map_err(|e| store_error(&e))?;
    let result = (|| {
        let after = root.feed_cursor()?;
        let feed = se_core::atlas_records::feed::next_with_paths(
            &mut snapshot,
            &admitted,
            after,
            &mut |path| tool_path(root, path),
        )?;
        let complete = match feed {
            Some(feed) => root.apply_feed(feed, FEED_WRITE)?.complete,
            None => true,
        };
        if !complete {
            return Ok(Fed::More);
        }
        let scope = RecordFeedScope {
            project: spec.project.clone(),
            root: spec.root.clone(),
            epoch,
        };
        Ok(if host.records().mark_current(scope, ticket)? {
            Fed::Current
        } else {
            Fed::Waiting
        })
    })();
    close_read(result, snapshot.close())
}

/// A captured tool path inside this worktree, if it names an indexable file
/// that exists there now. Parent references and private paths never count.
fn tool_path(root: &Root, path: &ObservedPath) -> Result<Option<RelativePath>> {
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
        let Some(cwd) = path.cwd.as_deref().map(Path::new).filter(|cwd| {
            cwd.is_absolute() && !cwd.components().any(|p| matches!(p, Component::ParentDir))
        }) else {
            return Ok(None);
        };
        cwd.join(spelling)
    };
    let Ok(relative) = absolute.strip_prefix(&root.spec().source) else {
        return Ok(None);
    };
    let Some(relative) = relative.to_str() else {
        return Ok(None);
    };
    let relative = relative.replace(std::path::MAIN_SEPARATOR, "/");
    if se_atlas_service::classify(&relative) != se_atlas_service::Reported::Source
        || !root.has_file(&relative)?
    {
        return Ok(None);
    }
    Ok(RelativePath::new(relative).ok())
}
