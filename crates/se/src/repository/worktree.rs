//! Native CLI route for `se worktree remove <PATH>`.
//! Runs directly against the local filesystem and Git metadata without opening
//! or requiring a StateEngine store, while enforcing the non-following
//! link/junction guard before any deletion.
use crate::bootstrap::Bootstrap;
use se_core::ops::{AnyOutput, WorktreeRemove, WorktreeRemoveOutput, inputs::Validate};
use se_repository::worktree::{WorktreeRemoveError, remove_worktree};
use se_types::{Detail, Result, SeError, details};
use std::path::PathBuf;

pub(crate) fn remove(cx: &Bootstrap, input: WorktreeRemove) -> Result<AnyOutput> {
    input.validate()?;
    let requested = PathBuf::from(&input.path);
    let target = if requested.is_absolute() {
        requested
    } else {
        cx.cwd.join(requested)
    };
    let report = remove_worktree(&target, input.force).map_err(map_error)?;
    Ok(AnyOutput::from(WorktreeRemoveOutput {
        path: report.path.display().to_string(),
        worktree_name: report.worktree_name,
        common_dir: report.common_dir.display().to_string(),
        forced: report.forced,
        pruned: report.pruned,
    }))
}

fn map_error(error: WorktreeRemoveError) -> SeError {
    match error {
        WorktreeRemoveError::Absent { path } => refusal(
            "worktree path",
            &format!("{} does not exist", path.display()),
            "Check active worktrees with `git worktree list` and pass an existing linked worktree path.",
        ),
        WorktreeRemoveError::Unreadable { entries, total } => {
            let listed = format_entries(&entries, total);
            SeError::new(Detail::SourceUnreadable(details::SourceUnreadable {
                subject: "worktree link inspection".into(),
                reason: format!("unreadable path(s) prevented link-guard verification: {listed}"),
                next_step: "Restore read permissions on the listed paths so the worktree can be inspected for links/junctions before removal.".into(),
            }))
        }
        WorktreeRemoveError::LinksDetected {
            links,
            total_links,
            unreadable,
            total_unreadable,
        } => links_refusal(&links, total_links, &unreadable, total_unreadable),
        WorktreeRemoveError::NestedGitRepositories { paths, total } => refusal(
            "nested Git repository",
            &format!(
                "refusing to delete nested Git repository or worktree(s): {}",
                format_entries(&paths, total)
            ),
            "Remove or commit the nested worktree/repository first (for example `se worktree remove <nested-path>`), then retry `se worktree remove`; `--force` never deletes nested Git repositories or worktrees.",
        ),
        WorktreeRemoveError::CustodyChanged { path, reason } => refusal(
            "worktree custody",
            &format!("{}: {reason}", path.display()),
            "Inspect the directory for concurrent modifications or mounts, then retry `se worktree remove`.",
        ),
        WorktreeRemoveError::NotLinkedWorktree { path, reason } => refusal(
            "worktree target",
            &format!("{}: {reason}", path.display()),
            "Pass the root directory of a linked Git worktree from `git worktree list`; primary repositories and unrelated directories are refused.",
        ),
        WorktreeRemoveError::Locked { path, reason } => {
            let detail = reason
                .as_deref()
                .filter(|r| !r.is_empty())
                .map(|r| format!(" ({r})"))
                .unwrap_or_default();
            refusal(
                "locked worktree",
                &format!("{} is locked{detail}", path.display()),
                "Unlock it with `git worktree unlock <PATH>` first, then retry `se worktree remove`.",
            )
        }
        WorktreeRemoveError::Dirty {
            path,
            count,
            sample,
        } => {
            let preview = if sample.is_empty() {
                String::new()
            } else {
                let suffix = if count > sample.len() {
                    format!(", ... (+{} more)", count - sample.len())
                } else {
                    String::new()
                };
                format!(" ({}{suffix})", sample.join(", "))
            };
            refusal(
                "dirty worktree",
                &format!(
                    "{} has {count} uncommitted or untracked change(s){preview}",
                    path.display()
                ),
                "Commit, stash, or discard changes first, or pass `--force` to remove a dirty worktree (links/junctions are still refused).",
            )
        }
        WorktreeRemoveError::DeleteFailed {
            path,
            reason,
            partial,
            dot_git_preserved,
        } => delete_refusal(&path, &reason, partial, dot_git_preserved),
        WorktreeRemoveError::PruneFailed {
            worktree_name,
            reason,
        } => refusal(
            "worktree metadata prune",
            &format!(
                "worktree directory was removed, but pruning Git metadata for '{worktree_name}' failed: {reason}"
            ),
            "Run `git worktree prune` in the primary repository to clean up stale metadata.",
        ),
    }
}

fn links_refusal(
    links: &[(PathBuf, String)],
    total_links: usize,
    unreadable: &[(PathBuf, String)],
    total_unreadable: usize,
) -> SeError {
    let listed = format_entries(links, total_links);
    let mut reason =
        format!("detected symbolic link(s), junction/reparse point(s), or mount(s): {listed}");
    if total_unreadable > 0 {
        reason.push_str(&format!(
            "; also found unreadable path(s): {}",
            format_entries(unreadable, total_unreadable)
        ));
    }
    refusal(
        "worktree link guard",
        &reason,
        "Unlink or unmount the listed paths manually (never recursively delete through them), then retry `se worktree remove`; `--force` never bypasses the link/mount guard.",
    )
}

fn delete_refusal(
    path: &std::path::Path,
    reason: &str,
    partial: bool,
    dot_git_preserved: bool,
) -> SeError {
    let (status, next_step) = match (partial, dot_git_preserved) {
        (true, true) => (
            "partial deletion occurred, but root .git was preserved so retry remains safe",
            "Close any processes holding open handles and fix directory permissions, then retry `se worktree remove`.",
        ),
        (true, false) => (
            "partial deletion occurred and root .git could not be restored",
            "Inspect the surviving directory, remove it manually once handles/permissions are resolved, and run `git worktree prune` in the primary repository.",
        ),
        (false, _) => (
            "no files were removed",
            "Close any processes holding open handles and fix directory permissions, then retry `se worktree remove`.",
        ),
    };
    refusal(
        "worktree deletion",
        &format!("failed to remove {}: {reason} ({status})", path.display()),
        next_step,
    )
}

fn format_entries(entries: &[(PathBuf, String)], total: usize) -> String {
    let mut parts: Vec<String> = entries
        .iter()
        .map(|(path, detail)| format!("{} ({detail})", path.display()))
        .collect();
    if total > entries.len() {
        parts.push(format!("... (+{} more)", total - entries.len()));
    }
    parts.join(", ")
}

fn refusal(subject: &str, reason: &str, next_step: &str) -> SeError {
    SeError::new(Detail::RepoInvalid(details::RepoInvalid {
        subject: subject.into(),
        reason: reason.into(),
        next_step: next_step.into(),
    }))
}
