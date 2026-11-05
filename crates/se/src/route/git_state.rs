//! Bounded read-only observation of an existing Git repository: the branch,
//! the commit count reachable from HEAD and whether uncommitted changes are
//! present. The commands and environment match the init repository reader.
use se_core::{ops::GitView, scope};
use se_types::{Result, SeError};
use std::{
    path::Path,
    process::{Command, Output},
};

pub fn observe(root: &Path) -> Result<Option<GitView>> {
    if !root.is_dir() {
        return Ok(None);
    }
    let mut candidate = Some(root);
    let mut registered = false;
    while let Some(path) = candidate {
        match std::fs::symlink_metadata(path.join(".git")) {
            Ok(_) => {
                registered = true;
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => {
                return Err(scope::unreadable(
                    "Git repository metadata",
                    &error.to_string(),
                ));
            }
        }
        candidate = path.parent();
    }
    if !registered {
        return Ok(None);
    }
    let symbolic = run(root, &["symbolic-ref", "-q", "HEAD"])?;
    let full_branch = if symbolic.status.success() {
        Some(text(&symbolic)?)
    } else if symbolic.status.code() == Some(1) {
        None
    } else {
        return Err(scope::unreadable(
            "Git HEAD",
            "symbolic HEAD could not be read",
        ));
    };
    let head = run(root, &["rev-parse", "--verify", "--quiet", "HEAD"])?;
    let (head, commits) = if head.status.success() {
        let value = text(&head)?;
        if !matches!(value.len(), 40 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(scope::unreadable(
                "Git HEAD",
                "Git returned an invalid object identity",
            ));
        }
        let count = run(root, &["rev-list", "--count", "HEAD"])?;
        if !count.status.success() {
            return Err(scope::unreadable(
                "Git HEAD",
                "commit count lookup failed; preserve the repository and restore access",
            ));
        }
        let count = text(&count)?
            .parse::<u64>()
            .map_err(|_| scope::unreadable("Git HEAD", "Git returned an invalid commit count"))?;
        (Some(value), Some(count))
    } else if head.status.code() == Some(1) {
        let branch = full_branch.as_deref().ok_or_else(|| {
            scope::unreadable("Git HEAD", "detached HEAD does not resolve to a commit")
        })?;
        let exists = run(root, &["show-ref", "--verify", "--quiet", branch])?;
        if exists.status.code() != Some(1) {
            return Err(scope::unreadable(
                "Git HEAD",
                "a present or unreadable branch failed to resolve",
            ));
        }
        (None, None)
    } else {
        return Err(scope::unreadable(
            "Git HEAD",
            "commit lookup failed; preserve the repository and restore access",
        ));
    };
    let uncommitted = match &head {
        Some(_) => {
            let status = run(root, &["status", "--porcelain"])?;
            if !status.status.success() {
                return Err(scope::unreadable(
                    "Git working tree",
                    "working tree status could not be read; preserve the repository and restore access",
                ));
            }
            Some(!status.stdout.is_empty())
        }
        None => None,
    };
    Ok(Some(GitView {
        head,
        branch: full_branch.map(|value| {
            value
                .strip_prefix("refs/heads/")
                .unwrap_or(&value)
                .to_owned()
        }),
        commits,
        uncommitted,
    }))
}
fn run(root: &Path, args: &[&str]) -> Result<Output> {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .map_err(|e| scope::unreadable("Git repository observation", &e.to_string()))
}
fn text(output: &Output) -> Result<String> {
    if output.stdout.len() > 4096 {
        return Err(SeError::too_large(
            "Git metadata",
            4096,
            output.stdout.len(),
        ));
    }
    std::str::from_utf8(&output.stdout)
        .map(|s| s.trim_end_matches(['\r', '\n']).to_owned())
        .map_err(|_| scope::unreadable("Git metadata", "Git returned non-UTF-8 metadata"))
}
