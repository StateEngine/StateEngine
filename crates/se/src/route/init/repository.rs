//! Read-only setup observations. A native root, its contents and optional Git
//! metadata are observed before the first setup write.
use crate::bootstrap::Bootstrap;
use se_core::{
    ops::{GitView, ProjectInit},
    scope,
};
use se_types::{Result, SeError};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

pub(super) struct Repository {
    pub path: PathBuf,
    pub name: String,
    pub nonempty: bool,
    pub git: Option<GitView>,
}
pub(super) fn observe(cx: &Bootstrap, input: &ProjectInit) -> Result<Repository> {
    let requested = input
        .repo
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| cx.cwd.clone());
    let path = se_proc::canonicalize_path(if requested.is_absolute() {
        requested
    } else {
        cx.cwd.join(requested)
    })
    .map_err(|e| scope::unreadable("repository root", &e.to_string()))?;
    if !path.is_dir() {
        return Err(SeError::invalid("repository root", "an existing directory"));
    }
    if canonical_destination(&cx.home)?.starts_with(&path) {
        return Err(SeError::invalid(
            "state home",
            "a state home outside the registered repository; managed init writes no repository files",
        ));
    }
    if cx.config.value.runtime.listen_port.is_none() {
        let configuration = match &cx.config.origin {
            crate::config::Origin::File(selected) => selected.clone(),
            crate::config::Origin::BuiltIn => cx.home.join("config.toml"),
        };
        if canonical_destination(&configuration)?.starts_with(&path) {
            return Err(SeError::invalid(
                "setup configuration",
                "a selected configuration outside the repository when setup must persist its listener port",
            ));
        }
    }
    let name = input
        .name
        .clone()
        .or_else(|| path.file_name().and_then(|s| s.to_str()).map(str::to_owned))
        .ok_or_else(|| {
            SeError::invalid(
                "project name",
                "--name for a root without a UTF-8 final component",
            )
        })?;
    let mut resolved = input.clone();
    resolved.name = Some(name.clone());
    se_core::ops::inputs::Validate::validate(&resolved)?;
    let nonempty = std::fs::read_dir(&path)
        .map_err(|e| scope::unreadable("repository contents", &e.to_string()))?
        .next()
        .transpose()
        .map_err(|e| scope::unreadable("repository contents", &e.to_string()))?
        .is_some();
    let git = git(&path)?;
    Ok(Repository {
        path,
        name,
        nonempty,
        git,
    })
}
fn git(root: &Path) -> Result<Option<GitView>> {
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
    let head = if head.status.success() {
        let value = text(&head)?;
        if !matches!(value.len(), 40 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(scope::unreadable(
                "Git HEAD",
                "Git returned an invalid object identity",
            ));
        }
        Some(value)
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
        None
    } else {
        return Err(scope::unreadable(
            "Git HEAD",
            "commit lookup failed; preserve the repository and restore access",
        ));
    };
    Ok(Some(GitView {
        head,
        branch: full_branch.map(|value| {
            value
                .strip_prefix("refs/heads/")
                .unwrap_or(&value)
                .to_owned()
        }),
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
fn canonical_destination(path: &Path) -> Result<PathBuf> {
    let mut parent = path;
    let mut missing = Vec::new();
    loop {
        match se_proc::canonicalize_path(parent) {
            Ok(mut resolved) => {
                for component in missing.into_iter().rev() {
                    resolved.push(component);
                }
                return Ok(resolved);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(
                    parent
                        .file_name()
                        .ok_or_else(|| SeError::invalid("state home", "a native absolute path"))?
                        .to_owned(),
                );
                parent = parent
                    .parent()
                    .ok_or_else(|| SeError::invalid("state home", "a native absolute path"))?;
            }
            Err(error) => {
                return Err(scope::unreadable(
                    "state home resolution",
                    &error.to_string(),
                ));
            }
        }
    }
}
