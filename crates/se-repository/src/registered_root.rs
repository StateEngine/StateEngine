//! Match an invocation to a registered root without crossing a nested worktree.
use std::path::{Path, PathBuf};

/// Exact roots also admit non-Git projects. Descendants require the nearest
/// Git worktree to be the registered root, so a nested repository stays separate.
pub fn registered_worktree(
    cwd: &Path,
    roots: impl IntoIterator<Item = Option<PathBuf>>,
) -> Result<Option<usize>, String> {
    let roots: Vec<_> = roots.into_iter().collect();
    if let Some(index) = roots.iter().position(|root| root.as_deref() == Some(cwd)) {
        return Ok(Some(index));
    }
    if !roots.iter().flatten().any(|root| cwd.starts_with(root)) {
        return Ok(None);
    }
    let repository = match git2::Repository::open_ext(
        cwd,
        git2::RepositoryOpenFlags::empty(),
        &[] as &[&std::ffi::OsStr],
    ) {
        Ok(repository) => repository,
        Err(error) if error.code() == git2::ErrorCode::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot identify the Git worktree: {error}")),
    };
    let Some(root) = repository.workdir() else {
        return Ok(None);
    };
    let root = se_proc::canonicalize_path(root)
        .map_err(|error| format!("cannot identify the Git worktree root: {error}"))?;
    Ok(roots
        .iter()
        .position(|candidate| candidate.as_deref() == Some(root.as_path())))
}
