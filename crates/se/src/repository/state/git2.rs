//! The replaceable native-library backend. It returns owned facts, never a
//! library handle or status entry across the repository-observation interface.
use super::Facts;
use git2::{ErrorCode, Repository, RepositoryOpenFlags, Status, StatusOptions};
use std::path::{Path, PathBuf};

pub(super) struct Prepared {
    repository: Repository,
    key: PathBuf,
    facts: Facts,
    untracked: bool,
}
impl Prepared {
    pub(super) fn open(root: &Path) -> Result<Self, String> {
        // Deliberately omit FROM_ENV: GIT_DIR, GIT_WORK_TREE and GIT_INDEX_FILE
        // cannot redirect an observation of the caller's selected repository.
        let repository = Repository::open_ext(
            root,
            RepositoryOpenFlags::empty(),
            &[] as &[&std::ffi::OsStr],
        )
        .map_err(describe)?;
        let config = repository.config().map_err(describe)?;
        for name in ["core.sparseCheckout", "index.sparse"] {
            match config.get_bool(name) {
                Ok(true) => return Err(format!("{name} requires the command-line observer")),
                Ok(false) => {}
                Err(error) if error.code() == ErrorCode::NotFound => {}
                Err(error) => return Err(describe(error)),
            }
        }
        let untracked = match config.get_string("status.showUntrackedFiles") {
            Ok(value) => match value.as_str() {
                "no" => false,
                "normal" | "all" => true,
                _ => return Err("unsupported status.showUntrackedFiles value".into()),
            },
            Err(error) if error.code() == ErrorCode::NotFound => true,
            Err(error) => return Err(describe(error)),
        };
        let key = repository
            .workdir()
            .ok_or("repository has no working tree")?
            .canonicalize()
            .map_err(|error| format!("cannot identify working tree: {error}"))?;
        let facts = header(&repository)?;
        drop(config);
        Ok(Self {
            repository,
            key,
            facts,
            untracked,
        })
    }
    pub(super) fn facts(&self) -> &Facts {
        &self.facts
    }
    pub(super) fn key(&self) -> &Path {
        &self.key
    }
    pub(super) fn scan(self) -> Result<bool, String> {
        let mut options = StatusOptions::new();
        options
            .include_untracked(self.untracked)
            // One untracked directory already proves dirtiness. Its contents
            // need not be retained to answer this boolean observation.
            .recurse_untracked_dirs(false)
            .include_ignored(false)
            .include_unmodified(false)
            .exclude_submodules(false)
            .renames_head_to_index(false)
            .renames_index_to_workdir(false)
            .include_unreadable(true)
            .include_unreadable_as_untracked(false)
            .no_refresh(false)
            .update_index(false);
        // This call can block. The interface waits only until its deadline and
        // retains single-flight ownership until the scan actually returns.
        let statuses = self
            .repository
            .statuses(Some(&mut options))
            .map_err(describe)?;
        let mut dirty = false;
        for entry in statuses.iter() {
            let status = entry.status();
            if status.contains(Status::WT_UNREADABLE) {
                return Err("working-tree status contains an unreadable path".into());
            }
            if status != Status::CURRENT && status != Status::IGNORED {
                dirty = true;
                break;
            }
        }
        if header(&self.repository)? != self.facts {
            return Err("repository HEAD or branch changed during the working-tree scan".into());
        }
        Ok(dirty)
    }
}

fn header(repository: &Repository) -> Result<Facts, String> {
    let (head, branch) = match repository.head() {
        Ok(reference) => {
            let head = reference
                .target()
                .ok_or("HEAD did not resolve to an object")?;
            let branch = if reference.is_branch() {
                let name =
                    std::str::from_utf8(reference.name_bytes()).map_err(|e| e.to_string())?;
                Some(
                    name.strip_prefix("refs/heads/")
                        .ok_or("invalid branch reference")?
                        .to_owned(),
                )
            } else {
                None
            };
            (Some(head.to_string()), branch)
        }
        Err(error) if error.code() == ErrorCode::UnbornBranch => {
            let reference = repository.find_reference("HEAD").map_err(describe)?;
            let name = reference
                .symbolic_target()
                .map_err(describe)?
                .ok_or("unborn HEAD has no UTF-8 branch")?;
            (
                None,
                Some(
                    name.strip_prefix("refs/heads/")
                        .ok_or("invalid unborn branch")?
                        .to_owned(),
                ),
            )
        }
        Err(error) => return Err(describe(error)),
    };
    Ok(Facts {
        head,
        branch,
        dirty: None,
    })
}

fn describe(error: git2::Error) -> String {
    error.message().to_owned()
}
