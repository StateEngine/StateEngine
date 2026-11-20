//! Bounded read-only observation of an existing Git repository: the branch,
//! the commit count reachable from HEAD and whether uncommitted changes are
//! present. A fresh in-process backend scans the working tree on a single-flight
//! thread; its answer deadline can leave that scan running with no dirty claim.
//! Unsupported observations use bounded Git invocations with a top-precedence
//! `core.fsmonitor=false` command parameter, which beats both repository
//! files and an inherited `GIT_CONFIG_PARAMETERS`, and keeps output bounded,
//! so the observer can never execute repository configuration, buffer an
//! unbounded working tree, or stretch the observation against a pipe a
//! retained descriptor keeps open.
#[path = "state_count.rs"]
mod count;
#[path = "count_cache.rs"]
mod count_cache;
#[path = "state_status.rs"]
mod status;
pub(super) use super::pipe;
use count::{CountRead, observe_count};
use se_core::{ops::GitView, scope};
#[cfg(any(windows, target_os = "macos"))]
use se_repository as library;
use se_types::Result;
use status::{StatusRead, status_within};
use std::{
    io,
    path::Path,
    process::{Command, ExitStatus},
    time::{Duration, Instant},
};

const STATUS_OBSERVATION_DEADLINE: Duration = Duration::from_secs(10);
const STDERR_RETAIN: usize = 4096;
const STDERR_TAIL: usize = 160;
/// A commit count is a short decimal number; a bound far above it refuses a
/// hostile or malformed writer instead of buffering it.
const COUNT_RETAIN: usize = 256;

pub fn observe(root: &Path) -> Result<Option<GitView>> {
    let deadline = Instant::now() + STATUS_OBSERVATION_DEADLINE;
    observe_within(root, deadline)
}

/// Status can reuse an exact history count from its protected data home.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn observe_cached(
    root: &Path,
    files: &dyn se_store::StateFiles,
    home: &Path,
) -> Result<Option<GitView>> {
    observe_using(
        root,
        Instant::now() + STATUS_OBSERVATION_DEADLINE,
        Some((files, home)),
        None,
    )
}

#[cfg(any(windows, target_os = "macos"))]
pub fn observe_cached_watched(
    root: &Path,
    files: &dyn se_store::StateFiles,
    home: &Path,
    watched: Option<&GitView>,
) -> Result<Option<GitView>> {
    observe_using(
        root,
        Instant::now() + STATUS_OBSERVATION_DEADLINE,
        Some((files, home)),
        watched,
    )
}

/// The observation with its one deadline supplied, so a test can drive the
/// bounded paths without waiting the production bound out.
pub(crate) fn observe_within(root: &Path, deadline: Instant) -> Result<Option<GitView>> {
    observe_using(root, deadline, None, None)
}

fn observe_using(
    root: &Path,
    deadline: Instant,
    cache: Option<(&dyn se_store::StateFiles, &Path)>,
    watched: Option<&GitView>,
) -> Result<Option<GitView>> {
    if !root.is_dir() {
        return Ok(None);
    }
    #[cfg(any(windows, target_os = "macos"))]
    if let Some(view) = watched.filter(|view| {
        view.uncommitted.is_some()
            && view
                .observation
                .as_ref()
                .is_some_and(|value| value.basis == "watched")
            && library::watch_environment().is_ok()
    }) {
        return Ok(Some(view.clone()));
    }
    let mut candidate = Some(root);
    let mut registered = None;
    while let Some(path) = candidate {
        match std::fs::symlink_metadata(path.join(".git")) {
            Ok(_) => {
                registered = Some(path);
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
    let Some(repository) = registered else {
        return Ok(None);
    };
    // Header and dirtiness come from the fresh native observer, or one bounded
    // `status --porcelain=v2 --branch` fallback. History counting is separate.
    #[cfg(not(any(windows, target_os = "macos")))]
    let _ = watched;
    let StatusRead::Known {
        header,
        dirty: observed_dirty,
    } = status_within(root, deadline)?
    else {
        // Git metadata is present but this machine has no Git binary: the
        // state is absent to this machine, not unreadable.
        return Ok(None);
    };
    // A dirty fact is only meaningful against a resolved commit; an unborn
    // branch reports no head, no count and no dirty fact. An unresolved dirty
    // fact stays `None`, which reads as unknown rather than clean.
    let uncommitted = if header.head.is_some() {
        observed_dirty
    } else {
        None
    };
    // The header's exact object ID keys the count and the history walk. Using
    // that ID instead of HEAD also avoids counting a later concurrent commit.
    let commits = match header.head.as_deref() {
        Some(head) => {
            let cached = cache.and_then(|(files, home)| {
                count_cache::CountCache::open(repository, head, files, home)
            });
            if let Some(count) = cached.as_ref().and_then(|cache| cache.count()) {
                Some(count)
            } else {
                match observe_blocking(observe_count(root, head, deadline))? {
                    CountRead::Count(count) => {
                        if let Some(cache) = cached {
                            cache.save(count);
                        }
                        Some(count)
                    }
                    // An incomplete walk is unknown, never an invented zero.
                    CountRead::Deadline => None,
                    CountRead::Missing => return Ok(None),
                }
            }
        }
        None => None,
    };
    Ok(Some(GitView {
        head: header.head,
        branch: header.branch,
        commits,
        uncommitted,
        observation: None,
    }))
}

fn observe_blocking<T>(observation: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|error| scope::unreadable("Git repository observation", &error.to_string()))?;
    runtime.block_on(observation)
}

/// Wait for the child to exit or the deadline to pass; `None` reports the
/// deadline first, leaving the child for the caller to kill and reap.
async fn bounded_exit(
    child: &mut tokio::process::Child,
    deadline: tokio::time::Instant,
) -> Option<io::Result<ExitStatus>> {
    tokio::select! {
        result = child.wait() => Some(result),
        () = tokio::time::sleep_until(deadline) => None,
    }
}

/// Git's own bounded stderr tail, prefixed for appending to a refusal. Empty
/// when Git said nothing, so a refusal without a cause stays unchanged.
fn stderr_tail(bytes: &[u8]) -> String {
    let trimmed = String::from_utf8_lossy(bytes).trim().to_owned();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut end = trimmed.len().min(STDERR_TAIL);
    while !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!(": {}", &trimmed[..end])
}

/// The flags every observation call shares. Both Git command builders —
/// std for the buffered metadata calls, tokio for the streaming status —
/// implement exactly this overlap, so one configuration governs both.
trait GitCommand {
    fn git_arg<S: AsRef<std::ffi::OsStr> + Clone>(&mut self, value: S) -> &mut Self;
    fn git_env(&mut self, key: &str, value: &str) -> &mut Self;
    fn git_env_remove(&mut self, key: &str) -> &mut Self;
}

impl GitCommand for Command {
    fn git_arg<S: AsRef<std::ffi::OsStr> + Clone>(&mut self, value: S) -> &mut Self {
        self.arg(value)
    }
    fn git_env(&mut self, key: &str, value: &str) -> &mut Self {
        self.env(key, value)
    }
    fn git_env_remove(&mut self, key: &str) -> &mut Self {
        self.env_remove(key)
    }
}

impl GitCommand for tokio::process::Command {
    fn git_arg<S: AsRef<std::ffi::OsStr> + Clone>(&mut self, value: S) -> &mut Self {
        self.arg(value)
    }
    fn git_env(&mut self, key: &str, value: &str) -> &mut Self {
        self.env(key, value)
    }
    fn git_env_remove(&mut self, key: &str) -> &mut Self {
        self.env_remove(key)
    }
}

/// One Git configuration for every observation call: the target root, a
/// top-precedence `core.fsmonitor=false` command parameter that beats both
/// repository files and an inherited `GIT_CONFIG_PARAMETERS`, no lock
/// maintenance, and no repository identity inherited from the caller's
/// environment.
fn configured<'a, C: GitCommand>(root: &Path, command: &'a mut C) -> &'a mut C {
    command
        .git_arg("-c")
        .git_arg("core.fsmonitor=false")
        .git_arg("-C")
        .git_arg(root)
        .git_env("GIT_OPTIONAL_LOCKS", "0")
        .git_env_remove("GIT_DIR")
        .git_env_remove("GIT_WORK_TREE")
        .git_env_remove("GIT_INDEX_FILE")
}
