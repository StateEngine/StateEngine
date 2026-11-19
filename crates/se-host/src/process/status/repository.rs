//! The host keeps a bounded watched repository observation between status calls.
use super::*;
#[cfg(windows)]
use std::time::Duration;
use std::{path::Path, time::Instant};

impl LaunchCoordinator {
    pub(in crate::process) fn observe_repository(
        &self,
        output: &mut AnyOutput,
        fresh: bool,
        include_ticket: bool,
        deadline: &Deadline,
    ) -> Result<()> {
        #[cfg(not(windows))]
        if !fresh {
            let _ = include_ticket;
            return Ok(());
        }
        let AnyOutput::ProjectStatus(status) = output else {
            return Ok(());
        };
        let Read::Present { value: project } = &mut status.value.project else {
            return Ok(());
        };
        if project.root.is_empty() {
            return Ok(());
        }
        let root = std::path::PathBuf::from(&project.root);
        match has_git(&root) {
            Ok(true) => (),
            Ok(false) => return Ok(()),
            Err(error) => {
                status.value.pending.push(PendingFact {
                    what: "repository state".into(),
                    since: None,
                    detail: format!("Git state could not be read: {error}"),
                });
                return Ok(());
            }
        }
        if fresh {
            match fresh_view(&root, deadline.at()) {
                Ok(git) => project.git = git,
                Err(error) => status.value.pending.push(PendingFact {
                    what: "repository state".into(),
                    since: None,
                    detail: format!("Git state could not be read: {error}"),
                }),
            }
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
        #[cfg(windows)]
        {
            let watched = self.watched_repository(&root, deadline);
            match watched {
                Ok(value) => project.git = Some(watched_view(value, include_ticket)?),
                Err(reason) => {
                    status.value.pending.push(PendingFact {
                        what: "repository watch".into(),
                        since: None,
                        detail: format!(
                            "Watched status is unavailable: {reason}. A fresh scan is the fallback."
                        ),
                    });
                    // The CLI owns its direct fallback; an MCP caller has no later local scan.
                    if !include_ticket {
                        match fresh_view(&root, deadline.at()) {
                            Ok(git) => project.git = git,
                            Err(error) => status.value.pending.push(PendingFact {
                                what: "repository state".into(),
                                since: None,
                                detail: format!("Git state could not be read: {error}"),
                            }),
                        }
                    }
                }
            }
            Ok(())
        }
    }
    #[cfg(windows)]
    fn watched_repository(
        &self,
        root: &Path,
        deadline: &Deadline,
    ) -> std::result::Result<se_repository::WatchedFacts, String> {
        let mut watches = self
            .repository_watches
            .try_lock()
            .map_err(|error| match error {
                std::sync::TryLockError::WouldBlock => {
                    "another watched status is in progress".to_owned()
                }
                std::sync::TryLockError::Poisoned(_) => {
                    "the watched status registry is unreadable".to_owned()
                }
            })?;
        let position = watches.iter().position(|watch| watch.root() == root);
        let index = if let Some(index) = position {
            index
        } else {
            if watches.len() >= 2 {
                watches.remove(0);
            }
            watches.push(se_repository::RepositoryWatch::start(root)?);
            watches.len() - 1
        };
        let bound = deadline.at().min(Instant::now() + Duration::from_millis(8));
        watches[index].observe(bound)
    }
}
#[cfg(windows)]
fn watched_view(value: se_repository::WatchedFacts, include_ticket: bool) -> Result<GitView> {
    let age_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|now| u64::try_from(now.as_micros()).ok())
        .and_then(|now| now.checked_sub(value.reconciled_at_us))
        .map(|age| age / 1_000_000);
    let timestamp = |value| {
        i64::try_from(value)
            .map_err(|_| error("repository observation", "representable observation time"))
            .and_then(receipt::timestamp)
    };
    Ok(GitView {
        head: value.facts.head,
        branch: value.facts.branch,
        commits: value.commits,
        uncommitted: value.facts.dirty,
        observation: Some(GitObservation {
            basis: "watched".into(),
            age_seconds,
            reconciled_at: timestamp(value.reconciled_at_us)?,
            last_notification_at: value.last_notification_at_us.map(timestamp).transpose()?,
        }),
        watch_ticket: include_ticket.then_some(value.ticket),
    })
}

fn has_git(root: &Path) -> Result<bool> {
    for path in root.ancestors() {
        match std::fs::symlink_metadata(path.join(".git")) {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(cause) => return Err(error("Git repository metadata", cause.to_string())),
        }
    }
    Ok(false)
}
fn fresh_view(root: &Path, deadline: Instant) -> Result<Option<GitView>> {
    match se_repository::observe(root, deadline) {
        se_repository::Read::Known(facts) => Ok(Some(GitView {
            head: facts.head,
            branch: facts.branch,
            commits: None,
            uncommitted: facts.dirty,
            observation: None,
            watch_ticket: None,
        })),
        se_repository::Read::Fallback(reason) => Err(error("repository observation", &reason)),
    }
}
